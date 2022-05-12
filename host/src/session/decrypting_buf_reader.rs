// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Buffering reader that performs decryption of message chunks produced by
//! `EncryptingBufWriter`.
//!
//! [`DecryptingBufReader`] buffers data (much like a [`tokio::io::BufReader`]
//! until it receives a complete chunk (identified by the 4-byte length prefix),
//! at which point it decrypts the chunk and is able to return data to its
//! caller.
//!
//! `DecryptingBufReader` will fail if it receives chunks whose sizes it can't
//! handle (either because they're too small to decrypt or too large to fit in
//! its buffer). The maximum chunk size must match the sender.

use super::TAG_SIZE;
use futures::ready;
use sprockets_session::Tag;
use std::io;
use std::mem;
use std::ops::Range;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

const LENGTH_PREFIX_LEN: usize = mem::size_of::<u32>();

pub(super) struct DecryptingBufReader {
    buf: Box<[u8]>,
    read_pos: usize,
    decrypted_chunk: Option<Range<usize>>,
}

impl DecryptingBufReader {
    pub(super) fn with_capacity(cap: usize) -> Self {
        assert!(cap > LENGTH_PREFIX_LEN + TAG_SIZE);
        assert!(cap + TAG_SIZE <= u32::MAX as usize);
        Self {
            buf: vec![0; cap].into_boxed_slice(),
            read_pos: 0,
            decrypted_chunk: None,
        }
    }

    pub(super) fn poll_read<T, F>(
        &mut self,
        mut inner: Pin<&mut T>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        mut decrypt: F,
    ) -> Poll<Result<(), io::Error>>
    where
        T: AsyncRead,
        F: FnOnce(&mut [u8], &Tag) -> io::Result<()>,
    {
        loop {
            // Copy from current decrypted chunk, if any.
            decrypt = match self
                .copy_from_decrypted_chunk(buf, decrypt)?
            {
                CopyResult::CopiedDecryptedData => return Poll::Ready(Ok(())),
                CopyResult::DidNotCopyData(decrypt) => decrypt,
            };

            // `copy_from_decrypted_chunk` should never return false if our
            // buffer is full; sanity check.
            assert!(self.read_pos < self.buf.len());

            // We don't have enough data to decrypt the next chunk; get more
            // from `inner`.
            let mut our_buf = ReadBuf::new(&mut self.buf[self.read_pos..]);
            ready!(inner.as_mut().poll_read(cx, &mut our_buf))?;

            let nread = our_buf.filled().len();
            if nread == 0 {
                // EOF!
                //
                // TODO: Should we fail if `self.read_pos != 0`? That would
                // imply we partially read a chunk and then we got EOF from
                // `inner` before the chunk was finished.
                return Poll::Ready(Ok(()));
            }
            self.read_pos += nread;
        }
    }

    // Attempt to copy decrypted data into `buf`, decrypting the next chunk
    // via `decrypt` if necessary.
    //
    // If we copy any data, we consume `decrypt`; if we do not, we return it to
    // our caller (who can then use it to call us again after reading more data
    // from the source).
    fn copy_from_decrypted_chunk<F>(
        &mut self,
        buf: &mut ReadBuf<'_>,
        decrypt: F,
    ) -> Result<CopyResult<F>, io::Error>
    where
        F: FnOnce(&mut [u8], &Tag) -> io::Result<()>,
    {
        // Helper function to copy as much data as we can from `&src[range]`
        // into `dst`, updating `range.start` accordingly.
        //
        // If we copy all the decrypted data we have, we shift the data within
        // `src` so that the first byte of the next chunk is at `src[0]` and
        // return true. If we do not copy all the data we have, return false
        // (and do not shift any data).
        fn copy_from_already_decrypted(
            range: &mut Range<usize>,
            src: &mut Box<[u8]>,
            dst: &mut ReadBuf<'_>,
            read_pos: &mut usize,
        ) -> bool {
            // We should never try to copy from an empty range; sanity check.
            assert!(range.end > range.start);

            // Copy as much data as we can.
            let n = usize::min(dst.remaining(), range.end - range.start);
            dst.put_slice(&src[range.start..range.start + n]);
            range.start += n;

            // Are we done with this chunk?
            if range.start == range.end {
                // Shift data we've already read from subsequent chunks
                // down to the front of `src`.
                //
                // TODO-perf: We could consider not shifting if we already
                // have all (or part but know we'd have enough room for the
                // rest) of the next encrypted chunk, but it would make
                // our logic a fair bit more complicated. For now we always
                // shift down after finishing a chunk.
                assert!(*read_pos >= range.end + TAG_SIZE);
                src.copy_within(range.end + TAG_SIZE..*read_pos, 0);
                *read_pos -= range.end + TAG_SIZE;
                true
            } else {
                false
            }
        }

        // Do we have already-decrypted data to copy?
        if let Some(range) = self.decrypted_chunk.as_mut() {
            if copy_from_already_decrypted(
                range,
                &mut self.buf,
                buf,
                &mut self.read_pos,
            ) {
                self.decrypted_chunk = None;
            }
            return Ok(CopyResult::CopiedDecryptedData);
        }

        // We don't have any already-encrypted data; do we have enough data to
        // know how long the next chunk is?
        let len = if self.read_pos >= LENGTH_PREFIX_LEN {
            u32::from_be_bytes(
                self.buf[..LENGTH_PREFIX_LEN].try_into().unwrap(),
            ) as usize
        } else {
            return Ok(CopyResult::DidNotCopyData(decrypt));
        };

        // Fail on chunks longer than our capacity or too short to contain
        // an auth tag and at least one byte of data.
        if len + LENGTH_PREFIX_LEN > self.buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "total chunk length ({}) exceeds read buffer size ({})",
                    len + LENGTH_PREFIX_LEN,
                    self.buf.len()
                ),
            ));
        } else if len <= TAG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk length ({len}) too short"),
            ));
        }

        // Bail out if we don't yet have the full chunk.
        if self.read_pos < len + LENGTH_PREFIX_LEN {
            return Ok(CopyResult::DidNotCopyData(decrypt));
        }

        // Extract the chunk subslice (skipping over the length prefix),
        // and split into ciphertext/tag
        let bytes = &mut self.buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + len];
        let (chunk, tag) = bytes.split_at_mut(len - TAG_SIZE);

        // Decrypt the chunk and note the range of the plaintext.
        decrypt(chunk, Tag::from_slice(tag))?;
        let mut decrypted_chunk =
            LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + chunk.len();

        // Copy as much of the decrypted chunk as we can; if we don't copy it
        // all, save `decrypted_chunk` for the next time we're called.
        if !copy_from_already_decrypted(
            &mut decrypted_chunk,
            &mut self.buf,
            buf,
            &mut self.read_pos,
        ) {
            self.decrypted_chunk = Some(decrypted_chunk);
        }

        Ok(CopyResult::CopiedDecryptedData)
    }
}

enum CopyResult<T> {
    CopiedDecryptedData,
    DidNotCopyData(T),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use pin_project::pin_project;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    const DUMMY_TAG: &[u8] = b"16 byte test tag";

    fn dummy_decrypt(msg: &mut [u8], tag: &Tag) -> io::Result<()> {
        if tag.as_slice() != DUMMY_TAG {
            return Err(io::Error::new(io::ErrorKind::Other, "bad tag"));
        }
        for b in msg {
            *b ^= 1;
        }
        Ok(())
    }

    #[pin_project]
    struct TestReader<T> {
        #[pin]
        inner: T,
        buf: DecryptingBufReader,
    }

    impl<T: AsyncRead> AsyncRead for TestReader<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let me = self.project();
            me.buf.poll_read(me.inner, cx, buf, dummy_decrypt)
        }
    }

    // Build a dummy-encrypted chunk from `plaintext`, including length prefix
    // and auth tag.
    fn build_dummy_chunk(plaintext: &[u8]) -> Vec<u8> {
        let mut chunk = plaintext.to_vec();

        // "decrypt" the chunk, which also encrypts it (thanks xor!)
        dummy_decrypt(&mut chunk, Tag::from_slice(DUMMY_TAG)).unwrap();

        // Append auth tag.
        chunk.extend_from_slice(DUMMY_TAG);

        // Prepent length prefix.
        let len = chunk.len() as u32;
        chunk.splice(0..0, len.to_be_bytes());

        chunk
    }

    #[tokio::test]
    async fn hello_world() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 16 bytes + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(
                16 + LENGTH_PREFIX_LEN + TAG_SIZE,
            ),
        };

        // Send an encrypted "hello world" chunk.
        let chunk = build_dummy_chunk(b"hello world");
        tx.write_all(&chunk).await.unwrap();

        // Drop `tx` so we can use `read_to_end()`.
        mem::drop(tx);

        // We should get it back.
        let mut buf = Vec::new();
        rx.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn read_two_chunks_from_inner() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 2 8-byte chunks + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(
                2 * (8 + LENGTH_PREFIX_LEN + TAG_SIZE),
            ),
        };

        // Build two encrypted chunks.
        let mut msg0 = build_dummy_chunk(b"hello ");
        let mut msg1 = build_dummy_chunk(b"world");

        // Concatenate the chunks and send them in one write.
        msg0.append(&mut msg1);
        tx.write_all(&msg0).await.unwrap();

        // Drop `tx` so we can use `read_to_end()`.
        mem::drop(tx);

        let mut buf = Vec::new();
        rx.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn read_max_length_chunks() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Repeat the test above of sending two chunks in one large write, but
        // this time each chunk entirely fills our buffer.

        // Allocate a reader with space for one 4-byte chunks + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(
                4 + LENGTH_PREFIX_LEN + TAG_SIZE,
            ),
        };

        // Build two encrypted chunks.
        let full_text = b"01234567";
        let mut msg0 = build_dummy_chunk(&full_text[..4]);
        let mut msg1 = build_dummy_chunk(&full_text[4..]);

        // Concatenate the chunks and send them in one write.
        msg0.append(&mut msg1);
        tx.write_all(&msg0).await.unwrap();

        // Read one byte at a time, sanity checking the internal state after
        // each read.
        let mut buf = vec![0; 8];

        let expected_len_prefix = ((4 + TAG_SIZE) as u32).to_be_bytes();

        for i in 0..8 {
            rx.read_exact(&mut buf[i..i + 1]).await.unwrap();

            // We read the byte we expected.
            assert_eq!(&buf[..i + 1], &full_text[..i + 1]);

            // Check internal state.
            match i {
                // Partway through the first chunk
                0..=2 => {
                    assert_eq!(
                        rx.buf.decrypted_chunk,
                        Some(LENGTH_PREFIX_LEN + i + 1..LENGTH_PREFIX_LEN + 4)
                    );
                    assert_eq!(rx.buf.read_pos, rx.buf.buf.len());
                    assert_eq!(
                        rx.buf.buf[..LENGTH_PREFIX_LEN],
                        expected_len_prefix,
                    );
                    assert_eq!(
                        &rx.buf.buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + 4],
                        &full_text[..4]
                    );
                    assert_eq!(&rx.buf.buf[LENGTH_PREFIX_LEN + 4..], DUMMY_TAG);
                }
                // End of first chunk; because it filled the buffer, we
                // haven't yet read the second chunk from the underlying
                // stream
                3 => {
                    assert_eq!(rx.buf.decrypted_chunk, None);
                    assert_eq!(rx.buf.read_pos, 0);
                }
                // Partway through the second chunk
                4..=6 => {
                    assert_eq!(
                        rx.buf.decrypted_chunk,
                        Some(
                            LENGTH_PREFIX_LEN + i + 1 - 4
                                ..LENGTH_PREFIX_LEN + 4
                        )
                    );
                    assert_eq!(rx.buf.read_pos, rx.buf.buf.len());
                    assert_eq!(
                        rx.buf.buf[..LENGTH_PREFIX_LEN],
                        expected_len_prefix,
                    );
                    assert_eq!(
                        &rx.buf.buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + 4],
                        &full_text[4..]
                    );
                    assert_eq!(&rx.buf.buf[LENGTH_PREFIX_LEN + 4..], DUMMY_TAG);
                }
                // End of second chunk
                7 => {
                    assert_eq!(rx.buf.decrypted_chunk, None);
                    assert_eq!(rx.buf.read_pos, 0);
                }
                _ => unreachable!(),
            }
        }
    }

    #[tokio::test]
    async fn reject_too_short_chunks() {
        // We should fail on any length prefix <= TAG_SIZE bytes. If it's
        // strictly < TAG_SIZE it isn't large enough to contain the length
        // prefix and the auth tag; if it's == TAG_SIZE then it's a 0-length
        // chunk and should not have been sent.
        for bad_len in 0..=TAG_SIZE {
            let (mut tx, rx) = tokio::io::duplex(128);
            let mut rx = TestReader {
                inner: rx,
                buf: DecryptingBufReader::with_capacity(128),
            };

            let prefix = (bad_len as u32).to_be_bytes();
            tx.write_all(&prefix).await.unwrap();

            let mut buf = vec![0; 1];
            let err = rx.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                err.to_string(),
                format!("chunk length ({bad_len}) too short")
            );
        }
    }

    #[tokio::test]
    async fn reject_too_long_chunks() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 4 bytes + overhead.
        let cap = 4 + LENGTH_PREFIX_LEN + TAG_SIZE;
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(cap),
        };

        // Send an encrypted chunk that's 5 bytes + overhead.
        let chunk = build_dummy_chunk(b"hello");
        tx.write_all(&chunk).await.unwrap();

        let mut buf = vec![0; 1];
        let err = rx.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            format!(
                "total chunk length ({}) exceeds read buffer size ({})",
                cap + 1,
                cap,
            )
        );
    }

    #[tokio::test]
    async fn forward_decrypt_errors_to_caller() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 16 bytes + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(
                16 + LENGTH_PREFIX_LEN + TAG_SIZE,
            ),
        };

        // Send an encrypted "hello world" chunk, but with a broken auth tag.
        let mut chunk = build_dummy_chunk(b"hello world");
        *chunk.last_mut().unwrap() ^= 1;
        tx.write_all(&chunk).await.unwrap();

        // We should get the error from `dummy_decrypt`.
        let mut buf = vec![0; 1];
        let err = rx.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "bad tag");
    }

    #[tokio::test]
    async fn read_partial_chunk() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 16 bytes + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(
                16 + LENGTH_PREFIX_LEN + TAG_SIZE,
            ),
        };

        let chunk = build_dummy_chunk(b"hello");

        // Write all but the last byte.
        tx.write_all(&chunk[..chunk.len() - 1]).await.unwrap();

        // Attempting to read should time out; we haven't received the full
        // chunk and therefore can't decrypt it.
        let mut buf = [0; 5];
        tokio::time::timeout(Duration::from_millis(100), rx.read(&mut buf))
            .await
            .unwrap_err();

        // Sanity check internal state.
        assert_eq!(rx.buf.read_pos, LENGTH_PREFIX_LEN + 5 + TAG_SIZE - 1);
        assert_eq!(rx.buf.decrypted_chunk, None);

        // Write final byte; we should now be able to read.
        tx.write_all(&chunk[chunk.len()-1..]).await.unwrap();

        assert_eq!(rx.read(&mut buf).await.unwrap(), 5);
        assert_eq!(buf.as_slice(), b"hello");
    }
}
