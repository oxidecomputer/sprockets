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

use super::aead_read_buf::{AeadCiphertextFrameBuf, AeadPlaintextFrameBuf};
use derive_more::From;
use futures::ready;
use sprockets_session::Tag;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

#[derive(From)]
enum AeadReadBuf {
    Ciphertext(AeadCiphertextFrameBuf),
    Plaintext(AeadPlaintextFrameBuf),
}

pub(super) struct DecryptingBufReader {
    buf: Option<AeadReadBuf>,
}

/// Indicate whether the AeadReadBuf needs to switch variants
enum NeedsTransition {
    ToPlaintext,
    ToCiphertext,
    False,
}

impl DecryptingBufReader {
    pub(super) fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Some(AeadCiphertextFrameBuf::with_capacity(cap).into()),
        }
    }

    pub(super) fn poll_read<T, F>(
        &mut self,
        mut inner: Pin<&mut T>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        decrypt: F,
    ) -> Poll<Result<(), io::Error>>
    where
        T: AsyncRead,
        F: FnOnce(&mut [u8], &Tag) -> Result<(), ()>,
    {
        let mut decrypt = Some(decrypt);

        loop {
            let needs_transition = match self.buf.as_mut().unwrap() {
                AeadReadBuf::Ciphertext(ciphertext) => {
                    if !ready!(read_until_ready_to_decrypt(
                        ciphertext, &mut inner, cx
                    ))? {
                        // 0 bytes were read from `inner`
                        return Poll::Ready(Ok(()));
                    }
                    // We have a complete frame to decrypt
                    NeedsTransition::ToPlaintext
                }
                AeadReadBuf::Plaintext(plaintext) => {
                    copy_plaintext(plaintext, buf)
                }
            };

            match needs_transition {
                NeedsTransition::ToCiphertext => {
                    // We've already copied all the plaintext into `buf`
                    let _ = self.transition(decrypt)?;
                    return Poll::Ready(Ok(()));
                }
                NeedsTransition::ToPlaintext => {
                    // Decrypt the ciphertext
                    decrypt = self.transition(decrypt)?;
                }
                NeedsTransition::False => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    // Transition from ciphertext to plaintext or vice versa
    //
    // Always consume `decrypt` and return Ok(None). This allows us to loop in
    // the caller to reuse decrypt. This is safe because each transition can
    // only occur once, and we only require decryption for the transition from
    // ciphertext to plaintext.
    //
    /// Return an error if decryption fails.
    fn transition<F>(
        &mut self,
        decrypt: Option<F>,
    ) -> Result<Option<F>, io::Error>
    where
        F: FnOnce(&mut [u8], &Tag) -> Result<(), ()>,
    {
        match self.buf.take().unwrap() {
            AeadReadBuf::Ciphertext(ciphertext) => {
                match ciphertext.decrypt_frame(decrypt.unwrap()) {
                    Ok(plaintext) => {
                        self.buf = Some(plaintext.into());
                        Ok(None)
                    }
                    Err(ciphertext) => {
                        self.buf = Some(ciphertext.into());
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            "decryption failed",
                        ))
                    }
                }
            }
            AeadReadBuf::Plaintext(plaintext) => {
                self.buf = Some(AeadCiphertextFrameBuf::from(plaintext).into());
                Ok(None)
            }
        }
    }
}

// Copy plaintext data into the user's buffer.
fn copy_plaintext(
    plaintext: &mut AeadPlaintextFrameBuf,
    buf: &mut ReadBuf<'_>,
) -> NeedsTransition {
    // Copy as much data as we can.
    let n = usize::min(buf.remaining(), plaintext.num_bytes_to_copy());
    buf.put_slice(&plaintext.as_slice()[..n]);
    plaintext.advance(n);

    // Should we transition back to ciphertext reading?
    if plaintext.is_empty() {
        NeedsTransition::ToCiphertext
    } else {
        NeedsTransition::False
    }
}

fn read_until_ready_to_decrypt<T>(
    ciphertext: &mut AeadCiphertextFrameBuf,
    inner: &mut Pin<&mut T>,
    cx: &mut Context,
) -> Poll<Result<bool, io::Error>>
where
    T: AsyncRead,
{
    loop {
        // We check befor reading because there may be a complete
        // frame already from a `read` of a prior frame's ciphertext.
        //
        // Without this check, the caller could see that it read 0 bytes, even
        // though there is a full frame in our buffer.
        if ciphertext.ready_to_decrypt()? {
            return Poll::Ready(Ok(true));
        }

        let mut our_buf = ReadBuf::new(ciphertext.unfilled_mut());
        ready!(inner.as_mut().poll_read(cx, &mut our_buf))?;
        let nread = our_buf.filled().len();
        if nread == 0 {
            // Should we fail if `self.read_pos != 0`? That would imply we
            // partially read a chunk and then we got EOF from `inner`
            // before the chunk was finished. I believe the answer is "no",
            // because the docs on `AsyncReadExt` note that a return of
            // `Ok(0)` means "currently at EOF", but that future reads might
            // return more data. We relay `Ok(0)` to our caller here and let
            // them decide whether the EOF is expected or if they want to
            // retry again later.
            //
            // We return `Ok(false)` here to indicate to the caller to
            // return to the user.
            return Poll::Ready(Ok(false));
        }
        ciphertext.advance(nread);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::TAG_SIZE;
    use super::*;
    use pin_project::pin_project;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    const DUMMY_TAG: &[u8] = b"16 byte test tag";
    const LENGTH_PREFIX_LEN: usize = mem::size_of::<u32>();
    use std::mem;

    fn dummy_decrypt(msg: &mut [u8], tag: &Tag) -> Result<(), ()> {
        if tag.as_slice() != DUMMY_TAG {
            return Err(());
        }
        for b in msg {
            *b ^= 1;
        }
        Ok(())
    }

    impl AeadReadBuf {
        // Return the plaintext data so we can do some white box inspection
        fn get_plaintext(&self) -> &AeadPlaintextFrameBuf {
            match self {
                Self::Plaintext(plaintext) => plaintext,
                _ => panic!("Not plaintext!"),
            }
        }

        // Return the ciphertext data so we can do some white box inspection
        fn get_ciphertext(&self) -> &AeadCiphertextFrameBuf {
            match self {
                Self::Ciphertext(ciphertext) => ciphertext,
                _ => panic!("Not ciphertext!"),
            }
        }
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

        // Prepend length prefix.
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
            buf: DecryptingBufReader::with_capacity(16),
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
                8 + (8 + LENGTH_PREFIX_LEN + TAG_SIZE),
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

        // Allocate a reader with space for one 4-byte chunk + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(4),
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

        for i in 0..8 {
            rx.read_exact(&mut buf[i..i + 1]).await.unwrap();

            // We read the byte we expected.
            assert_eq!(&buf[..i + 1], &full_text[..i + 1]);

            // Check internal state.
            match i {
                // Partway through the first chunk
                0..=2 => {
                    let unread_index = i + 1;
                    let plaintext =
                        rx.buf.buf.as_ref().unwrap().get_plaintext();
                    assert_eq!(plaintext.num_bytes_to_copy(), 4 - unread_index);
                    assert_eq!(plaintext.is_empty(), false);
                    assert_eq!(
                        plaintext.as_slice(),
                        &full_text[unread_index..4]
                    );
                }
                // End of first chunk; because it filled the buffer, we
                // haven't yet read the second chunk from the underlying
                // stream
                3 => {
                    // We should have a ciphertext frame
                    let ciphertext =
                        rx.buf.buf.as_ref().unwrap().get_ciphertext();

                    // The remaining space is the entire buffer
                    assert_eq!(
                        ciphertext.remaining(),
                        4 + LENGTH_PREFIX_LEN + TAG_SIZE
                    );
                    assert_eq!(false, ciphertext.ready_to_decrypt().unwrap());
                }
                // Partway through the second chunk
                4..=6 => {
                    let unread_index = i + 1;
                    let plaintext =
                        rx.buf.buf.as_ref().unwrap().get_plaintext();
                    assert_eq!(plaintext.num_bytes_to_copy(), 8 - unread_index);
                    assert_eq!(plaintext.is_empty(), false);
                    assert_eq!(
                        plaintext.as_slice(),
                        &full_text[unread_index..]
                    );
                }
                // End of second chunk
                7 => {
                    // We should have a ciphertext frame
                    let ciphertext =
                        rx.buf.buf.as_ref().unwrap().get_ciphertext();

                    // The remaining space is the entire buffer
                    assert_eq!(
                        ciphertext.remaining(),
                        4 + LENGTH_PREFIX_LEN + TAG_SIZE
                    );
                    assert_eq!(false, ciphertext.ready_to_decrypt().unwrap());
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
                format!("frame length ({bad_len}) too short")
            );
        }
    }

    #[tokio::test]
    async fn reject_too_long_chunks() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 4 bytes + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(4),
        };

        // Send an encrypted chunk that's 5 bytes + overhead.
        let chunk = build_dummy_chunk(b"hello");
        tx.write_all(&chunk).await.unwrap();

        let mut buf = vec![0; 1];
        let err = rx.read(&mut buf).await.unwrap_err();
        let buf_size = 4 + LENGTH_PREFIX_LEN + TAG_SIZE;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            format!(
                "total frame length ({}) exceeds read buffer size ({})",
                buf_size + 1,
                buf_size,
            )
        );
    }

    #[tokio::test]
    async fn forward_decrypt_errors_to_caller() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 16 bytes + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(16),
        };

        // Send an encrypted "hello world" chunk, but with a broken auth tag.
        let mut chunk = build_dummy_chunk(b"hello world");
        *chunk.last_mut().unwrap() ^= 1;
        tx.write_all(&chunk).await.unwrap();

        // We should get the error from `dummy_decrypt`.
        let mut buf = vec![0; 1];
        let err = rx.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "decryption failed");
    }

    #[tokio::test]
    async fn read_partial_chunk() {
        let (mut tx, rx) = tokio::io::duplex(128);

        // Allocate a reader with space for 16 bytes + overhead.
        let mut rx = TestReader {
            inner: rx,
            buf: DecryptingBufReader::with_capacity(16),
        };

        let chunk = build_dummy_chunk(b"hello");

        // Write all but the last byte.
        tx.write_all(&chunk[..chunk.len() - 1]).await.unwrap();

        // Attempting to read should time out; we haven't received the full
        // chunk and therefore can't decrypt it.
        let mut buf = [0; 5];
        tokio::time::timeout(Duration::from_millis(1), rx.read(&mut buf))
            .await
            .unwrap_err();

        // Sanity check internal state.
        // We should have a ciphertext frame
        let ciphertext = rx.buf.buf.as_ref().unwrap().get_ciphertext();

        let buf_size = 16 + LENGTH_PREFIX_LEN + TAG_SIZE;
        let expected = buf_size - (chunk.len() - 1);

        assert_eq!(ciphertext.remaining(), expected);
        assert_eq!(false, ciphertext.ready_to_decrypt().unwrap());

        // Write final byte; we should now be able to read.
        tx.write_all(&chunk[chunk.len() - 1..]).await.unwrap();

        assert_eq!(rx.read(&mut buf).await.unwrap(), 5);
        assert_eq!(buf.as_slice(), b"hello");
    }
}
