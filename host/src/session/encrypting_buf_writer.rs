// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::TAG_SIZE;
use futures::ready;
use sprockets_session::Tag;
use std::io;
use std::mem;
use std::ops::Range;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncWrite;

const LENGTH_PREFIX_LEN: usize = mem::size_of::<u32>();

pub(super) struct EncryptingBufWriter {
    buf: Box<[u8]>,
    copy_pos: usize,
    flush: Option<Range<usize>>,
}

impl EncryptingBufWriter {
    pub(super) fn with_capacity(cap: usize) -> Self {
        // Ensure we have room for at least one byte of data.
        assert!(cap > LENGTH_PREFIX_LEN + TAG_SIZE);
        // Ensure the max message size won't overflow our u32 length prefix.
        assert!(cap + TAG_SIZE <= u32::MAX as usize);
        Self {
            buf: vec![0; cap].into_boxed_slice(),
            copy_pos: LENGTH_PREFIX_LEN,
            flush: None,
        }
    }

    pub(super) fn poll_write<T, F>(
        &mut self,
        inner: Pin<&mut T>,
        cx: &mut Context<'_>,
        buf: &[u8],
        encrypt: F,
    ) -> Poll<io::Result<usize>>
    where
        T: AsyncWrite,
        F: FnOnce(&mut [u8]) -> io::Result<Tag>,
    {
        let copy_end = self.buf.len() - TAG_SIZE;

        // Flush, if necessary.
        if self.flush.is_none() && self.copy_pos == copy_end {
            // We're not currently flushing, but our buffer is full; we need to
            // encrypt and then flush.
            self.flush = Some(self.encrypt_current_buffer(encrypt)?);
        }
        ready!(self.flush_to_inner_if_needed(inner, cx))?;

        // Carve out our remaining available space as a subslice.
        let available = &mut self.buf[self.copy_pos..copy_end];

        // If we return without blocking from `flush_to_inner_if_needed`, two
        // things must be true: We have no encrypted data waiting to be written,
        // and we have room to read at least one more byte. Sanity check both.
        assert!(self.flush.is_none());
        assert!(!available.is_empty());

        // Copy as much data as we can from `buf`.
        let n = usize::min(available.len(), buf.len());
        available[..n].copy_from_slice(&buf[..n]);
        self.copy_pos += n;

        Poll::Ready(Ok(n))
    }

    pub(super) fn poll_flush<T, F>(
        &mut self,
        mut inner: Pin<&mut T>,
        cx: &mut Context<'_>,
        encrypt: F,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite,
        F: FnOnce(&mut [u8]) -> io::Result<Tag>,
    {
        // Are we already flushing?
        ready!(self.flush_to_inner_if_needed(inner.as_mut(), cx))?;

        // Do we have unencrypted, unsent data to send?
        if self.copy_pos > LENGTH_PREFIX_LEN {
            self.flush = Some(self.encrypt_current_buffer(encrypt)?);
            ready!(self.flush_to_inner_if_needed(inner, cx))?;
        }

        Poll::Ready(Ok(()))
    }

    fn flush_to_inner_if_needed<T>(
        &mut self,
        mut inner: Pin<&mut T>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite,
    {
        // Do we need to flush?
        let flush = match self.flush.as_mut() {
            Some(flush) => flush,
            None => return Poll::Ready(Ok(())),
        };

        while flush.start < flush.end {
            // Extract data remaining to flush.
            let buf = &self.buf[flush.clone()];
            let n = ready!(inner.as_mut().poll_write(cx, buf))?;

            flush.start += n;
        }

        // Flushing complete; reset.
        self.flush = None;
        self.copy_pos = LENGTH_PREFIX_LEN;

        Poll::Ready(Ok(()))
    }

    fn encrypt_current_buffer<F>(
        &mut self,
        encrypt: F,
    ) -> io::Result<Range<usize>>
    where
        F: FnOnce(&mut [u8]) -> io::Result<Tag>,
    {
        // We should only be called if we have a nonzero amount of data to
        // encrypt and we're not currently flushing.
        assert!(self.copy_pos > LENGTH_PREFIX_LEN);
        assert!(self.flush.is_none());

        // `poll_write` should always leave room for the auth tag.
        assert!(self.buf.len() - self.copy_pos >= TAG_SIZE);

        // Encrypt this message.
        let message = &mut self.buf[LENGTH_PREFIX_LEN..self.copy_pos];
        let tag = encrypt(message)?;

        // Append the auth tag into our buffer.
        assert_eq!(tag.len(), TAG_SIZE);
        self.buf[self.copy_pos..self.copy_pos + TAG_SIZE].copy_from_slice(&tag);

        // Fill in the length prefix. This is guaranteed to fit in `u32` via the
        // assertions we performed in `with_capacity()`.
        let len = (self.copy_pos - LENGTH_PREFIX_LEN + TAG_SIZE) as u32;
        self.buf[..LENGTH_PREFIX_LEN].copy_from_slice(&len.to_be_bytes());

        // Note the subset of the buffer we need to flush.
        Ok(0..self.copy_pos + TAG_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pin_project::pin_project;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    const DUMMY_TAG: &[u8] = b"16 byte test tag";

    fn dummy_encrypt(msg: &mut [u8]) -> io::Result<Tag> {
        for b in msg {
            *b ^= 1;
        }
        Ok(*Tag::from_slice(DUMMY_TAG))
    }

    #[pin_project]
    struct TestWriter<T> {
        #[pin]
        inner: T,
        encrypt: fn(&mut [u8]) -> io::Result<Tag>,
        buf: EncryptingBufWriter,
    }

    impl<T> TestWriter<T> {
        fn new(
            inner: T,
            encrypt: fn(&mut [u8]) -> io::Result<Tag>,
            capacity: usize,
        ) -> Self {
            Self {
                inner,
                encrypt,
                buf: EncryptingBufWriter::with_capacity(capacity),
            }
        }
    }

    impl<T: AsyncWrite> AsyncWrite for TestWriter<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let me = self.project();
            me.buf.poll_write(me.inner, cx, buf, me.encrypt)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            let me = self.project();
            me.buf.poll_flush(me.inner, cx, me.encrypt)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            let mut me = self.project();
            ready!(me.buf.poll_flush(me.inner.as_mut(), cx, me.encrypt))?;
            me.inner.poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn hello_world() {
        let (tx, mut rx) = tokio::io::duplex(128);

        // Allocate a writer with space for 8 bytes + overhead.
        let mut tx = TestWriter::new(
            tx,
            dummy_encrypt,
            8 + LENGTH_PREFIX_LEN + TAG_SIZE,
        );

        // Writing 6 bytes should not flush to the underlying buffer.
        tx.write_all(b"012345").await.unwrap();

        // Reading should time out; no data has been flushed yet!
        let mut buf = vec![0; 64];
        tokio::time::timeout(Duration::from_millis(100), rx.read(&mut buf))
            .await
            .unwrap_err();

        // Flush, and confirm we get our expected message.
        tx.flush().await.unwrap();

        let expected_message =
            &[b'0' ^ 1, b'1' ^ 1, b'2' ^ 1, b'3' ^ 1, b'4' ^ 1, b'5' ^ 1];
        let expected_len = expected_message.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_message.len()],
            expected_message
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_message.len()..n],
            DUMMY_TAG
        );

        // Writing 12 bytes should flush a first message to the underlying
        // buffer.
        let mut message = b"hello world!".to_vec();
        tx.write_all(&message).await.unwrap();

        dummy_encrypt(&mut message).unwrap();

        let expected_message = &message[..8];
        let expected_len = expected_message.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_message.len()],
            expected_message
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_message.len()..n],
            DUMMY_TAG
        );

        // Shutting down the writer should flush the remaining bytes in a new
        // message.
        tx.shutdown().await.unwrap();

        let expected_message = &message[8..];
        let expected_len = expected_message.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_message.len()],
            expected_message
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_message.len()..n],
            DUMMY_TAG
        );
    }

    #[tokio::test]
    async fn writing_zero_length_messages_does_not_send_data() {
        let (tx, mut rx) = tokio::io::duplex(128);

        // Allocate a writer with space for 8 bytes + overhead.
        let mut tx = TestWriter::new(
            tx,
            dummy_encrypt,
            8 + LENGTH_PREFIX_LEN + TAG_SIZE,
        );

        // We can write 0-length buffers into `tx`, but flushing after any
        // number of them should not result in any data being sent.
        for i in 0..100 {
            tx.write_all(&[]).await.unwrap();
            if i % 10 == 9 {
                tx.flush().await.unwrap();
            }
        }

        // Drop `tx` so we can use `read_to_end` (which should give us nothing
        // at all!)
        mem::drop(tx);

        let mut buf = Vec::new();
        rx.read_to_end(&mut buf).await.unwrap();
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn forward_encrypt_errors_to_caller() {
        let (tx, _rx) = tokio::io::duplex(128);

        // Use an always-failing encryption closure.
        let mut tx = TestWriter::new(
            tx,
            |_| Err(io::Error::new(io::ErrorKind::Other, "boom")),
            128,
        );

        // Writing won't fail...
        tx.write_all(b"hello").await.unwrap();

        // ... until we actually encrypt (e.g., by flushing)
        let err = tx.flush().await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "boom");
    }

    #[tokio::test]
    async fn can_resume_after_encryption_failure() {
        let (tx, mut rx) = tokio::io::duplex(128);

        // Use an always-failing encryption closure with a buffer sized for a
        // length=5 message plus overhead.
        let mut tx = TestWriter::new(
            tx,
            |_| Err(io::Error::new(io::ErrorKind::Other, "boom")),
            5 + LENGTH_PREFIX_LEN + TAG_SIZE,
        );

        // Write 5 bytes; this should fill the buffer.
        tx.write_all(b"01234").await.unwrap();

        // Flushing should fail when it tries to encrypt.
        let err = tx.flush().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "boom");

        // Swap out our encryption function for one that works.
        tx.encrypt = dummy_encrypt;

        // Call `.write()` again. Currently our buffer is still full of
        // unencrypted data; writing more should trigger an "encrypt then flush"
        // to make room.
        tx.write_all(b"56").await.unwrap();

        // Confirm the now-correctly-encrypted original message was flushed.
        let mut expected_message = b"01234".to_vec();
        dummy_encrypt(&mut expected_message).unwrap();

        let mut buf = [0; 64];
        let expected_len = expected_message.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_message.len()],
            expected_message
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_message.len()..n],
            DUMMY_TAG
        );
    }
}
