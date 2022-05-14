// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Buffering writer that performs encryption and message chunking.
//!
//! [`EncryptingBufWriter`] buffers data (much like a [`tokio::io::BufWriter`]
//! until either it fills or is explicitly told to flush, at which point it:
//!
//! 1. Encrypts the contents of its buffer, which appends an auth tag.
//! 2. Prepends the length of the chunk (including the auth tag, not including
//!    the length itself) as a 4-byte u32 in network order.
//!
//! and then attempts to flush that encrypted chunk into the underlying writer.
//! Further writes to the buffer will block until that flush completes.

use super::aead_write_buf::{AeadCiphertextBuf, AeadPlaintextBuf};
use derive_more::From;
use futures::ready;
use sprockets_session::Tag;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncWrite;

#[derive(From)]
enum AeadWriteBuf {
    Plaintext(AeadPlaintextBuf),
    Ciphertext {
        ciphertext: AeadCiphertextBuf,
        // The amount of data flushed so far
        flushed: usize,
    },
}

pub(super) struct EncryptingBufWriter {
    // Need an option to allow moving from one variant to another
    buf: Option<AeadWriteBuf>,
}

impl EncryptingBufWriter {
    pub(super) fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Some(AeadPlaintextBuf::with_capacity(cap).into()),
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
        F: FnOnce(&mut [u8]) -> Result<Tag, ()>,
    {
        // We guarantee that buf is always `Some`. We reset it after the match
        // if flushing is required. Otherwise, we are appending to the existing
        // plaintext, so reset it without any further function calls.
        let (new_buf, ret) = match self.buf.take().unwrap() {
            AeadWriteBuf::Plaintext(mut plaintext) => {
                if plaintext.is_full() {
                    encrypt_and_flush(inner, cx, plaintext, encrypt)
                } else {
                    let n = plaintext.extend(buf);
                    self.buf = Some(plaintext.into());
                    return Poll::Ready(Ok(n));
                }
            }
            AeadWriteBuf::Ciphertext {
                ciphertext,
                flushed,
            } => flush(inner, cx, ciphertext, flushed),
        };

        self.buf = Some(new_buf);
        ready!(ret)?;

        // If we reached this point we have flushed a a complete encrypted
        // frame and have an empty plaintext buffer in `self.buf`. We write
        // some data into the plaintext buffer and fulfill the expectation of
        // the caller that if there is no error, they will get back
        // `Poll::Pending` or `Poll::Ready(Ok(n))`. In this case they will get
        // back `Poll::Ready` because at least some data will be written into
        // buf.
        //
        // However, as we allow the caller to pass an empty slice in `buf`, they
        // may get back `Poll::Ready(Ok(0))` which does not indicate an error.
        let n = self.get_plaintext_mut().extend(buf);
        Poll::Ready(Ok(n))
    }

    pub(super) fn poll_flush<T, F>(
        &mut self,
        inner: Pin<&mut T>,
        cx: &mut Context<'_>,
        encrypt: F,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite,
        F: FnOnce(&mut [u8]) -> Result<Tag, ()>,
    {
        // We guarantee that buf is always `Some`. We reset it after the match.
        let (new_buf, ret) = match self.buf.take().unwrap() {
            AeadWriteBuf::Plaintext(plaintext) => {
                if plaintext.is_empty() {
                    // Nothing to flush
                    (plaintext.into(), Poll::Ready(Ok(())))
                } else {
                    encrypt_and_flush(inner, cx, plaintext, encrypt)
                }
            }
            AeadWriteBuf::Ciphertext {
                ciphertext,
                flushed,
            } => flush(inner, cx, ciphertext, flushed),
        };

        self.buf = Some(new_buf);
        ret
    }

    fn get_plaintext_mut(&mut self) -> &mut AeadPlaintextBuf {
        if let AeadWriteBuf::Plaintext(plaintext) = self.buf.as_mut().unwrap() {
            plaintext
        } else {
            panic!("AeadWriteBuf contains ciphertext, not plaintext")
        }
    }
}

fn encrypt_and_flush<T, F>(
    inner: Pin<&mut T>,
    cx: &mut Context<'_>,
    plaintext: AeadPlaintextBuf,
    encrypt: F,
) -> (AeadWriteBuf, Poll<io::Result<()>>)
where
    T: AsyncWrite,
    F: FnOnce(&mut [u8]) -> Result<Tag, ()>,
{
    match plaintext.encrypt(encrypt) {
        Ok(ciphertext) => flush(inner, cx, ciphertext, 0),
        Err(plaintext) => (
            plaintext.into(),
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "encryption failed",
            ))),
        ),
    }
}

fn flush<T>(
    mut inner: Pin<&mut T>,
    cx: &mut Context<'_>,
    ciphertext: AeadCiphertextBuf,
    mut flushed: usize,
) -> (AeadWriteBuf, Poll<io::Result<()>>)
where
    T: AsyncWrite,
{
    let mut ret = Poll::Ready(Ok(()));

    // Flush as much of the ciphertext frame as we can.
    while flushed != ciphertext.len() {
        let buf = &ciphertext.as_slice()[flushed..];
        match inner.as_mut().poll_write(cx, buf) {
            Poll::Pending => {
                ret = Poll::Pending;
                break;
            }
            Poll::Ready(Ok(0)) => {
                ret = Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write ciphertext",
                )));
                break;
            }
            Poll::Ready(Ok(n)) => {
                flushed += n;
            }
            Poll::Ready(Err(err)) => {
                ret = Poll::Ready(Err(err));
                break;
            }
        }
    }

    // Are we done flushing?
    let new_buf = if flushed == ciphertext.len() {
        // Reset the buffer to allow writing plaintext data again
        AeadPlaintextBuf::from(ciphertext).into()
    } else {
        AeadWriteBuf::Ciphertext {
            ciphertext,
            flushed,
        }
    };

    (new_buf, ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pin_project::pin_project;
    use std::mem;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    const LENGTH_PREFIX_LEN: usize = mem::size_of::<u32>();
    const DUMMY_TAG: &[u8] = b"16 byte test tag";
    const TAG_SIZE: usize = DUMMY_TAG.len();

    fn dummy_encrypt(msg: &mut [u8]) -> Result<Tag, ()> {
        for b in msg {
            *b ^= 1;
        }
        Ok(*Tag::from_slice(DUMMY_TAG))
    }

    #[pin_project]
    struct TestWriter<T> {
        #[pin]
        inner: T,
        encrypt: fn(&mut [u8]) -> Result<Tag, ()>,
        buf: EncryptingBufWriter,
    }

    impl<T> TestWriter<T> {
        fn new(
            inner: T,
            encrypt: fn(&mut [u8]) -> Result<Tag, ()>,
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
        let mut tx = TestWriter::new(tx, dummy_encrypt, 8);

        // Writing 6 bytes should not flush to the underlying buffer.
        tx.write_all(b"012345").await.unwrap();

        // Reading should time out; no data has been flushed yet!
        let mut buf = vec![0; 64];
        tokio::time::timeout(Duration::from_millis(100), rx.read(&mut buf))
            .await
            .unwrap_err();

        // Flush, and confirm we get our expected message.
        tx.flush().await.unwrap();

        let expected_chunk =
            &[b'0' ^ 1, b'1' ^ 1, b'2' ^ 1, b'3' ^ 1, b'4' ^ 1, b'5' ^ 1];
        let expected_len = expected_chunk.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_chunk.len()],
            expected_chunk
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_chunk.len()..n],
            DUMMY_TAG
        );

        // Writing 12 bytes should flush a first chunk to the underlying
        // buffer.
        let mut message = b"hello world!".to_vec();
        tx.write_all(&message).await.unwrap();

        dummy_encrypt(&mut message).unwrap();

        let expected_chunk = &message[..8];
        let expected_len = expected_chunk.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_chunk.len()],
            expected_chunk
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_chunk.len()..n],
            DUMMY_TAG
        );

        // Shutting down the writer should flush the remaining bytes in a new
        // chunk.
        tx.shutdown().await.unwrap();

        let expected_chunk = &message[8..];
        let expected_len = expected_chunk.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_chunk.len()],
            expected_chunk
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_chunk.len()..n],
            DUMMY_TAG
        );
    }

    #[tokio::test]
    async fn writing_zero_length_data_does_not_send() {
        let (tx, mut rx) = tokio::io::duplex(128);

        // Allocate a writer with space for 8 bytes + overhead.
        let mut tx = TestWriter::new(tx, dummy_encrypt, 8);

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
        let mut tx = TestWriter::new(tx, |_| Err(()), 128);

        // Writing won't fail...
        tx.write_all(b"hello").await.unwrap();

        // ... until we actually encrypt (e.g., by flushing)
        let err = tx.flush().await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "encryption failed");
    }

    #[tokio::test]
    async fn can_resume_after_encryption_failure() {
        let (tx, mut rx) = tokio::io::duplex(128);

        // Use an always-failing encryption closure with a buffer sized for a
        // length=5 chunk plus overhead.
        let mut tx = TestWriter::new(tx, |_| Err(()), 5);

        // Write 5 bytes; this should fill the buffer.
        tx.write_all(b"01234").await.unwrap();

        // Flushing should fail when it tries to encrypt.
        let err = tx.flush().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "encryption failed");

        // Swap out our encryption function for one that works.
        tx.encrypt = dummy_encrypt;

        // Call `.write()` again. Currently our buffer is still full of
        // unencrypted data; writing more should trigger an "encrypt then flush"
        // to make room.
        tx.write_all(b"56").await.unwrap();

        // Confirm the now-correctly-encrypted original chunk was flushed.
        let mut expected_chunk = b"01234".to_vec();
        dummy_encrypt(&mut expected_chunk).unwrap();

        let mut buf = [0; 64];
        let expected_len = expected_chunk.len() + TAG_SIZE;

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, expected_len + LENGTH_PREFIX_LEN);
        assert_eq!(
            &buf[..LENGTH_PREFIX_LEN],
            (expected_len as u32).to_be_bytes()
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + expected_chunk.len()],
            expected_chunk
        );
        assert_eq!(
            &buf[LENGTH_PREFIX_LEN + expected_chunk.len()..n],
            DUMMY_TAG
        );
    }
}
