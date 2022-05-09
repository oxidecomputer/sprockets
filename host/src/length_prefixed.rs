// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Buffered reader/writer that sends `u32`-length-prefixed messages on the
//! underlying channel.

use futures::ready;
use pin_project::pin_project;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

#[pin_project]
pub(crate) struct LengthPrefixed<T> {
    #[pin]
    inner: T,
    read_buf: Box<[u8]>,
    read_remaining_this_msg: usize,
    read_pos: usize,
    read_end: usize,
}

impl<T> LengthPrefixed<T> {
    pub(crate) fn with_capacity(inner: T, cap: usize) -> Self {
        let read_buf = vec![0; cap];
        Self {
            inner,
            read_buf: read_buf.into_boxed_slice(),
            read_remaining_this_msg: 0,
            read_pos: 0,
            read_end: 0,
        }
    }

    fn project_read(self: Pin<&mut Self>) -> ProjectedRead<'_, T> {
        let me = self.project();
        ProjectedRead {
            inner: me.inner,
            buf: me.read_buf,
            remaining_this_msg: me.read_remaining_this_msg,
            pos: me.read_pos,
            end: me.read_end,
        }
    }
}

struct ProjectedRead<'a, T> {
    inner: Pin<&'a mut T>,
    buf: &'a mut [u8],
    remaining_this_msg: &'a mut usize,
    pos: &'a mut usize,
    end: &'a mut usize,
}

impl<T: AsyncRead> ProjectedRead<'_, T> {
    fn fill_read_buf(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        // We should only be called when we've either read all buffered data or
        // we have too little buffered data to know how long the next message
        // will be (i.e., < 4 bytes).
        debug_assert!(*self.end - *self.pos < 4);

        // Shift any remaining data down to the front.
        let new_end = *self.end - *self.pos;
        self.buf.copy_within(*self.pos..*self.end, 0);
        *self.pos = 0;
        *self.end = new_end;

        // Issue a read to our underlying channel.
        let mut buf = ReadBuf::new(&mut self.buf[*self.end..]);
        ready!(self.inner.as_mut().poll_read(cx, &mut buf))?;

        let n = buf.filled().len();
        *self.end += n;

        Poll::Ready(Ok(n))
    }

    fn buffered_data(&mut self) -> Option<&[u8]> {
        // See if we have buffered data remaining that's part of the current
        // message we're reading.
        let mut amt_buffered = *self.end - *self.pos;
        if *self.remaining_this_msg > 0 && amt_buffered > 0 {
            let n = usize::min(*self.remaining_this_msg, amt_buffered);
            return Some(&self.buf[*self.pos..*self.pos + n]);
        }

        // See if we have buffered data from the next message, looping to
        // discard any 0-length messages.
        while amt_buffered > 4 {
            let prefix = &self.buf[*self.pos..*self.pos + 4];
            *self.remaining_this_msg =
                u32::from_be_bytes(prefix.try_into().unwrap()) as usize;
            *self.pos += 4;
            amt_buffered -= 4;
            if *self.remaining_this_msg > 0 && amt_buffered > 0 {
                let n = usize::min(*self.remaining_this_msg, amt_buffered);
                return Some(&self.buf[*self.pos..*self.pos + n]);
            }
        }

        None
    }

    fn consume(&mut self, amt: usize) {
        assert!(amt <= *self.remaining_this_msg);
        assert!(amt <= *self.end - *self.pos);
        *self.pos += amt;
        *self.remaining_this_msg -= amt;
    }
}

impl<T: AsyncRead> AsyncRead for LengthPrefixed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut me = self.project_read();

        // Make sure we were given output space.
        let starting_space_remaining = buf.remaining();
        if starting_space_remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            // Copy as much data as we can from our buffer.
            while let Some(data) = me.buffered_data() {
                debug_assert!(!data.is_empty());
                let n = usize::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                me.consume(n);
                if buf.remaining() == 0 {
                    break;
                }
            }

            // If we copied any data, we're done.
            if buf.remaining() < starting_space_remaining {
                return Poll::Ready(Ok(()));
            }

            // If we had no buffered data, try to read more from our underlying
            // reader. If we read `Ok(0)` (EOF), forward that to our caller.
            if ready!(me.fill_read_buf(cx))? == 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    // Helper that counts how many times `poll_read()` is called.
    #[pin_project]
    struct CountPollRead<R> {
        #[pin]
        inner: R,
        count: usize,
    }

    impl<R> CountPollRead<R> {
        fn new(inner: R) -> Self {
            Self { inner, count: 0 }
        }
    }

    impl<R: AsyncRead> AsyncRead for CountPollRead<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let me = self.project();
            *me.count += 1;
            me.inner.poll_read(cx, buf)
        }
    }

    #[tokio::test]
    async fn async_read_multiple_messages() {
        let (mut tx, rx) = tokio::io::duplex(32);
        let mut rx = LengthPrefixed::with_capacity(CountPollRead::new(rx), 32);
        let mut buf = vec![0; 32];

        // Write nonemtpy message, empty message, nonempty message, all of which
        // fits in our buffer capacity, and confirm we get both nonempty
        // messages back-to-back from one read call.
        tx.write(&5_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hello").await.unwrap();
        tx.write(&0_u32.to_be_bytes()).await.unwrap();
        tx.write(&5_u32.to_be_bytes()).await.unwrap();
        tx.write(b"world").await.unwrap();

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..n], b"helloworld");

        // We should have only polled the inner reader once.
        assert_eq!(rx.inner.count, 1);

        // Repeat the above, but use a tiny buffer. We should only read from the
        // inner stream once more despite multiple small read calls.
        tx.write(&5_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hello").await.unwrap();
        tx.write(&0_u32.to_be_bytes()).await.unwrap();
        tx.write(&5_u32.to_be_bytes()).await.unwrap();
        tx.write(b"world").await.unwrap();

        let buf = &mut buf[..2];
        assert_eq!(rx.read(buf).await.unwrap(), 2);
        assert_eq!(buf, b"he");
        assert_eq!(rx.read(buf).await.unwrap(), 2);
        assert_eq!(buf, b"ll");
        assert_eq!(rx.read(buf).await.unwrap(), 2);
        assert_eq!(buf, b"ow");
        assert_eq!(rx.read(buf).await.unwrap(), 2);
        assert_eq!(buf, b"or");
        assert_eq!(rx.read(buf).await.unwrap(), 2);
        assert_eq!(buf, b"ld");
        assert_eq!(rx.inner.count, 2);
    }

    #[tokio::test]
    async fn async_read_long_message() {
        let (mut tx, rx) = tokio::io::duplex(32);
        let mut rx = LengthPrefixed::with_capacity(CountPollRead::new(rx), 8);

        // Write a message that's longer than our buffer cap.
        tx.write(&11_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hello world").await.unwrap();

        let mut buf = vec![0; 11];
        rx.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello world");

        // We should have polled the inner reader twice (11 bytes + 4 byte
        // prefix = 15; our buffer cap is 8).
        assert_eq!(rx.inner.count, 2);

        // Repeat the above, but use `read()` instead of `read_exact()`.
        tx.write(&11_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hello world").await.unwrap();

        // First read should get the prefix and the first 4 bytes.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hell");
        assert_eq!(rx.inner.count, 3);

        // Second read should get the remaining 7 bytes.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"o world");
        assert_eq!(rx.inner.count, 4);
    }

    #[tokio::test]
    async fn async_read_partial_prefix() {
        let (mut tx, rx) = tokio::io::duplex(32);
        let mut rx = LengthPrefixed::with_capacity(CountPollRead::new(rx), 8);

        // Write two messages; with a buffer cap of 8, we should read the first
        // message in its entirety and half of the length prefix of the second.
        tx.write(&2_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hi").await.unwrap();
        tx.write(&6_u32.to_be_bytes()).await.unwrap();
        tx.write(b" there").await.unwrap();

        let mut buf = vec![0; 32];

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(rx.inner.count, 1);
        assert_eq!(rx.read_remaining_this_msg, 0);
        assert_eq!(rx.read_pos, 6);
        assert_eq!(rx.read_end, 8);

        // The next read has to keep the 2 bytes of the prefix, so it only has
        // room for 6 more bytes: the remaining 2 prefix bytes, and the first 4
        // bytes of the message.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b" the");
        assert_eq!(rx.inner.count, 2);

        // The final read should get the remainder of the second message.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"re");
        assert_eq!(rx.inner.count, 3);
    }
}
