// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Buffered reader/writer that sends `u32`-length-prefixed messages on the
//! underlying channel.

use futures::ready;
use pin_project::pin_project;
use std::io;
use std::mem;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

#[pin_project]
pub(crate) struct LengthPrefixed<T> {
    #[pin]
    inner: T,
    write_current: Vec<u8>,
    write_current_pos: usize,
    write_next: Vec<u8>,
    read_buf: Box<[u8]>,
    read_remaining_this_msg: usize,
    read_pos: usize,
    read_end: usize,
}

impl<T> LengthPrefixed<T> {
    pub(crate) fn with_capacity(inner: T, cap: usize) -> Self {
        // We work with 4-byte length prefixes; make sure there's room for at
        // least a byte of data in addition to those prefixes.
        assert!(cap >= 5);
        let read_buf = vec![0; cap];
        Self {
            inner,
            write_current: Vec::with_capacity(cap),
            write_current_pos: 0,
            write_next: Vec::with_capacity(cap),
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

    fn project_write(self: Pin<&mut Self>) -> ProjectedWrite<'_, T> {
        let me = self.project();
        ProjectedWrite {
            inner: me.inner,
            current: me.write_current,
            current_pos: me.write_current_pos,
            next: me.write_next,
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

struct ProjectedWrite<'a, T> {
    inner: Pin<&'a mut T>,
    current: &'a mut Vec<u8>,
    current_pos: &'a mut usize,
    next: &'a mut Vec<u8>,
}

impl<T: AsyncWrite> ProjectedWrite<'_, T> {
    fn set_current_from_next(&mut self) {
        // `next` should have at least four bytes (space for the length prefix).
        assert!(self.next.len() >= 4);

        // Assign the length prefix.
        let len = self.next.len();
        let len =
            u32::try_from(len - 4).expect("buffer capacity overflows u32");
        self.next[..4].copy_from_slice(&len.to_be_bytes());

        // Do the swap, and clear the new `next`.
        mem::swap(self.next, self.current);
        self.next.clear();
    }

    fn buffer_into_next(&mut self, data: &[u8]) -> usize {
        // Do nothing if we have no data to buffer.
        if data.is_empty() {
            return 0;
        }

        // If we haven't yet started buffering the next message, do so now: skip
        // ahead 4 bytes to leave room for the length prefix.
        if self.next.is_empty() {
            self.next.resize(4, 0);
        }

        // Buffer as much of `data` as we can.
        let n = usize::min(data.len(), self.next.capacity() - self.next.len());
        self.next.extend_from_slice(&data[..n]);

        n
    }

    fn next_is_full(&self) -> bool {
        self.next.capacity() == self.next.len()
    }

    fn flush_current(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut ret = Ok(());
        while *self.current_pos < self.current.len() {
            match ready!(self
                .inner
                .as_mut()
                .poll_write(cx, &self.current[*self.current_pos..]))
            {
                Ok(0) => {
                    ret = Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write the buffered data",
                    ));
                    break;
                }
                Ok(n) => *self.current_pos += n,
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            }
        }
        if *self.current_pos == self.current.len() {
            *self.current_pos = 0;
            self.current.clear();
        }
        Poll::Ready(ret)
    }
}

impl<T: AsyncWrite> AsyncWrite for LengthPrefixed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut me = self.project_write();

        // If we still have buffered data from the message we're currently
        // sending, try to flush it to our underlying writer (and return if we
        // can't).
        if !me.current.is_empty() {
            ready!(me.flush_current(cx))?;
        }

        // `flush_current` should only return successfully if all data has been
        // flushed; sanity check.
        debug_assert!(me.current.is_empty());

        // Buffer as much of `buf` as we can.
        let mut n = me.buffer_into_next(buf);

        // If we've filled the next buffer, swap it with `current` and continue
        // buffering.
        if me.next_is_full() {
            me.set_current_from_next();

            // Do we have leftover data from the caller we could continue to
            // buffer?
            if n < buf.len() {
                let m = me.buffer_into_next(&buf[n..]);
                n += m;
            }
        }

        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut me = self.project_write();
        ready!(me.flush_current(cx))?;
        if !me.next.is_empty() {
            me.set_current_from_next();
            ready!(me.flush_current(cx))?;
        }
        me.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut me = self.project_write();
        ready!(me.flush_current(cx))?;
        if !me.next.is_empty() {
            me.set_current_from_next();
            ready!(me.flush_current(cx))?;
        }
        me.inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    // Helper that counts how many times `poll_read()` is called.
    #[pin_project]
    struct CountPoll<T> {
        #[pin]
        inner: T,
        read_count: usize,
        write_count: usize,
    }

    impl<T> CountPoll<T> {
        fn new(inner: T) -> Self {
            Self {
                inner,
                read_count: 0,
                write_count: 0,
            }
        }
    }

    impl<T: AsyncRead> AsyncRead for CountPoll<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let me = self.project();
            *me.read_count += 1;
            me.inner.poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite> AsyncWrite for CountPoll<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let me = self.project();
            *me.write_count += 1;
            me.inner.poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            self.project().inner.poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            self.project().inner.poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn async_read_multiple_messages() {
        let (mut tx, rx) = tokio::io::duplex(32);
        let mut rx = LengthPrefixed::with_capacity(CountPoll::new(rx), 32);
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
        assert_eq!(rx.inner.read_count, 1);

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
        assert_eq!(rx.inner.read_count, 2);
    }

    #[tokio::test]
    async fn async_read_long_message() {
        let (mut tx, rx) = tokio::io::duplex(32);
        let mut rx = LengthPrefixed::with_capacity(CountPoll::new(rx), 8);

        // Write a message that's longer than our buffer cap.
        tx.write(&11_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hello world").await.unwrap();

        let mut buf = vec![0; 11];
        rx.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello world");

        // We should have polled the inner reader twice (11 bytes + 4 byte
        // prefix = 15; our buffer cap is 8).
        assert_eq!(rx.inner.read_count, 2);

        // Repeat the above, but use `read()` instead of `read_exact()`.
        tx.write(&11_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hello world").await.unwrap();

        // First read should get the prefix and the first 4 bytes.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hell");
        assert_eq!(rx.inner.read_count, 3);

        // Second read should get the remaining 7 bytes.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"o world");
        assert_eq!(rx.inner.read_count, 4);
    }

    #[tokio::test]
    async fn async_read_partial_prefix() {
        let (mut tx, rx) = tokio::io::duplex(32);
        let mut rx = LengthPrefixed::with_capacity(CountPoll::new(rx), 8);

        // Write two messages; with a buffer cap of 8, we should read the first
        // message in its entirety and half of the length prefix of the second.
        tx.write(&2_u32.to_be_bytes()).await.unwrap();
        tx.write(b"hi").await.unwrap();
        tx.write(&6_u32.to_be_bytes()).await.unwrap();
        tx.write(b" there").await.unwrap();

        let mut buf = vec![0; 32];

        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(rx.inner.read_count, 1);
        assert_eq!(rx.read_remaining_this_msg, 0);
        assert_eq!(rx.read_pos, 6);
        assert_eq!(rx.read_end, 8);

        // The next read has to keep the 2 bytes of the prefix, so it only has
        // room for 6 more bytes: the remaining 2 prefix bytes, and the first 4
        // bytes of the message.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b" the");
        assert_eq!(rx.inner.read_count, 2);

        // The final read should get the remainder of the second message.
        let n = rx.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"re");
        assert_eq!(rx.inner.read_count, 3);
    }

    #[tokio::test]
    async fn async_write_small_messages() {
        let (tx, mut rx) = tokio::io::duplex(32);
        let mut tx = LengthPrefixed::with_capacity(CountPoll::new(tx), 8);

        // Sanity check that the write buffer capacity is exactly 8, as our test
        // logic below assumes it.
        assert_eq!(tx.write_current.capacity(), 8);
        assert_eq!(tx.write_next.capacity(), 8);

        // Buffer capacity is 8; with a length prefix of 4, we should be able to
        // write individual bytes but only see writes to the underlying duplex
        // stream every four.
        for i in 0..8 {
            tx.write_all(&[i]).await.unwrap();
            if i < 4 {
                assert_eq!(tx.inner.write_count, 0);
            } else {
                assert_eq!(tx.inner.write_count, 1);
            }
        }
        tx.flush().await.unwrap();
        assert_eq!(tx.inner.write_count, 2);

        let expected = &[
            0, 0, 0, 4, // first message prefix
            0, 1, 2, 3, // first message data
            0, 0, 0, 4, // second message prefix
            4, 5, 6, 7, // second message data
        ];
        let mut buf = vec![0; expected.len()];
        rx.read_exact(&mut buf).await.unwrap();

        assert_eq!(buf, expected);
    }

    #[tokio::test]
    async fn async_write_message_crosses_buffer_boundary() {
        let (tx, mut rx) = tokio::io::duplex(32);
        let mut tx = LengthPrefixed::with_capacity(CountPoll::new(tx), 8);

        // Sanity check that the write buffer capacity is exactly 8, as our test
        // logic below assumes it.
        assert_eq!(tx.write_current.capacity(), 8);
        assert_eq!(tx.write_next.capacity(), 8);

        // Write 3 bytes; this should insert space for a 4-byte prefix and leave
        // room for 1 more byte (without writing anything to the underlying
        // duplex stream).
        tx.write_all(b"012").await.unwrap();
        assert_eq!(tx.inner.write_count, 0);
        assert_eq!(tx.write_next.len(), 7);
        assert_eq!(&tx.write_next[4..], b"012");

        // Try to write 3 more bytes; the first of these bytes should be
        // included in the write that goes to the underlying stream, and the
        // remaining 2 bytes should end up in the new `write_next` buffer.
        //
        // This _still_ doesn't trigger any writes to the underlying stream;
        // it only forces a buffer swap (writes will happen the next time a
        // write is called).
        tx.write_all(b"345").await.unwrap();
        assert_eq!(tx.inner.write_count, 0);
        assert_eq!(&tx.write_current[..4], 4_u32.to_be_bytes());
        assert_eq!(&tx.write_current[4..], b"0123");
        assert_eq!(tx.write_next.len(), 6);
        assert_eq!(&tx.write_next[4..], b"45");

        // Shut down the stream (which should also flush both buffers), then
        // drop it.
        tx.shutdown().await.unwrap();
        assert_eq!(tx.inner.write_count, 2);
        mem::drop(tx);

        let mut buf = Vec::new();
        rx.read_to_end(&mut buf).await.unwrap();

        let expected = &[
            0, 0, 0, 4, // first message prefix
            b'0', b'1', b'2', b'3', // first message data
            0, 0, 0, 2, // second message prefix
            b'4', b'5', // second message data
        ];
        assert_eq!(buf, expected);
    }

    #[tokio::test]
    async fn bidirectional() {
        let (dup0, dup1) = tokio::io::duplex(32);

        let dup0 = LengthPrefixed::with_capacity(dup0, 16);
        let dup1 = LengthPrefixed::with_capacity(dup1, 16);

        // The flow of data is:
        //
        // 1. We write into `tx`, which is a `LengthPrefixed` around dup0.
        // 2. `LengthPrefixed` chunks it into length-prefixed messages and
        //    writes it to `dup1` (which is wrapped in another
        //    `LengthPrefixed`).
        // 3. The dup1 `LengthPrefixed` reads that data (stripping the length
        //    prefix).
        // 4. We copy the data back into dup1, which adds length prefixing and
        //    sends it to the read half of dup0.
        // 5. We read from `rx`, which strips the length prefixing.
        let (mut rx, mut tx) = tokio::io::split(dup0);
        let (mut src, mut sink) = tokio::io::split(dup1);

        tokio::spawn(async move {
            // Echo data on dup1; this takes care of steps 3 and 4 above.
            tokio::io::copy(&mut src, &mut sink).await.unwrap();
        });

        let written = tokio::spawn(async move {
            let mut written = Vec::new();

            // Create messages of multiple lengths, including those both shorter
            // and longer than our `LengthPrefixed` buffer capacity and the
            // capacity of the underlying duplex streams.
            for i in 0..64 {
                let mut msg = vec![i as u8; i];
                tx.write_all(&msg).await.unwrap();
                written.append(&mut msg);
            }
            tx.shutdown().await.unwrap();

            written
        });

        let mut read = Vec::new();
        rx.read_to_end(&mut read).await.unwrap();

        let written = written.await.unwrap();

        assert_eq!(read, written);
    }
}
