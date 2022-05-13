// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use futures::future::BoxFuture;
use futures::ready;
use hyper::server::accept::Accept;
use sprockets_common::Ed25519PublicKey;
use sprockets_host::Ed25519Certificates;
use sprockets_host::RotManagerHandle;
use sprockets_host::Session;
use sprockets_host::SessionHandshakeError;
use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

type SessionFut<'a, T, E> =
    BoxFuture<'a, Result<Session<T>, SessionHandshakeError<E>>>;

/// A stream protected with sprockets.
pub struct SprocketsStream<T, E: Error> {
    state: State<T, E>,
}

enum State<T, E: Error> {
    Handshaking(SessionFut<'static, T, E>),
    Streaming(Session<T>),
}

impl<T, E> AsyncRead for SprocketsStream<T, E>
where
    T: AsyncRead + Unpin,
    E: Error,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match &mut me.state {
            State::Handshaking(ref mut fut) => {
                match ready!(fut.as_mut().poll(cx)) {
                    Ok(mut session) => {
                        let result = Pin::new(&mut session).poll_read(cx, buf);
                        me.state = State::Streaming(session);
                        result
                    }
                    Err(err) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        err.to_string(),
                    ))),
                }
            }
            State::Streaming(ref mut stream) => {
                Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

impl<T, E> AsyncWrite for SprocketsStream<T, E>
where
    T: AsyncWrite + Unpin,
    E: Error,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let me = self.get_mut();
        match &mut me.state {
            State::Handshaking(ref mut fut) => {
                match ready!(fut.as_mut().poll(cx)) {
                    Ok(mut session) => {
                        let result = Pin::new(&mut session).poll_write(cx, buf);
                        me.state = State::Streaming(session);
                        result
                    }
                    Err(err) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        err.to_string(),
                    ))),
                }
            }
            State::Streaming(ref mut stream) => {
                Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut self.get_mut().state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut self.get_mut().state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
        }
    }
}

pub struct SprocketsAcceptor<T, E: Error> {
    listener: T,
    manufacturing_public_key: Ed25519PublicKey,
    rot_certs: Ed25519Certificates,
    rot_handle: RotManagerHandle<E>,
    rot_timeout: Duration,
}

impl<T, E: Error> SprocketsAcceptor<T, E> {
    pub fn new(
        listener: T,
        manufacturing_public_key: Ed25519PublicKey,
        rot_certs: Ed25519Certificates,
        rot_handle: RotManagerHandle<E>,
        rot_timeout: Duration,
    ) -> Self {
        // TODO: We could ask the RoT for its certs instead of requiring our
        // caller to? We'd be exchanging an arg for making ourselves fallible,
        // plus every acceptor created would re-query the RoT. I think the way
        // we have it now is better? Remove this comment after PR review.
        Self {
            listener,
            manufacturing_public_key,
            rot_certs,
            rot_handle,
            rot_timeout,
        }
    }
}

impl<T, E> Accept for SprocketsAcceptor<T, E>
where
    T: Accept + Unpin,
    T::Conn: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: Error + Send + 'static,
{
    type Conn = SprocketsStream<T::Conn, E>;
    type Error = T::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let me = self.get_mut();
        match ready!(Pin::new(&mut me.listener).poll_accept(cx)) {
            Some(Ok(conn)) => {
                let session = Session::new_server(
                    conn,
                    me.manufacturing_public_key,
                    me.rot_handle.clone(),
                    me.rot_certs,
                    me.rot_timeout,
                );
                let state = State::Handshaking(Box::pin(session));
                Poll::Ready(Some(Ok(SprocketsStream { state })))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            None => Poll::Ready(None),
        }
    }
}
