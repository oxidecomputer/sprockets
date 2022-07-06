// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use futures::future::BoxFuture;
use hyper::client::connect::Connection;
use hyper::service::Service;
use hyper::Uri;
use sprockets_host::Ed25519Certificates;
use sprockets_host::RotManagerHandle;
use sprockets_host::Session;
use sprockets_host::SessionHandshakeError;
use std::error::Error;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pub struct SprocketsConnection<T>(Session<T>);

impl<T> Connection for SprocketsConnection<T>
where
    T: AsyncRead + AsyncWrite + Connection + Unpin,
{
    fn connected(&self) -> hyper::client::connect::Connected {
        self.0.get_ref().connected()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SprocketsConnection<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SprocketsConnection<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[derive(Debug, Error)]
pub enum ConnectorError<C: Error, S: Error> {
    #[error("connection error: {0}")]
    ConnectionError(C),
    #[error("sprockets error: {0}")]
    SprocketsError(SessionHandshakeError<S>),
}

pub struct SprocketsConnector<T, E: Error> {
    connector: T,
    rot_certs: Ed25519Certificates,
    rot_handle: RotManagerHandle<E>,
    rot_timeout: Duration,
}

// We can't derive `Clone` because that would require `E: Clone`, which we don't
// actually need. Implement it by hand. We do still need `T: Clone`.
impl<T: Clone, E: Error> Clone for SprocketsConnector<T, E> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            rot_certs: self.rot_certs,
            rot_handle: self.rot_handle.clone(),
            rot_timeout: self.rot_timeout,
        }
    }
}

impl<T, E: Error> SprocketsConnector<T, E> {
    pub fn new(
        connector: T,
        rot_certs: Ed25519Certificates,
        rot_handle: RotManagerHandle<E>,
        rot_timeout: Duration,
    ) -> Self {
        Self {
            connector,
            rot_certs,
            rot_handle,
            rot_timeout,
        }
    }
}

impl<T, E> Service<Uri> for SprocketsConnector<T, E>
where
    T: Service<Uri>,
    T::Response: AsyncRead + AsyncWrite + Send + Unpin,
    T::Future: Send + 'static,
    T::Error: Error,
    E: Error + Send + 'static,
{
    type Response = SprocketsConnection<T::Response>;
    type Error = ConnectorError<T::Error, E>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.connector.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(ConnectorError::ConnectionError(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let connecting = self.connector.call(req);
        let rot_handle = self.rot_handle.clone();
        let rot_certs = self.rot_certs;
        let rot_timeout = self.rot_timeout;

        let fut = async move {
            let inner =
                connecting.await.map_err(ConnectorError::ConnectionError)?;
            let session = Session::new_client(
                inner,
                rot_handle.clone(),
                rot_certs,
                rot_timeout,
            )
            .await
            .map_err(ConnectorError::SprocketsError)?;
            Ok(SprocketsConnection(session))
        };
        Box::pin(fut)
    }
}
