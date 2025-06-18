// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS based connections

use camino::Utf8PathBuf;
use rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;
use rustls::crypto::ring::kx_group::X25519;
use rustls::crypto::CryptoProvider;
use slog::error;
use std::io::prelude::*;
use std::io::IoSlice;
use std::marker::Unpin;

#[cfg(any(unix, target_os = "wasi"))]
use std::os::fd::{AsRawFd, RawFd};

use anyhow::Context;
use std::fs::File;
use std::pin::Pin;
use std::task::{self, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsStream;
use x509_cert::{
    der::{self, DecodePem},
    Certificate,
};

pub mod client;
pub mod ipcc;
pub mod keys;
pub mod server;

pub use client::Client;
pub use server::Server;

/// The top-level sprockets error type
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("der error: {0}")]
    Der(#[from] der::Error),

    #[error("pem error: {0}")]
    Pem(#[from] pem_rfc7468::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    // TODO: Return a more specific error / errors from dice-util
    #[error("dice error: {0}")]
    Dice(#[from] anyhow::Error),

    #[error("RotRequest: {0}")]
    RotRequest(#[from] ipcc::RotRequestError),

    #[error("Incorrect Private Key Format: {0}")]
    BadPrivateKey(String),
}

/// A type representing an established sprockets connection.
///
/// Users can send and recieve directly over this stream.
///
/// By the time a `Stream` is returned:
///    * A TCP stream has been established
///    * A mutual TLS session has been established over that TCP stream
///    * Each side has successfully attested to the other side's measurements
///      over the TLS session.
pub struct Stream<T> {
    inner: TlsStream<T>,
}

impl<T> Stream<T> {
    pub fn new(tls_stream: TlsStream<T>) -> Stream<T> {
        Stream { inner: tls_stream }
    }

    // Return the raw tls stream.
    pub fn inner(&mut self) -> &mut TlsStream<T> {
        &mut self.inner
    }
}

#[cfg(any(unix, target_os = "wasi"))]
impl<T: AsRawFd> AsRawFd for Stream<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}
impl<T> AsyncRead for Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut pinned = std::pin::pin!(&mut self.get_mut().inner);
        pinned.as_mut().poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut pinned = std::pin::pin!(&mut self.get_mut().inner);
        pinned.as_mut().poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let mut pinned = std::pin::pin!(&mut self.get_mut().inner);
        pinned.as_mut().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut pinned = std::pin::pin!(&mut self.get_mut().inner);
        pinned.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut pinned = std::pin::pin!(&mut self.get_mut().inner);
        pinned.as_mut().poll_shutdown(cx)
    }
}

pub fn load_root_cert(path: &Utf8PathBuf) -> Result<Certificate, Error> {
    let mut root_cert_pem = Vec::new();
    File::open(path)
        .with_context(|| format!("failed to open {}", &path))?
        .read_to_end(&mut root_cert_pem)
        .with_context(|| format!("failed to read {}", &path))?;
    let root = Certificate::from_pem(&root_cert_pem).with_context(|| {
        format!("failed to convert pem read from {}", &path)
    })?;
    Ok(root)
}

/// Return a common [`CryptoProvider`] for use by both client and server.
///
/// Use `ring` as a crypto provider. `aws_lc` doesn't compile on illumos.
///
/// Only allow X25519 for key exchange
///
/// Only allow CHACHA20_POLY1305_SHA256 for symmetric crypto
pub fn crypto_provider() -> CryptoProvider {
    let mut crypto_provider = rustls::crypto::ring::default_provider();
    crypto_provider.kx_groups = vec![X25519];
    crypto_provider.cipher_suites = vec![TLS13_CHACHA20_POLY1305_SHA256];
    crypto_provider
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use slog::Drain;
    use std::net::SocketAddrV6;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::sleep;

    pub fn logger() -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = std::sync::Mutex::new(drain).fuse();
        slog::Logger::root(drain, slog::o!("component" => "sprockets"))
    }

    #[tokio::test]
    async fn toml_config() {
        let ipcc = r#"
        resolve = {which = "ipcc"}
        roots = ["/path/to/root1", "/path/to/root2"]
        "#;

        let _: keys::SprocketsConfig = toml::from_str(ipcc).unwrap();

        let local = r#"
        resolve = { which = "local", priv_key = "/path/to/priv.pem", cert_chain = "/path/to/chain.pem" }

        roots = ["/path/to/root1"]
        "#;

        let _: keys::SprocketsConfig = toml::from_str(local).unwrap();
    }

    #[tokio::test]
    async fn basic() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let log = logger();

        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46456").unwrap();

        let server_config = keys::SprocketsConfig {
            roots: vec![pki_keydir.join("test-root-a.cert.pem")],
            resolve: keys::ResolveSetting::Local {
                priv_key: pki_keydir.join("test-sprockets-auth-1.key.pem"),
                cert_chain: pki_keydir
                    .join("test-sprockets-auth-1.certlist.pem"),
            },
        };

        // Message to send over TLS
        const MSG: &str = "Hello Joe";

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let log2 = log.clone();

        tokio::spawn(async move {
            let mut server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();
            let (mut stream, _) = server.accept().await.unwrap();
            let mut buf = String::new();
            stream.read_to_string(&mut buf).await.unwrap();

            assert_eq!(buf.as_str(), MSG);

            // Inform the main task that the test is complete.
            let _ = done_tx.send(());
        });

        // Loop until we succesfully connect
        let mut stream = loop {
            let client_config = keys::SprocketsConfig {
                roots: vec![pki_keydir.join("test-root-a.cert.pem")],
                resolve: keys::ResolveSetting::Local {
                    priv_key: pki_keydir.join("test-sprockets-auth-2.key.pem"),
                    cert_chain: pki_keydir
                        .join("test-sprockets-auth-2.certlist.pem"),
                },
            };

            if let Ok(stream) =
                Client::connect(client_config, addr, log.clone()).await
            {
                break stream;
            }
            sleep(Duration::from_millis(1)).await;
        };

        stream.write_all(MSG.as_bytes()).await.unwrap();

        // Trigger an EOF so that `read_to_string` in the acceptor task
        // completes.
        stream.shutdown().await.unwrap();

        // Wait for the other side of the connection to receive and assert the
        // message
        let _ = done_rx.await;
    }
}
