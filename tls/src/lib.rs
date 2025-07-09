// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS based connections

use camino::Utf8PathBuf;
use dice_mfg_msgs::PlatformId;
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsStream;
use x509_cert::{
    der::{self, DecodePem, Encode, Reader, SliceReader},
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

    #[error("Failed to create mock attester: {0}")]
    AttestMock(#[from] dice_verifier::mock::AttestMockError),

    #[error("Failed to create IPCC attester: {0}")]
    AttestIpcc(#[from] dice_verifier::ipcc::IpccError),

    #[error("Failed to parse CBOR encoded CoRIM: {0}")]
    CorimError(#[from] dice_verifier::CorimError),

    #[error(
        "Failed to create MeasurementSet from attestation cert chain & log: {0}"
    )]
    MeasurementSet(#[from] dice_verifier::MeasurementSetError),

    #[error("Failed to create ReferenceMeasurements from Corim: {0}")]
    ReferenceMeasurements(#[from] dice_verifier::ReferenceMeasurementsError),

    #[error("Attest error: {0}")]
    Attest(#[from] dice_verifier::AttestError),

    #[error("AttestData error: {0}")]
    AttestData(#[from] attest_data::AttestDataError),

    #[error("Failed to verify peer attestation cert chain: {0}")]
    AttestCertVerifier(#[from] dice_verifier::PkiPathSignatureVerifierError),

    #[error("Failed to get PlatformId from cert chain: {0}")]
    PlatformIdPkiPath(#[from] dice_mfg_msgs::PlatformIdPkiPathError),

    #[error("Failed to get string representation of PlatformId: {0}")]
    PlatformId(#[from] dice_mfg_msgs::PlatformIdError),

    #[error("failed to convert bytes into an integer: {0}")]
    IntConversion(#[from] std::num::TryFromIntError),

    #[error("Hubpack error: {0}")]
    Hubpack(#[from] hubpack::Error),

    #[error("Failed to verify attestation: {0}")]
    AttestationVerifier(#[from] dice_verifier::VerifyAttestationError),

    #[error("Failed to verify measurements from peer attestation data: {0}")]
    AttestMeasurementsVerifier(#[from] dice_verifier::VerifyMeasurementsError),

    #[error("No certs associated with connection")]
    NoTQCerts,

    #[error("TQ and attestation cert chains disagree on PlatformId")]
    PlatformIdMismatch,
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
    platform_id: PlatformId,
    // Represents whether or not the appraisal against the
    // measurement corpus succeeded
    corpus_appraisal_success: bool,
}

impl<T> Stream<T> {
    pub fn new(
        tls_stream: TlsStream<T>,
        pid: PlatformId,
        corpus_appraisal_success: bool,
    ) -> Stream<T> {
        Stream {
            inner: tls_stream,
            platform_id: pid,
            corpus_appraisal_success,
        }
    }

    // Return the raw tls stream.
    pub fn inner(&mut self) -> &mut TlsStream<T> {
        &mut self.inner
    }

    pub fn peer_platform_id(&self) -> &PlatformId {
        &self.platform_id
    }

    pub fn appraisal_success(&self) -> bool {
        self.corpus_appraisal_success
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

fn certs_to_der(certs: &[Certificate]) -> Result<Vec<u8>, Error> {
    let mut der = Vec::new();

    for cert in certs {
        der.append(&mut cert.to_der()?);
    }

    Ok(der)
}

fn certs_from_der(buf: &[u8]) -> Result<Vec<Certificate>, Error> {
    let mut certs = Vec::new();
    let mut reader = SliceReader::new(buf)?;

    while !reader.is_finished() {
        certs.push(reader.decode()?);
    }

    Ok(certs)
}

async fn recv_msg<T: AsyncReadExt + Unpin>(
    stream: &mut T,
) -> Result<Vec<u8>, Error> {
    // to receive a message we first get its length that is a u32 serialized as
    // a little endian byte array
    let mut msg_len = [0u8; 4];
    stream.read_exact(&mut msg_len).await?;
    let msg_len = u32::from_le_bytes(msg_len).try_into()?;

    // with the length we can then get the message body
    let mut buf = vec![0u8; msg_len];
    stream.read_exact(&mut buf).await?;

    Ok(buf)
}

async fn send_msg<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    msg: &[u8],
) -> Result<(), Error> {
    // to send a message we first send the receiver its length as a u32
    // serialized as a little endian byte array
    let len: u32 = msg.len().try_into()?;
    stream.write_all(&len.to_le_bytes()).await?;
    // then we send the message
    Ok(stream.write_all(msg).await?)
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
        attest = {which = "ipcc"}
        "#;

        let _: keys::SprocketsConfig = toml::from_str(ipcc).unwrap();

        let local = r#"
        resolve = { which = "local", priv_key = "/path/to/tq-priv.pem", cert_chain = "/path/to/tq-chain.pem" }
        attest = { which = "local", priv_key = "/path/to/attest-priv.pem", cert_chain = "/path/to/attest-chain.pem", log = "/path/to/log.bin" }

        roots = ["/path/to/root1"]
        "#;

        let _: keys::SprocketsConfig = toml::from_str(local).unwrap();
    }

    #[tokio::test]
    async fn no_corpus() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let log = logger();

        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46457").unwrap();

        let server_config = keys::SprocketsConfig {
            attest: keys::AttestConfig::Local {
                priv_key: pki_keydir.join("test-alias-1.key.pem"),
                cert_chain: pki_keydir.join("test-alias-1.certlist.pem"),
                log: pki_keydir.join("log.bin"),
            },
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
        let corpus = vec![
            // we don't use a corpus
        ];

        tokio::spawn(async move {
            let mut server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            let (mut stream, _) =
                server.accept(corpus.as_slice()).await.unwrap();
            let mut buf = String::new();
            stream.read_to_string(&mut buf).await.unwrap();

            assert_eq!(buf.as_str(), MSG);

            // Inform the main task that the test is complete.
            let _ = done_tx.send(());
        });

        // Loop until we succesfully connect
        let mut stream = loop {
            let client_config = keys::SprocketsConfig {
                attest: keys::AttestConfig::Local {
                    priv_key: pki_keydir.join("test-alias-2.key.pem"),
                    cert_chain: pki_keydir.join("test-alias-2.certlist.pem"),
                    log: pki_keydir.join("log.bin"),
                },
                roots: vec![pki_keydir.join("test-root-a.cert.pem")],
                resolve: keys::ResolveSetting::Local {
                    priv_key: pki_keydir.join("test-sprockets-auth-2.key.pem"),
                    cert_chain: pki_keydir
                        .join("test-sprockets-auth-2.certlist.pem"),
                },
            };

            let corpus = vec![
                // We don't use a corpus
            ];

            if let Ok(stream) =
                Client::connect(client_config, addr, corpus, log.clone()).await
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

    #[tokio::test]
    async fn basic() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let log = logger();

        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46456").unwrap();

        let server_config = keys::SprocketsConfig {
            attest: keys::AttestConfig::Local {
                priv_key: pki_keydir.join("test-alias-1.key.pem"),
                cert_chain: pki_keydir.join("test-alias-1.certlist.pem"),
                log: pki_keydir.join("log.bin"),
            },
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
        let corpus = vec![
            pki_keydir.join("corim-rot.cbor"),
            pki_keydir.join("corim-sp.cbor"),
        ];

        tokio::spawn(async move {
            let mut server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            let (mut stream, _) =
                server.accept(corpus.as_slice()).await.unwrap();
            let mut buf = String::new();
            stream.read_to_string(&mut buf).await.unwrap();

            assert_eq!(buf.as_str(), MSG);

            // Inform the main task that the test is complete.
            let _ = done_tx.send(());
        });

        // Loop until we succesfully connect
        let mut stream = loop {
            let client_config = keys::SprocketsConfig {
                attest: keys::AttestConfig::Local {
                    priv_key: pki_keydir.join("test-alias-2.key.pem"),
                    cert_chain: pki_keydir.join("test-alias-2.certlist.pem"),
                    log: pki_keydir.join("log.bin"),
                },
                roots: vec![pki_keydir.join("test-root-a.cert.pem")],
                resolve: keys::ResolveSetting::Local {
                    priv_key: pki_keydir.join("test-sprockets-auth-2.key.pem"),
                    cert_chain: pki_keydir
                        .join("test-sprockets-auth-2.certlist.pem"),
                },
            };

            let corpus = vec![
                pki_keydir.join("corim-rot.cbor"),
                pki_keydir.join("corim-sp.cbor"),
            ];

            if let Ok(stream) =
                Client::connect(client_config, addr, corpus, log.clone()).await
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

    #[tokio::test]
    async fn unattested_client() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let log = logger();

        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46459").unwrap();

        let server_config = keys::SprocketsConfig {
            attest: keys::AttestConfig::Local {
                priv_key: pki_keydir.join("test-alias-1.key.pem"),
                cert_chain: pki_keydir.join("test-alias-1.certlist.pem"),
                log: pki_keydir.join("log.bin"),
            },
            roots: vec![pki_keydir.join("test-root-a.cert.pem")],
            resolve: keys::ResolveSetting::Local {
                priv_key: pki_keydir.join("test-sprockets-auth-1.key.pem"),
                cert_chain: pki_keydir
                    .join("test-sprockets-auth-1.certlist.pem"),
            },
        };

        // Message to send over TLS
        const MSG: &str = "Hello Joe";

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let log2 = log.clone();
        let corpus = vec![
            pki_keydir.join("corim-rot.cbor"),
            pki_keydir.join("corim-sp.cbor"),
        ];

        let handle = tokio::spawn(async move {
            let mut server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            // We never expect this to succeed
            let _ = match server.accept(corpus.as_slice()).await {
                Ok(_) => panic!("This should not succed"),
                Err(_) => done_tx.send(()),
            };
        });

        let client_config = client::Client::new_tls_local_client_config(
            pki_keydir.join("test-sprockets-auth-2.key.pem"),
            pki_keydir.join("test-sprockets-auth-2.certlist.pem"),
            vec![pki_keydir.join("test-root-a.cert.pem")],
            log,
        )
        .unwrap();

        let dnsname =
            rustls::pki_types::ServerName::try_from("unknown.com").unwrap();

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
            client_config,
        ));
        let stream = loop {
            if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
                break s;
            };
            sleep(Duration::from_millis(1)).await;
        };

        let mut stream = connector.connect(dnsname, stream).await.unwrap();

        stream.write_all(MSG.as_bytes()).await.unwrap();

        // Trigger an EOF so that `read_to_string` in the acceptor task
        // completes.
        stream.shutdown().await.unwrap();

        // Wait for the other side of the connection to receive and assert the
        // message
        let _ = done_rx.await;

        handle.await.unwrap();
    }
}
