// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS based connections
//!
//! The default transport is TCP ([`Client`] / [`Server`]). With the `quic`
//! cargo feature enabled, the `quic` module provides the same
//! mutually-authenticated, attested channel over QUIC.

use camino::Utf8PathBuf;
use dice_mfg_msgs::PlatformId;
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;
use rustls::crypto::aws_lc_rs::kx_group::X25519;
use rustls::crypto::CryptoProvider;
use slog::error;
use slog_error_chain::SlogInlineError;
use std::io::IoSlice;
use std::marker::Unpin;

#[cfg(any(unix, target_os = "wasi"))]
use std::os::fd::{AsRawFd, RawFd};

use std::pin::Pin;
use std::task::{self, Poll};
use std::{fs, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsStream;
use x509_cert::{
    der::{self, Decode, DecodePem},
    Certificate,
};

mod attest;
pub mod client;
mod config;
pub mod ipcc;
pub mod keys;
#[cfg(feature = "quic")]
pub mod quic;
pub mod server;

pub use client::Client;
pub use server::Server;

/// The top-level sprockets error type
#[derive(thiserror::Error, Debug, SlogInlineError)]
pub enum Error {
    #[error("rustls error")]
    Rustls(#[from] rustls::Error),

    #[error("der error")]
    Der(#[from] der::Error),

    #[error("pem error")]
    Pem(#[from] pem_rfc7468::Error),

    #[error("io error")]
    Io(#[from] std::io::Error),

    #[error("io error: {path}")]
    FailedRead {
        path: Utf8PathBuf,
        #[source]
        err: io::Error,
    },

    #[error("RotRequest")]
    RotRequest(#[from] ipcc::RotRequestError),

    #[error("Incorrect Private Key Format: {0}")]
    BadPrivateKey(String),

    #[error("Failed to create mock attester")]
    AttestMock(#[from] dice_verifier::mock::AttestMockError),

    #[error("Failed to create IPCC attester")]
    AttestIpcc(#[from] dice_verifier::ipcc::IpccError),

    #[error("Failed to parse CBOR encoded CoRIM")]
    CorimError(#[from] dice_verifier::CorimError),

    #[error(
        "Failed to create MeasurementSet from attestation cert chain & log"
    )]
    MeasurementSet(#[from] dice_verifier::MeasurementSetError),

    #[error("Failed to create ReferenceMeasurements from Corim")]
    ReferenceMeasurements(#[from] dice_verifier::ReferenceMeasurementsError),

    #[error("Attest error")]
    Attest(#[from] dice_verifier::AttestError),

    #[error("AttestData error")]
    AttestData(#[from] attest_data::AttestDataError),

    #[error("Nonce error")]
    NonceError(#[from] attest_data::NonceError),

    #[error("Failed to verify peer attestation cert chain")]
    AttestCertVerifier(#[from] dice_verifier::PkiPathSignatureVerifierError),

    #[error("Failed to get PlatformId from cert chain")]
    PlatformIdPkiPath(#[from] dice_mfg_msgs::PlatformIdPkiPathError),

    #[error("Failed to get string representation of PlatformId")]
    PlatformId(#[from] dice_mfg_msgs::PlatformIdError),

    #[error("failed to convert bytes into an integer")]
    IntConversion(#[from] std::num::TryFromIntError),

    #[error("Hubpack error:")]
    Hubpack(#[from] hubpack::Error),

    #[error("protocol message length {len} exceeds maximum {max}")]
    MessageTooLarge { len: usize, max: usize },

    #[error("Failed to verify attestation")]
    AttestationVerifier(#[from] dice_verifier::VerifyAttestationError),

    #[error("Failed to verify measurements from {peer}")]
    AttestMeasurementsVerifier {
        peer: PlatformId,

        #[source]
        err: dice_verifier::VerifyMeasurementsError,
    },

    #[error("No certs associated with connection")]
    NoTQCerts,

    #[error("TQ and attestation cert chains disagree on PlatformId")]
    PlatformIdMismatch,

    #[error("Cannot support requested protocol version")]
    ProtocolVersion,

    #[error("Client didn't request the proper version")]
    ClientMismatch,

    #[error("Client gave up negotating the version")]
    ClientGaveUp,

    #[cfg(feature = "quic")]
    #[error("QUIC connect error")]
    QuicConnect(#[from] quinn::ConnectError),

    #[cfg(feature = "quic")]
    #[error("QUIC connection error")]
    QuicConnection(#[from] quinn::ConnectionError),

    #[cfg(feature = "quic")]
    #[error("QUIC TLS config has no RFC 9001 Initial cipher suite")]
    QuicNoInitialCipherSuite(
        #[from] quinn::crypto::rustls::NoInitialCipherSuite,
    ),

    #[cfg(feature = "quic")]
    #[error("QUIC endpoint is closed")]
    QuicEndpointClosed,
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
    let cert = fs::read(path).map_err(|err| Error::FailedRead {
        path: path.to_owned(),
        err,
    })?;
    let cert = Certificate::from_pem(&cert)?;

    Ok(cert)
}

/// Derives the peer's [`PlatformId`] from the trust quorum certificate chain
/// presented during the TLS handshake.
///
/// `tls_certs` is the peer's chain as rustls reports it, end entity first. The
/// resulting identity is the one an attestation exchange must agree with: the
/// caller is expected to compare it against the `PlatformId` of the peer's
/// attestation cert chain and reject the connection on a mismatch.
///
/// # Errors
///
/// Returns [`Error::NoTQCerts`] if `tls_certs` is `None`, which is how both an
/// unauthenticated peer and a rustls handle that has not finished its handshake
/// present themselves.
pub(crate) fn platform_id_from_tls_certs(
    tls_certs: Option<&[rustls::pki_types::CertificateDer<'_>]>,
) -> Result<PlatformId, Error> {
    let Some(tls_certs) = tls_certs else {
        return Err(Error::NoTQCerts);
    };

    let mut pki_path = Vec::new();
    for der in tls_certs.iter() {
        pki_path.push(Certificate::from_der(der).map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )
        })?)
    }

    Ok(PlatformId::try_from(&pki_path)?)
}

/// Return a common [`CryptoProvider`] for use by both client and server.
///
/// Uses `aws-lc-rs` as the crypto provider.
///
/// Only allow X25519 for key exchange
///
/// Only allow CHACHA20_POLY1305_SHA256 for symmetric crypto
pub fn crypto_provider() -> CryptoProvider {
    let mut crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
    crypto_provider.kx_groups = vec![X25519];
    crypto_provider.cipher_suites = vec![TLS13_CHACHA20_POLY1305_SHA256];
    crypto_provider
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MeasurementConnectionPolicy;
    use camino::Utf8PathBuf;
    use slog::Drain;
    use std::net::SocketAddrV6;
    use std::str::FromStr;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::sleep;

    pub fn logger() -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = std::sync::Mutex::new(drain).fuse();
        slog::Logger::root(drain, slog::o!("component" => "sprockets"))
    }

    pub fn mock_datadir() -> Utf8PathBuf {
        Utf8PathBuf::from(env!("OUT_DIR"))
    }

    pub fn local_config(
        n: usize,
        enforce: MeasurementConnectionPolicy,
    ) -> keys::SprocketsConfig {
        let mock_datadir = mock_datadir();

        let attest_priv_key =
            mock_datadir.join(format!("test-alias-{n}.key.pem"));
        let attest_cert_chain =
            mock_datadir.join(format!("test-alias-{n}.certlist.pem"));
        let resolve_priv_key =
            mock_datadir.join(format!("test-sprockets-auth-{n}.key.pem"));
        let resolve_cert_chain =
            mock_datadir.join(format!("test-sprockets-auth-{n}.certlist.pem"));

        keys::SprocketsConfig {
            attest: keys::AttestConfig::Local {
                priv_key: attest_priv_key,
                cert_chain: attest_cert_chain,
                log: mock_datadir.join("log.bin"),
                test_corpus: vec![],
            },
            roots: vec![mock_datadir.join("test-root-a.cert.pem")],
            resolve: keys::ResolveSetting::Local {
                priv_key: resolve_priv_key,
                cert_chain: resolve_cert_chain,
            },
            enforce,
        }
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

    // This is explicily testing the MeasurementConnectionPolicy::Permissive
    // behavior. This test should be removed when that policy is removed.
    #[tokio::test]
    async fn no_corpus() {
        let log = logger();
        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46457").unwrap();

        // Message to send over TLS
        const MSG: &str = "Hello Joe";

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let log2 = log.clone();
        let corpus = vec![
            // we don't use a corpus
        ];

        tokio::spawn(async move {
            let server_config =
                local_config(1, MeasurementConnectionPolicy::Permissive);
            let server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            let (mut stream, _) = server
                .accept(corpus.clone())
                .await
                .unwrap()
                .handshake()
                .await
                .unwrap();
            let mut buf = String::new();
            stream.read_to_string(&mut buf).await.unwrap();

            assert_eq!(buf.as_str(), MSG);

            // Inform the main task that the test is complete.
            let _ = done_tx.send(());
        });

        // Loop until we succesfully connect
        let mut stream = loop {
            let client_config =
                local_config(2, MeasurementConnectionPolicy::Permissive);

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
        let log = logger();
        let mock_datadir = mock_datadir();
        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46456").unwrap();
        let server_config =
            local_config(1, MeasurementConnectionPolicy::Enforced);

        // Message to send over TLS
        const MSG: &str = "Hello Joe";

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let log2 = log.clone();
        let corpus = vec![
            mock_datadir.join("corim-rot.cbor"),
            mock_datadir.join("corim-sp.cbor"),
        ];

        tokio::spawn(async move {
            let server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            let (mut stream, _) = server
                .accept(corpus.clone())
                .await
                .unwrap()
                .handshake()
                .await
                .unwrap();
            let mut buf = String::new();
            stream.read_to_string(&mut buf).await.unwrap();

            assert_eq!(buf.as_str(), MSG);

            // Inform the main task that the test is complete.
            let _ = done_tx.send(());
        });

        // Loop until we succesfully connect
        let mut stream = loop {
            let client_config =
                local_config(2, MeasurementConnectionPolicy::Enforced);

            let corpus = vec![
                mock_datadir.join("corim-rot.cbor"),
                mock_datadir.join("corim-sp.cbor"),
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
        let log = logger();
        let mock_datadir = mock_datadir();
        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46459").unwrap();

        let server_config =
            local_config(1, MeasurementConnectionPolicy::Enforced);

        // Message to send over TLS
        const MSG: &str = "Hello Joe";

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let log2 = log.clone();
        let corpus = vec![
            mock_datadir.join("corim-rot.cbor"),
            mock_datadir.join("corim-sp.cbor"),
        ];

        let handle = tokio::spawn(async move {
            let server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            // We never expect this to succeed
            let _ = match server
                .accept(corpus.clone())
                .await
                .unwrap()
                .handshake()
                .await
            {
                Ok(_) => panic!("This should not succed"),
                Err(_) => done_tx.send(()),
            };
        });

        let roots =
            config::load_roots(&[mock_datadir.join("test-root-a.cert.pem")])
                .unwrap();
        let client_config = config::new_tls_client_config(
            keys::ResolveSetting::Local {
                priv_key: mock_datadir.join("test-sprockets-auth-2.key.pem"),
                cert_chain: mock_datadir
                    .join("test-sprockets-auth-2.certlist.pem"),
            },
            roots,
            &log,
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

    // A version message whose body is shorter than the 4-byte version, sent
    // by a TLS-authenticated client, is rejected as Error::ProtocolVersion —
    // the server task must error, not panic on a short slice.
    #[tokio::test]
    async fn short_version_message_rejected() {
        let log = logger();
        let mock_datadir = mock_datadir();
        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46467").unwrap();

        let server_config =
            local_config(1, MeasurementConnectionPolicy::Enforced);
        let corpus = vec![
            mock_datadir.join("corim-rot.cbor"),
            mock_datadir.join("corim-sp.cbor"),
        ];

        let log2 = log.clone();
        let handle = tokio::spawn(async move {
            let server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            let result = server
                .accept(corpus.clone())
                .await
                .unwrap()
                .handshake()
                .await;
            match result {
                Err(Error::ProtocolVersion) => {}
                Err(other) => {
                    panic!("expected ProtocolVersion, got {other:?}")
                }
                Ok(_) => {
                    panic!("a malformed version message must not complete")
                }
            }
        });

        let roots =
            config::load_roots(&[mock_datadir.join("test-root-a.cert.pem")])
                .unwrap();
        let client_config = config::new_tls_client_config(
            keys::ResolveSetting::Local {
                priv_key: mock_datadir.join("test-sprockets-auth-2.key.pem"),
                cert_chain: mock_datadir
                    .join("test-sprockets-auth-2.certlist.pem"),
            },
            roots,
            &log,
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

        // A valid length prefix (2) followed by a 2-byte body: the server's
        // recv_msg succeeds, but the body is shorter than the 4-byte version
        // it must contain.
        stream.write_all(&2u32.to_le_bytes()).await.unwrap();
        stream.write_all(b"xy").await.unwrap();
        stream.shutdown().await.unwrap();

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn spawn_accept() {
        let log = logger();
        let mock_datadir = mock_datadir();

        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46466").unwrap();

        let server_config =
            local_config(1, MeasurementConnectionPolicy::Enforced);

        // Message to send over TLS
        const MSG: &str = "Hello Joe";

        let log2 = log.clone();
        let corpus = vec![
            mock_datadir.join("corim-rot.cbor"),
            mock_datadir.join("corim-sp.cbor"),
        ];

        // Accept connections from `max_connections` clients in different tasks
        //
        // For this test, the clients all share a set of keys, because
        // we only generate 2 sets of keys from the KDL.
        let max_connections = 3;
        let done_count = Arc::new(AtomicUsize::new(0));
        let dc2 = done_count.clone();
        tokio::spawn(async move {
            let server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            for _ in 0..max_connections {
                let acceptor = server.accept(corpus.clone()).await.unwrap();
                let done_count = dc2.clone();
                tokio::spawn(async move {
                    let (mut stream, _) = acceptor.handshake().await.unwrap();
                    let mut buf = String::new();
                    stream.read_to_string(&mut buf).await.unwrap();

                    assert_eq!(buf.as_str(), MSG);
                    done_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        });

        // Spawn `max_connections` tasks to concurrently connect
        for _ in 0..max_connections {
            let log = log.clone();
            let mock_datadir = mock_datadir.clone();
            tokio::spawn(async move {
                // Loop until we succesfully connect
                let mut stream = loop {
                    let client_config =
                        local_config(2, MeasurementConnectionPolicy::Enforced);

                    let corpus = vec![
                        mock_datadir.join("corim-rot.cbor"),
                        mock_datadir.join("corim-sp.cbor"),
                    ];

                    if let Ok(stream) = Client::connect(
                        client_config,
                        addr,
                        corpus,
                        log.clone(),
                    )
                    .await
                    {
                        break stream;
                    }
                    sleep(Duration::from_millis(1)).await;
                };

                stream.write_all(MSG.as_bytes()).await.unwrap();

                // Trigger an EOF so that `read_to_string` in the acceptor task
                // completes.
                stream.shutdown().await.unwrap();
            });
        }

        // Wait each spawned server task to receive and assert the message from
        // a single client.
        while done_count.load(std::sync::atomic::Ordering::Relaxed)
            != max_connections
        {
            sleep(Duration::from_millis(1)).await;
        }
    }

    // A message whose length prefix exceeds MAX_MSG_SIZE, sent by a
    // TLS-authenticated client, is rejected as Error::MessageTooLarge before
    // the message buffer is allocated — the peer-controlled prefix must not
    // be able to demand a 4 GiB allocation.
    #[tokio::test]
    async fn oversized_message_rejected() {
        let log = logger();
        let mock_datadir = mock_datadir();
        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46468").unwrap();

        let server_config =
            local_config(1, MeasurementConnectionPolicy::Enforced);
        let corpus = vec![
            mock_datadir.join("corim-rot.cbor"),
            mock_datadir.join("corim-sp.cbor"),
        ];

        let log2 = log.clone();
        let handle = tokio::spawn(async move {
            let server = Server::new(server_config, addr, log2.clone())
                .await
                .unwrap();

            let result = server
                .accept(corpus.clone())
                .await
                .unwrap()
                .handshake()
                .await;
            match result {
                Err(Error::MessageTooLarge { .. }) => {}
                Err(other) => {
                    panic!("expected MessageTooLarge, got {other:?}")
                }
                Ok(_) => {
                    panic!("an oversized message must not complete")
                }
            }
        });

        let roots =
            config::load_roots(&[mock_datadir.join("test-root-a.cert.pem")])
                .unwrap();
        let client_config = config::new_tls_client_config(
            keys::ResolveSetting::Local {
                priv_key: mock_datadir.join("test-sprockets-auth-2.key.pem"),
                cert_chain: mock_datadir
                    .join("test-sprockets-auth-2.certlist.pem"),
            },
            roots,
            &log,
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

        // A length prefix claiming a 4 GiB message; no body ever follows. The
        // server must reject on the prefix alone.
        stream.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        handle.await.unwrap();
    }
}
