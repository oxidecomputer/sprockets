// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS based connections

use anyhow::{bail, Context};
use camino::{Utf8Path, Utf8PathBuf};
use dice_verifier::PkiPathSignatureVerifier;
use ed25519_dalek::pkcs8::PrivateKeyInfo;
use rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;
use rustls::crypto::ring::kx_group::X25519;
use rustls::{
    client::danger::HandshakeSignatureValid,
    crypto::CryptoProvider,
    sign::{CertifiedKey, Signer, SigningKey},
    SignatureScheme,
};
use secrecy::{DebugSecret, ExposeSecret, Secret};
use sha2::{Digest, Sha512};
use slog::{error, info};
use std::io::prelude::*;
use std::io::IoSlice;
use std::iter;
use std::marker::Unpin;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{self, Poll};
use std::{fs::File, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsStream;
use x509_cert::{
    der::{self, Decode, DecodePem},
    Certificate,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod client;
mod server;

pub use client::{new_tls_client_config, Client, SprocketsClientConfig};
pub use server::{new_tls_server_config, Server, SprocketsServerConfig};

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

// These are on device keys and certs that differ for each node
//
// In production, we won't use files to load them but will retrieve them from
// the RoT over IPCC.
const SPROCKETS_AUTH_CERT_FILENAME: &str = "sprockets-auth.cert.pem";
const SPROCKETS_AUTH_KEY_FILENAME: &str = "sprockets-auth.key.pem";
const DEVICE_ID_CERT_FILENAME: &str = "deviceid.cert.pem";
const PLATFORM_ID_CERT_FILENAME: &str = "platformid.cert.pem";

/// These certs are shared across different nodes and used for PKI cert chain
/// validation.
const OKS_SIGNER_CERT_FILENAME: &str = "oks-signer.cert.pem";
pub(crate) const ROOT_CERT_FILENAME: &str = "root.cert.pem";

// A context for TLS signing
//
// Please don't confuse my deputies
const TLS_SIGNING_CONTEXT: &[u8] = b"sprockets-tls-signing";

/// Load a root certificate from a given path
pub fn load_root_cert(keydir: &Utf8PathBuf) -> Result<Certificate, Error> {
    let mut root_cert_path = keydir.clone();
    root_cert_path.push(ROOT_CERT_FILENAME);
    let mut root_cert_pem = Vec::new();
    File::open(&root_cert_path)
        .with_context(|| format!("failed to open {}", &root_cert_path))?
        .read_to_end(&mut root_cert_pem)
        .with_context(|| format!("failed to read {}", &root_cert_path))?;
    let root = Certificate::from_pem(&root_cert_pem).with_context(|| {
        format!("failed to convert pem read from {}", &root_cert_path)
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

/// A resolver for certs that gets them from the local filesystem
///
/// This is primarily used for testing. In production we'll retrieve these over
/// IPCC from the RoT
///
/// We use hardcoded filenames for simplicity, since we have to build specific
/// cert chains
#[derive(Debug)]
pub struct LocalCertResolver {
    /// Directory containing public key certs for the root and intermediate
    /// online signing key.
    pki_keydir: Utf8PathBuf,

    /// Directory containing "on-device" certs and private keys
    node_keydir: Utf8PathBuf,

    log: slog::Logger,
}

impl LocalCertResolver {
    pub fn new(
        pki_keydir: Utf8PathBuf,
        node_keydir: Utf8PathBuf,
        log: slog::Logger,
    ) -> LocalCertResolver {
        LocalCertResolver {
            pki_keydir,
            node_keydir,
            log,
        }
    }
}

impl LocalCertResolver {
    // Load a PEM cert file and decode it to DER along with its type label
    fn load_and_decode(
        &self,
        path: &Utf8Path,
        expected_label: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let mut pem = Vec::new();
        File::open(path)
            .with_context(|| format!("failed to open {path}"))?
            .read_to_end(&mut pem)
            .with_context(|| format!("failed to read {path}"))?;
        let (type_label, der) =
            pem_rfc7468::decode_vec(&pem).with_context(|| {
                format!("failed to decode pem to der for {path}")
            })?;
        if type_label != expected_label {
            bail!(format!(
                concat!(
                    "File read from {} had improper label. ",
                    "Expected: {}, Actual: {}"
                ),
                path, expected_label, type_label
            ));
        }

        Ok(der)
    }
    fn load_certified_key(&self) -> anyhow::Result<Arc<CertifiedKey>> {
        // Read the private key as a pemfile and convert it to DER that can be
        // used by rustls
        let mut path = self.node_keydir.clone();
        path.push(SPROCKETS_AUTH_KEY_FILENAME);
        let privkey_der = self.load_and_decode(&path, "PRIVATE KEY")?;
        info!(
            self.log,
            "Successfully loaded sprockets auth key from {path}"
        );

        // Create a `SigningKey` using the private key
        let signing_key = Arc::new(LocalEd25519SigningKey {
            privkey_der: Secret::new(PrivkeyDer(privkey_der)),
        }) as Arc<dyn SigningKey>;

        // Load the full cert chain as pemfiles and convert them to a chain
        // of DER buffers that can be used by rutsls.
        //
        // We don't include the root cert, as that is known to the verifier
        // already.

        // OKS signing cert
        //
        // This is an intermediate signing cert from the Online Signing Service
        // It's used to sign the on device platformid certs.
        let mut path = self.pki_keydir.clone();
        path.push(OKS_SIGNER_CERT_FILENAME);
        let oks_signer_der = self.load_and_decode(&path, "CERTIFICATE")?;
        info!(self.log, "Successfully loaded OKS signing cert from {path}");

        // A unique id set at manufacturing time for each device
        //
        // This is an intermediate embedded signing cert used to sign deviceid
        // certs.
        let mut path = self.node_keydir.clone();
        path.push(PLATFORM_ID_CERT_FILENAME);
        let platformid_der = self.load_and_decode(&path, "CERTIFICATE")?;
        info!(self.log, "Successfully loaded platform id cert from {path}");

        // Device ID Cert
        //
        // This is the cert for an embedded CA used to sign measurement certs as
        // well as TLS authentication certs used in sprockets.
        let mut path = self.node_keydir.clone();
        path.push(DEVICE_ID_CERT_FILENAME);
        let deviceid_der = self.load_and_decode(&path, "CERTIFICATE")?;
        info!(self.log, "Successfully loaded device id cert from {path}");

        // The sprockets TLS auth cert
        //
        // This is the end-entity cert that is used to authenticate the TLS session
        let mut path = self.node_keydir.clone();
        path.push(SPROCKETS_AUTH_CERT_FILENAME);
        let sprockets_auth_der = self.load_and_decode(&path, "CERTIFICATE")?;
        info!(
            self.log,
            "Successfully loaded sprockets auth (end entity) cert from {path}"
        );

        Ok(Arc::new(CertifiedKey::new(
            // The end-entity cert must come first, so put the chain in reverse order.
            vec![
                sprockets_auth_der.into(),
                deviceid_der.into(),
                platformid_der.into(),
                oks_signer_der.into(),
            ],
            signing_key,
        )))
    }
}

/// A mechanism for signing using an in memory Ed25519 private key
#[derive(Debug)]
pub(crate) struct LocalEd25519Signer {
    // Not necessary to wrap in a `Secret`. It already prevents debug printing
    // of the secret.
    key: ed25519_dalek::SigningKey,
}

impl Signer for LocalEd25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // We must hash with SHA-512 and then sign the digest
        let mut prehashed = Sha512::new();
        prehashed.update(message);
        let sig = self
            .key
            .sign_prehashed(prehashed, Some(TLS_SIGNING_CONTEXT))
            .map_err(|e| {
                rustls::Error::General(format!("Failed to sign message: {e}"))
            })?;

        Ok(sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// A DER encoded private key
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrivkeyDer(Vec<u8>);

impl DebugSecret for PrivkeyDer {}

/// An implementation of a an Ed25519 private signing key that lives in memory
///
/// In production we'll send signing requests to the RoT via IPCC and sprot.
#[derive(Debug)]
pub(crate) struct LocalEd25519SigningKey {
    privkey_der: Secret<PrivkeyDer>,
}

impl SigningKey for LocalEd25519SigningKey {
    fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if !offered.iter().any(|&s| s == SignatureScheme::ED25519) {
            return None;
        }

        let privkey_info = PrivateKeyInfo::try_from(
            self.privkey_der.expose_secret().0.as_slice(),
        )
        .ok()?;

        let signing_key =
            ed25519_dalek::SigningKey::try_from(privkey_info).ok()?;

        Some(Box::new(LocalEd25519Signer { key: signing_key })
            as Box<dyn Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

/// A verifier for certs generated on the RoT
#[derive(Debug)]
struct RotCertVerifier {
    verifier: PkiPathSignatureVerifier,
    log: slog::Logger,
}

impl RotCertVerifier {
    pub fn new(root: Certificate, log: slog::Logger) -> Result<Self, Error> {
        let verifier = PkiPathSignatureVerifier::new(Some(root))?;
        Ok(RotCertVerifier { verifier, log })
    }

    /// Create a `PkiPath` suitable for `dice-verifier`
    fn pki_path(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
    ) -> Result<Vec<Certificate>, rustls::Error> {
        let mut pki_path = Vec::new();
        for der in iter::once(end_entity).chain(intermediates) {
            pki_path.push(Certificate::from_der(der).map_err(|e| {
                error!(self.log, "failed to create a pki_path: {e}");
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )
            })?)
        }
        Ok(pki_path)
    }

    /// Verify the certificate chain via `dice-verifier`
    pub fn verify_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
    ) -> Result<(), rustls::Error> {
        let pki_path = self.pki_path(end_entity, intermediates)?;
        self.verifier.verify(&pki_path).map_err(|e| {
            error!(self.log, "Failed to verify cert: {e}");
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )
        })?;

        info!(self.log, "Certificate chain verified successfully");

        Ok(())
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        sig: &[u8],
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        // Get the public key
        let cert = Certificate::from_der(cert).map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )
        })?;

        let pubkey: [u8; 32] = match cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
        {
            Some(pubkey) => pubkey.try_into().map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )
            })?,
            None => {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                ))
            }
        };
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
            .map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )
            })?;

        // We must hash with SHA-512 and then verify the digest
        let mut prehashed = Sha512::new();
        prehashed.update(message);

        let signature =
            ed25519_dalek::Signature::from_slice(sig).map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )
            })?;
        verifying_key
            .verify_prehashed(prehashed, Some(TLS_SIGNING_CONTEXT), &signature)
            .map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature,
                )
            })?;

        info!(self.log, "Signature verified successfully");

        Ok(HandshakeSignatureValid::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::ResolvesClientCert;
    use rustls::server::ResolvesServerCert;
    use slog::Drain;
    use std::net::SocketAddrV6;
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub fn logger() -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = std::sync::Mutex::new(drain).fuse();
        slog::Logger::root(drain, slog::o!("component" => "sprockets"))
    }

    #[tokio::test]
    async fn basic() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let mut client_node_keydir = pki_keydir.clone();
        client_node_keydir.push("sled1");
        let mut server_node_keydir = pki_keydir.clone();
        server_node_keydir.push("sled2");
        let log = logger();

        // Create a resolver that can return the cert chain for this client so
        // the server can authenticate it, along with a mechanism for signing
        // transcripts.
        let client_resolver = Arc::new(LocalCertResolver::new(
            pki_keydir.clone(),
            client_node_keydir,
            log.clone(),
        )) as Arc<dyn ResolvesClientCert>;

        // Create a resolver that can return the cert chain for this server so
        // the client can authenticate it, along with a mechanism for signing
        // transcripts.
        let server_resolver = Arc::new(LocalCertResolver::new(
            pki_keydir.clone(),
            server_node_keydir,
            log.clone(),
        )) as Arc<dyn ResolvesServerCert>;

        let addr: SocketAddrV6 = SocketAddrV6::from_str("[::1]:46456").unwrap();

        let client_config = SprocketsClientConfig {
            pki_keydir: pki_keydir.clone(),
            resolver: client_resolver,
            addr: addr.clone(),
        };

        let server_config = SprocketsServerConfig {
            pki_keydir: pki_keydir.clone(),
            resolver: server_resolver,
            listen_addr: addr,
        };

        // Message to send over TLS
        const MSG: &str = "Hello Joe";

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let log2 = log.clone();

        tokio::spawn(async move {
            let mut server =
                Server::listen(server_config, log.clone()).await.unwrap();
            let mut stream = server.accept().await.unwrap();

            let mut buf = String::new();
            stream.read_to_string(&mut buf).await.unwrap();

            assert_eq!(buf.as_str(), MSG);

            // Inform the main task that the test is complete.
            let _ = done_tx.send(());
        });

        // Loop until we succesfully connect
        let mut stream = loop {
            if let Ok(stream) =
                Client::connect(client_config.clone(), log2.clone()).await
            {
                break stream;
            }
        };
        stream.write_all(MSG.as_bytes()).await.unwrap();
        drop(stream);

        // Wait for the other side of the connection to receive and assert the
        // message
        let _ = done_rx.await;
    }
}
