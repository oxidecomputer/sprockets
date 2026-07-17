// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based client

use rustls::pki_types::ServerName;
use std::net::SocketAddrV6;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::attest;
use crate::config::{load_roots, new_tls_client_config};
use crate::keys::AttestConfig;
use crate::keys::{
    CertResolver, MeasurementConnectionPolicy, RotCertVerifier, SprocketsConfig,
};
use crate::{platform_id_from_tls_certs, Error, Stream};
use camino::Utf8PathBuf;
use rustls::{
    client::{
        danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        },
        ResolvesClientCert,
    },
    sign::CertifiedKey,
    ClientConfig, SignatureScheme,
};
use slog::{error, info};
use x509_cert::Certificate;

impl ResolvesClientCert for CertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // TODO: Do we need to use `_root_hint_subjects`?

        // We only support Ed25519
        if !sigschemes.iter().all(|&s| s == SignatureScheme::ED25519) {
            error!(
                self.log,
                "Invalid signature schemes requested: {:?}", sigschemes
            );
            return None;
        }
        match self.load_certified_key() {
            Ok(key) => {
                info!(self.log, "Loaded keys and certs");
                Some(key)
            }
            Err(e) => {
                error!(self.log, "failed to load certified key"; e);
                None
            }
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ServerCertVerifier for RotCertVerifier {
    // We explicitly ignore the timestamp since we may be operating before the
    // rack has proper time.
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // TODO: Validate `server_name` and `ocsp_response`?
        self.verify_cert(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        // We don't allow the use of TLS 1.2
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss.signature())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// The top-level sprockets client
pub struct Client {}

impl Client {
    /// Connect to a listening server at the provided `addr`ess according to
    /// the `config`uration provided. Before the stream is returned to the
    /// client
    /// - the TLS handshake will be completed and mutually authenticated
    ///   against the roots from the `config`
    /// - the attestation process is carried out with peer credentials
    ///   authenticated by the roots from the `config` and peer measurements
    ///   appraised using the provided `corpus`
    ///
    /// NOTE: This function is not cancel safe and should be run in a dedicated
    /// task.
    pub async fn connect(
        config: SprocketsConfig,
        addr: SocketAddrV6,
        corpus: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<Stream<TcpStream>, Error> {
        let roots = load_roots(&config.roots)?;
        let tls_config =
            new_tls_client_config(config.resolve, roots.clone(), &log)?;

        Client::connect_with_config(
            tls_config,
            config.attest,
            roots,
            corpus,
            addr,
            log,
            config.enforce,
        )
        .await
    }

    /// Connect to a remote peer
    async fn connect_with_config(
        tls_config: ClientConfig,
        attest_config: AttestConfig,
        roots: Vec<Certificate>,
        corpus: Vec<Utf8PathBuf>,
        addr: SocketAddrV6,
        log: slog::Logger,
        enforce: MeasurementConnectionPolicy,
    ) -> Result<Stream<TcpStream>, Error> {
        // Nodes on the bootstrap network don't have DNS names. We don't
        // actually ever know who we are connecting to on the bootstrap
        // network, as we just learned of potential peers by IPv6 address from
        // DDMD. We learn the identities of peers from the subject name in the
        // certificate. Because of this we always pass a dummy DNS name, and
        // ignore it when validating the connection on the server side.
        let dnsname = ServerName::try_from("unknown.com").unwrap();

        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                println!("{e:?}");
                return Err(e.into());
            }
        };

        let mut stream = connector.connect(dnsname, stream).await?;

        // get server cert chain from connection
        let (_, conn) = stream.get_ref();
        let tq_platform_id =
            platform_id_from_tls_certs(conn.peer_certificates())?;

        let (server_platform_id, result) = attest::client_exchange(
            &mut stream,
            tq_platform_id,
            &attest_config,
            &roots,
            corpus,
            enforce,
            &log,
        )
        .await?;

        Ok(Stream::new(stream.into(), server_platform_id, result))
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::CertResolver;
    use crate::keys::ResolveSetting;
    use crate::keys::RotCertVerifier;
    use crate::load_root_cert;
    use crate::tests::logger;
    use camino::Utf8PathBuf;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::ServerName;
    use rustls::SignatureScheme;

    #[test]
    // Ensure the test certs can be loaded and verified
    fn test_client_verifier() {
        let pki_keydir = Utf8PathBuf::from(env!("OUT_DIR"));
        let root =
            load_root_cert(&pki_keydir.join("test-root-a.cert.pem")).unwrap();
        let verifier = RotCertVerifier::new(vec![root], logger()).unwrap();
        let resolver = CertResolver::new(
            logger(),
            ResolveSetting::Local {
                priv_key: pki_keydir.join("test-sprockets-auth-1.key.pem"),
                cert_chain: pki_keydir
                    .join("test-sprockets-auth-1.certlist.pem"),
            },
        );
        let certified_key = resolver.load_certified_key().unwrap();
        let end_entity = certified_key.end_entity_cert().unwrap();
        let intermediates = &certified_key.cert[1..];
        let server_name: ServerName = "example.com".try_into().unwrap();

        // Verify that the cert chain is valid
        verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();

        // Now create a signature over an arbitrary message using our
        // LocalEd25519Signer and then verify it.
        let message = b"sign-me-then-verify-me";
        let signer = certified_key
            .key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap();
        let signature = signer.sign(message).unwrap();
        let res = verifier.verify_signature(message, end_entity, &signature);
        assert!(res.is_ok());
    }
}
