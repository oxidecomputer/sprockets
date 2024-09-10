// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based client

use rustls::pki_types::ServerName;
use std::net::SocketAddrV6;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::keys::ResolveSetting;
use crate::keys::{CertResolver, RotCertVerifier, SprocketsConfig};
use crate::{crypto_provider, load_root_cert};
use crate::{Error, Stream};
use camino::Utf8PathBuf;
use rustls::{
    client::{
        danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        },
        ResolvesClientCert,
    },
    sign::CertifiedKey,
    version::TLS13,
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
                error!(self.log, "failed to load certified key: {e}");
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
    pub async fn new(
        config: SprocketsConfig,
        addr: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<Stream<TcpStream>, Error> {
        let c = match config.resolve {
            ResolveSetting::Local {
                priv_key,
                cert_chain,
            } => Client::new_tls_local_client_config(
                priv_key,
                cert_chain,
                config.roots,
                log.clone(),
            )?,
            ResolveSetting::Ipcc => {
                Client::new_tls_ipcc_client_config(config.roots, log.clone())?
            }
        };
        Client::connect(c, addr, log).await
    }

    fn new_tls_local_client_config(
        priv_key: Utf8PathBuf,
        cert_chain: Utf8PathBuf,
        roots: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<ClientConfig, Error> {
        let roots = roots
            .into_iter()
            .map(|x| load_root_cert(&x))
            .collect::<Result<Vec<Certificate>, _>>()?;

        let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
            as Arc<dyn ServerCertVerifier>;

        let client_resolver = Arc::new(CertResolver::new(
            log.clone(),
            ResolveSetting::Local {
                priv_key,
                cert_chain,
            },
        )) as Arc<dyn ResolvesClientCert>;

        let config =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
                .with_protocol_versions(&[&TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(client_resolver);

        Ok(config)
    }

    fn new_tls_ipcc_client_config(
        roots: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<ClientConfig, Error> {
        let roots = roots
            .into_iter()
            .map(|x| load_root_cert(&x))
            .collect::<Result<Vec<Certificate>, _>>()?;

        let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
            as Arc<dyn ServerCertVerifier>;

        let client_resolver =
            Arc::new(CertResolver::new(log.clone(), ResolveSetting::Ipcc))
                as Arc<dyn ResolvesClientCert>;

        let config =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
                .with_protocol_versions(&[&TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(client_resolver);

        Ok(config)
    }

    /// Connect to a remote peer
    async fn connect(
        tls_config: ClientConfig,
        addr: SocketAddrV6,
        _log: slog::Logger,
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
                println!("{:?}", e);
                return Err(e.into());
            }
        };

        let stream = connector.connect(dnsname, stream).await?;
        // TODO: Measurement Attestations
        Ok(Stream::new(stream.into()))
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
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let mut node_keydir = pki_keydir.clone();
        node_keydir.push("sled1");
        let root = load_root_cert(&pki_keydir.join("root.cert.pem")).unwrap();
        let verifier = RotCertVerifier::new(vec![root], logger()).unwrap();
        let resolver = CertResolver::new(
            logger(),
            ResolveSetting::Local {
                priv_key: node_keydir.join("sprockets-auth.key.pem"),
                cert_chain: pki_keydir.join("chain1.pem"),
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
