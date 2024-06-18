// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based client

use camino::Utf8PathBuf;
use rustls::crypto::ring::kx_group::X25519;
use rustls::version::TLS13;
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
use std::io::prelude::*;
use std::iter;
use std::{fs::File, sync::Arc};
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

use crate::{
    load_root_cert, LocalCertResolver, RotCertVerifier, ROOT_CERT_FILENAME,
};

impl ResolvesClientCert for LocalCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // TODO: Do we need to use `_root_hint_subjects`?

        // We only support Ed25519
        if !sigschemes.iter().any(|&s| s == SignatureScheme::ED25519) {
            return None;
        }
        match self.load_certified_key() {
            Ok(key) => Some(key),
            Err(e) => {
                // TODO: Logging
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
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
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
    ) -> anyhow::Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss.signature())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
pub struct Client {
    pub config: ClientConfig,
}

impl Client {
    pub fn new(
        root_keydir: &Utf8PathBuf,
        resolver: Arc<dyn ResolvesClientCert>,
    ) -> anyhow::Result<Client> {
        let root = load_root_cert(&root_keydir)?;

        // Create a verifier that is capable of verifying the cert chain of the
        // server and any signed transcripts.
        let verifier = Arc::new(RotCertVerifier::new(root)?)
            as Arc<dyn ServerCertVerifier>;

        // Use ring as a crypto provider and only allow X25519 for key exchange
        let mut crypto_provider = rustls::crypto::ring::default_provider();
        crypto_provider.kx_groups = vec![X25519];

        let config =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider))
                .with_protocol_versions(&[&TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(resolver);

        Ok(Client { config })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    #[test]
    // Ensure the test certs can be loaded and verified
    fn test_client_verifier() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let mut node_keydir = pki_keydir.clone();
        node_keydir.push("sled1");
        let root = load_root_cert(&pki_keydir).unwrap();
        let verifier = RotCertVerifier::new(root).unwrap();
        let resolver = LocalCertResolver::new(pki_keydir, node_keydir);
        let certified_key = resolver.load_certified_key().unwrap();
        let end_entity = certified_key.end_entity_cert().unwrap();
        let intermediates = &certified_key.cert[1..];
        let server_name: ServerName = "example.com".try_into().unwrap();

        // Verify that the cert chain is valid
        verifier
            .verify_server_cert(
                &end_entity,
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
