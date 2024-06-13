// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based client

use camino::Utf8PathBuf;
use rustls::version::TLS13;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerifier},
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

use crate::{LocalCertResolver, RotCertVerifier, ROOT_CERT_FILENAME};

impl ResolvesClientCert for LocalCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
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
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> anyhow::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
    {
        // Create a PkiPath for our dice-verifier
        let mut pki_path: Vec<Certificate> = Vec::new();

        for der in iter::once(end_entity).chain(intermediates) {
            pki_path.push(Certificate::from_der(der).map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )
            })?)
        }

        self.verifier.verify(&pki_path).map_err(|e| {
            println!("err = {e}");
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )
        })?;

        Ok(rustls::client::danger::ServerCertVerified::assertion())
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
    config: ClientConfig,
}

impl Client {
    pub fn load_root_cert(keydir: &Utf8PathBuf) -> anyhow::Result<Certificate> {
        let mut root_cert_path = keydir.clone();
        root_cert_path.push(ROOT_CERT_FILENAME);
        let mut root_cert_pem = Vec::new();
        File::open(&root_cert_path)?.read_to_end(&mut root_cert_pem)?;
        let root = Certificate::from_pem(&root_cert_pem)?;
        Ok(root)
    }

    pub fn new(
        pki_keydir: Utf8PathBuf,
        node_keydir: Utf8PathBuf,
    ) -> anyhow::Result<Client> {
        let root = Client::load_root_cert(&pki_keydir)?;

        // Create a resolver that can return the cert chain for this client
        // so the server can authenticate it and a mechanism for signing
        // transcripts.
        let resolver = Arc::new(LocalCertResolver::new(pki_keydir, node_keydir))
            as Arc<dyn ResolvesClientCert>;

        // Create a verifier that is capable of verifying the cert chain of the
        // server and any signed transcripts.
        let verifier = Arc::new(RotCertVerifier::new(root)?)
            as Arc<dyn ServerCertVerifier>;

        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
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
        let root = Client::load_root_cert(&pki_keydir).unwrap();
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

    #[test]
    fn basic() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let mut node_keydir = pki_keydir.clone();
        node_keydir.push("sled1");
        let _client = Client::new(pki_keydir, node_keydir).unwrap();
    }
}
