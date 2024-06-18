// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based server

use crate::load_root_cert;
use camino::Utf8PathBuf;
use rustls::crypto::ring::kx_group::X25519;
use rustls::version::TLS13;
use rustls::{
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ResolvesServerCert,
    },
    sign::CertifiedKey,
    CipherSuite, ServerConfig, SignatureScheme,
};
use std::io::prelude::*;
use std::iter;
use std::{fs::File, sync::Arc};
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

use crate::{LocalCertResolver, RotCertVerifier, ROOT_CERT_FILENAME};

impl ResolvesServerCert for LocalCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // We only support Ed25519 and we control both sides of the connection
        if !client_hello
            .signature_schemes()
            .iter()
            .all(|&s| s == SignatureScheme::ED25519)
        {
            return None;
        }

        // We only support ChaCha20Poly1305 with SHA-256 and we control both sides of the connection
        if !client_hello
            .cipher_suites()
            .iter()
            .any(|&s| s == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        {
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
}

impl ClientCertVerifier for RotCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // TODO: Do we actually need to return anything here?
        &[]
    }

    // We explicitly ignore the timestamp since we may be operating before the
    // rack has proper time.
    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_cert(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        self.verify_signature(message, cert, dss.signature())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
pub struct Server {
    pub config: ServerConfig,
}

impl Server {
    pub fn new(
        root_keydir: &Utf8PathBuf,
        resolver: Arc<dyn ResolvesServerCert>,
    ) -> anyhow::Result<Server> {
        let root = load_root_cert(&root_keydir)?;

        // Create a verifier that is capable of verifying the cert chain of the
        // server and any signed transcripts.
        let verifier = Arc::new(RotCertVerifier::new(root)?)
            as Arc<dyn ClientCertVerifier>;

        // Use ring as a crypto provider and only allow X25519 for key exchange
        let mut crypto_provider = rustls::crypto::ring::default_provider();
        crypto_provider.kx_groups = vec![X25519];

        let config =
            ServerConfig::builder_with_provider(Arc::new(crypto_provider))
                .with_protocol_versions(&[&TLS13])?
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(resolver);

        Ok(Server { config })
    }
}
