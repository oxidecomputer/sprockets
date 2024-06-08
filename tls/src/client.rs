// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based client

use anyhow::Result;
use camino::Utf8PathBuf;
use dice_verifier::PkiPathSignatureVerifier;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerifier},
        ResolvesClientCert,
    },
    sign::CertifiedKey,
    ClientConfig, SignatureScheme,
};
use std::sync::Arc;
use x509_cert::{der::Encode, Certificate, PkiPath};

/// A resolver for certs that gets them from the local filesystem
///
/// In production we'll retrieve these over IPCC from the RoT
#[derive(Debug)]
pub struct LocalCertResolver {
    path: Utf8PathBuf,
}

impl LocalCertResolver {
    pub fn new(path: Utf8PathBuf) -> LocalCertResolver {
        LocalCertResolver { path }
    }
}

impl ResolvesClientCert for LocalCertResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        todo!()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// An implementation of a an Ed25519 private signing key that lives in memory
///
/// In production we'll send signing requests to the RoT via IPCC and sprot.
pub struct LocalEd25519SigningKey {}

/// A verifier for certs generated on the RoT
#[derive(Debug)]
struct RotServerCertVerifier {
    verifier: PkiPathSignatureVerifier,
}

impl RotServerCertVerifier {
    pub fn new(root: Certificate) -> Result<Self> {
        let verifier = PkiPathSignatureVerifier::new(Some(root))?;
        Ok(RotServerCertVerifier { verifier })
    }
}

impl ServerCertVerifier for RotServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        todo!()
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
        // TODO: Actually verify the signature :)
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

pub struct Client {}

impl Client {
    pub fn new(
        root: Certificate,
        resolver: Arc<dyn ResolvesClientCert>,
    ) -> anyhow::Result<Client> {
        let verifier = Arc::new(RotServerCertVerifier::new(root)?)
            as Arc<dyn ServerCertVerifier>;
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(resolver);

        todo!()
    }
}
