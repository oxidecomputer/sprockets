// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based client

use anyhow::Result;
use camino::Utf8PathBuf;
use dice_verifier::PkiPathSignatureVerifier;
use pem_rfc7468;
use rustls::version::TLS13;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerifier},
        ResolvesClientCert,
    },
    pki_types::CertificateDer,
    sign::{CertifiedKey, SigningKey},
    ClientConfig, SignatureScheme,
};
use std::io::prelude::*;
use std::iter;
use std::{fs::File, sync::Arc};
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate, PkiPath,
};

/// A resolver for certs that gets them from the local filesystem
///
/// In production we'll retrieve these over IPCC from the RoT
///
/// We use hardcoded filenames for simplicity, since we have to build specific
/// cert chains
#[derive(Debug)]
pub struct LocalCertResolver {
    keydir: Utf8PathBuf,
}

impl LocalCertResolver {
    pub fn new(keydir: Utf8PathBuf) -> LocalCertResolver {
        LocalCertResolver { keydir }
    }
}

impl LocalCertResolver {
    fn load_certified_key(&self) -> Result<Arc<CertifiedKey>> {
        let mut privkey_pem = Vec::new();

        // Read the private key as a pemfile and convert it to DER that can be
        // used by rustls
        let mut privkey_path = self.keydir.clone();
        privkey_path.push("test-sprockets-auth-1.key.pem");
        File::open(&privkey_path)?.read_to_end(&mut privkey_pem)?;

        let (type_label, privkey_der) = pem_rfc7468::decode_vec(&privkey_pem)?;
        assert_eq!(type_label, "PRIVATE KEY");

        // Create a `SigningKey` using the private key
        let signing_key = Arc::new(LocalEd25519SigningKey { privkey_der })
            as Arc<dyn SigningKey>;

        // Load the full cert chain as pemfiles and convert them to a chain
        // of DER buffers that can be used by rutsls.
        //
        // We don't include the root cert, as that is known to the verifier
        // already.

        // OKS signing cert
        //
        // This is an intermediate signing cert from the Online Signing Service
        // It's used to sign the on device platformid certs.
        let mut oks_signer_pem = Vec::new();
        let mut oks_signer_path = self.keydir.clone();
        oks_signer_path.push("test-signer-a1.cert.pem");
        File::open(&oks_signer_path)?.read_to_end(&mut oks_signer_pem)?;
        let (type_label, oks_signer_der) =
            pem_rfc7468::decode_vec(&oks_signer_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // A unique id set at manufacturing time for each device
        //
        // This is an intermediate embedded signing cert used to sign deviceid
        // certs.
        let mut platformid_pem = Vec::new();
        let mut platformid_path = self.keydir.clone();
        platformid_path.push("test-platformid-1.cert.pem");
        File::open(&platformid_path)?.read_to_end(&mut platformid_pem)?;
        let (type_label, platformid_der) =
            pem_rfc7468::decode_vec(&platformid_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // Device ID Cert
        //
        // This is the cert for an embedded CA used to sign measurement certs as
        // well as TLS authentication certs used in sprockets.
        let mut deviceid_pem = Vec::new();
        let mut deviceid_path = self.keydir.clone();
        deviceid_path.push("test-deviceid-1.cert.pem");
        File::open(&deviceid_path)?.read_to_end(&mut deviceid_pem)?;
        let (type_label, deviceid_der) =
            pem_rfc7468::decode_vec(&deviceid_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // The sprockets TLS auth cert
        //
        // This is the end-entity cert that is used to authenticate the TLS session
        let mut sprockets_auth_pem = Vec::new();
        let mut sprockets_auth_path = self.keydir.clone();
        sprockets_auth_path.push("test-sprockets-auth-1.cert.pem");
        File::open(&sprockets_auth_path)?
            .read_to_end(&mut sprockets_auth_pem)?;
        let (type_label, sprockets_auth_der) =
            pem_rfc7468::decode_vec(&sprockets_auth_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

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

/// An implementation of a an Ed25519 private signing key that lives in memory
///
/// In production we'll send signing requests to the RoT via IPCC and sprot.
#[derive(Debug)]
pub struct LocalEd25519SigningKey {
    privkey_der: Vec<u8>,
}

impl SigningKey for LocalEd25519SigningKey {
    fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if !offered.iter().any(|&s| s == SignatureScheme::ED25519) {
            return None;
        }

        todo!()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

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
        // Create a PkiPath for our dice-verifier
        let mut pki_path: Vec<Certificate> = Vec::new();

        for der in iter::once(end_entity).chain(intermediates) {
            pki_path.push(Certificate::from_der(der).map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )
            })?)
        }

        println!("ayo i'm here");

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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TODO: Actually verify the signature :)
        Ok(HandshakeSignatureValid::assertion())
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
        root_cert_path.push("test-root-a.cert.pem");
        let mut root_cert_pem = Vec::new();
        File::open(&root_cert_path)?.read_to_end(&mut root_cert_pem)?;
        let root = Certificate::from_pem(&root_cert_pem)?;
        Ok(root)
    }

    pub fn new(keydir: Utf8PathBuf) -> anyhow::Result<Client> {
        let root = Client::load_root_cert(&keydir)?;

        // Create a resolver that can return the cert chain for this client
        // so the server can authenticate it and a mechanism for signing
        // transcripts.
        let resolver = Arc::new(LocalCertResolver::new(keydir))
            as Arc<dyn ResolvesClientCert>;

        // Create a verifier that is capable of verifying the cert chain of the
        // server and any signed transcripts.
        let verifier = Arc::new(RotServerCertVerifier::new(root)?)
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
        let mut keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keydir.push("test-keys");
        let root = Client::load_root_cert(&keydir).unwrap();
        let verifier = RotServerCertVerifier::new(root).unwrap();
        let resolver = LocalCertResolver::new(keydir);
        let certified_key = resolver.load_certified_key().unwrap();
        let end_entity = certified_key.end_entity_cert().unwrap();
        let intermediates = &certified_key.cert[1..];
        let server_name: ServerName = "example.com".try_into().unwrap();
        verifier
            .verify_server_cert(
                &end_entity,
                intermediates,
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();
    }

    #[test]
    fn basic() {
        let mut keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keydir.push("test-keys");
        println!("keydir = {}", keydir);
        let _client = Client::new(keydir).unwrap();
    }
}
