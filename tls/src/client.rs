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
use std::{fs::File, sync::Arc};
use x509_cert::{
    der::{DecodePem, Encode},
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
        privkey_path.push("trust-quorum-dhe.key.pem");
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

        // Persistent Identity Cert
        //
        // This is the cert for an intermediate on-device CA provisioned at
        // manufacturing time and used to sign `DeviceId` certs.
        let mut persistentid_pem = Vec::new();
        let mut persistentid_path = self.keydir.clone();
        persistentid_path.push("persistentid.cert.pem");
        File::open(&persistentid_path)?.read_to_end(&mut persistentid_pem)?;
        let (type_label, persistentid_der) =
            pem_rfc7468::decode_vec(&persistentid_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // Device ID Cert
        //
        // This is the cert for an embedded CA used to sign measurement certs as
        // well as DHE authentication certs used in sprockets.
        let mut deviceid_pem = Vec::new();
        let mut deviceid_path = self.keydir.clone();
        deviceid_path.push("deviceid.cert.pem");
        File::open(&deviceid_path)?.read_to_end(&mut deviceid_pem)?;
        let (type_label, deviceid_der) =
            pem_rfc7468::decode_vec(&deviceid_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // Trust quorum DHE cert
        //
        // This is the end-entity cert that is used to authenticate the TLS session
        let mut trust_quorum_dhe_pem = Vec::new();
        let mut trust_quorum_dhe_path = self.keydir.clone();
        trust_quorum_dhe_path.push("trust-quorum-dhe.cert.pem");
        File::open(&trust_quorum_dhe_path)?
            .read_to_end(&mut trust_quorum_dhe_pem)?;
        let (type_label, trust_quorum_dhe_der) =
            pem_rfc7468::decode_vec(&trust_quorum_dhe_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        Ok(Arc::new(CertifiedKey::new(
            // The end-entity cert must come first, so put the chain in reverse order.
            vec![
                trust_quorum_dhe_der.into(),
                deviceid_der.into(),
                persistentid_der.into(),
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

#[derive(Debug)]
pub struct Client {
    config: ClientConfig,
}

impl Client {
    pub fn new(keydir: Utf8PathBuf) -> anyhow::Result<Client> {
        // Read the root certificate
        let mut root_cert_path = keydir.clone();
        root_cert_path.push("root.cert.pem");
        let mut root_cert_pem = Vec::new();
        File::open(&root_cert_path)?.read_to_end(&mut root_cert_pem)?;
        let root = Certificate::from_pem(&root_cert_pem)?;

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

    #[test]
    fn basic() {
        let mut keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keydir.push("test-keys/a");
        println!("keydir = {}", keydir);
        let _client = Client::new(keydir).unwrap();
    }
}
