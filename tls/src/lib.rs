// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS based connections

use camino::Utf8PathBuf;
use dice_verifier::PkiPathSignatureVerifier;
use ed25519_dalek::pkcs8::PrivateKeyInfo;
use rustls::{
    client::danger::HandshakeSignatureValid,
    sign::{CertifiedKey, Signer, SigningKey},
    SignatureScheme,
};
use sha2::{Digest, Sha512};
use std::io::prelude::*;
use std::iter;
use std::{fs::File, sync::Arc};
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

mod client;
mod server;

// These are on device keys and certs that differ for each node
//
// In production, we won't use files to load them but will retrieve them from
// the RoT over IPCC.
const SPROCKETS_AUTH_CERT_FILENAME: &'static str = "sprockets-auth.cert.pem";
const SPROCKETS_AUTH_KEY_FILENAME: &'static str = "sprockets-auth.key.pem";
const DEVICE_ID_CERT_FILENAME: &'static str = "deviceid.cert.pem";
const DEVICE_ID_KEY_FILENAME: &'static str = "deviceid.key.pem";
const PLATFORM_ID_CERT_FILENAME: &'static str = "platformid.cert.pem";
const PLATFORM_ID_KEY_FILENAME: &'static str = "platformid.key.pem";

/// These certs are shared across different nodes and used for PKI cert chain
/// validation.
const OKS_SIGNER_CERT_FILENAME: &'static str = "oks-signer.cert.pem";
pub(crate) const ROOT_CERT_FILENAME: &'static str = "root.cert.pem";

// A context for TLS signing
//
// Please don't confuse my deputies
const TLS_SIGNING_CONTEXT: &[u8] = b"sprockets-tls-signing";

/// Load a root certificate from a given path
pub fn load_root_cert(keydir: &Utf8PathBuf) -> anyhow::Result<Certificate> {
    let mut root_cert_path = keydir.clone();
    root_cert_path.push(ROOT_CERT_FILENAME);
    let mut root_cert_pem = Vec::new();
    File::open(&root_cert_path)?.read_to_end(&mut root_cert_pem)?;
    let root = Certificate::from_pem(&root_cert_pem)?;
    Ok(root)
}

/// A resolver for certs that gets them from the local filesystem
///
/// This is primarily used for testing. In production we'll retrieve these over
/// IPCC from the RoT
///
/// We use hardcoded filenames for simplicity, since we have to build specific
/// cert chains
#[derive(Debug)]
pub(crate) struct LocalCertResolver {
    /// Directory containing public key certs for the root and intermediate
    /// online signing key.
    pki_keydir: Utf8PathBuf,

    /// Directory containing "on-device" certs and private keys
    node_keydir: Utf8PathBuf,
}

impl LocalCertResolver {
    pub fn new(
        pki_keydir: Utf8PathBuf,
        node_keydir: Utf8PathBuf,
    ) -> LocalCertResolver {
        LocalCertResolver {
            pki_keydir,
            node_keydir,
        }
    }
}

impl LocalCertResolver {
    fn load_certified_key(&self) -> anyhow::Result<Arc<CertifiedKey>> {
        // Read the private key as a pemfile and convert it to DER that can be
        // used by rustls
        let mut privkey_pem = Vec::new();
        let mut path = self.node_keydir.clone();
        path.push(SPROCKETS_AUTH_KEY_FILENAME);
        File::open(&path)?.read_to_end(&mut privkey_pem)?;

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
        let mut path = self.pki_keydir.clone();
        path.push(OKS_SIGNER_CERT_FILENAME);
        File::open(&path)?.read_to_end(&mut oks_signer_pem)?;
        let (type_label, oks_signer_der) =
            pem_rfc7468::decode_vec(&oks_signer_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // A unique id set at manufacturing time for each device
        //
        // This is an intermediate embedded signing cert used to sign deviceid
        // certs.
        let mut platformid_pem = Vec::new();
        let mut path = self.node_keydir.clone();
        path.push(PLATFORM_ID_CERT_FILENAME);
        File::open(&path)?.read_to_end(&mut platformid_pem)?;
        let (type_label, platformid_der) =
            pem_rfc7468::decode_vec(&platformid_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // Device ID Cert
        //
        // This is the cert for an embedded CA used to sign measurement certs as
        // well as TLS authentication certs used in sprockets.
        let mut deviceid_pem = Vec::new();
        let mut path = self.node_keydir.clone();
        path.push(DEVICE_ID_CERT_FILENAME);
        File::open(&path)?.read_to_end(&mut deviceid_pem)?;
        let (type_label, deviceid_der) =
            pem_rfc7468::decode_vec(&deviceid_pem)?;
        assert_eq!(type_label, "CERTIFICATE");

        // The sprockets TLS auth cert
        //
        // This is the end-entity cert that is used to authenticate the TLS session
        let mut sprockets_auth_pem = Vec::new();
        let mut path = self.node_keydir.clone();
        path.push(SPROCKETS_AUTH_CERT_FILENAME);
        File::open(&path)?.read_to_end(&mut sprockets_auth_pem)?;
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

/// A mechanism for signing using an in memory Ed25519 private key
#[derive(Debug)]
pub(crate) struct LocalEd25519Signer {
    // TODO: Wrap in a secret
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
            .map_err(|_| {
                rustls::Error::General("Failed to sign message".to_string())
            })?;

        Ok(sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// An implementation of a an Ed25519 private signing key that lives in memory
///
/// In production we'll send signing requests to the RoT via IPCC and sprot.
#[derive(Debug)]
pub(crate) struct LocalEd25519SigningKey {
    // TODO: Wrap in a secret
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

        let privkey_info =
            PrivateKeyInfo::try_from(self.privkey_der.as_slice()).ok()?;

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
}

impl RotCertVerifier {
    pub fn new(root: Certificate) -> anyhow::Result<Self> {
        let verifier = PkiPathSignatureVerifier::new(Some(root))?;
        Ok(RotCertVerifier { verifier })
    }

    /// Create a `PkiPath` suitable for `dice-verifier`
    fn pki_path(
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
    ) -> Result<Vec<Certificate>, rustls::Error> {
        let mut pki_path = Vec::new();
        for der in iter::once(end_entity).chain(intermediates) {
            pki_path.push(Certificate::from_der(der).map_err(|_| {
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
        let pki_path = Self::pki_path(end_entity, intermediates)?;
        self.verifier.verify(&pki_path).map_err(|e| {
            println!("err = {e}");
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )
        })?;

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

        Ok(HandshakeSignatureValid::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client::Client;
    use rustls::client::ResolvesClientCert;
    use rustls::server::ResolvesServerCert;
    use server::Server;
    use std::{
        net::{TcpListener, TcpStream},
        time,
    };

    #[test]
    fn basic() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let mut client_node_keydir = pki_keydir.clone();
        client_node_keydir.push("sled1");
        let mut server_node_keydir = pki_keydir.clone();
        server_node_keydir.push("sled2");

        // Create a resolver that can return the cert chain for this client so
        // the server can authenticate it, along with a mechanism for signing
        // transcripts.
        let client_resolver = Arc::new(LocalCertResolver::new(
            pki_keydir.clone(),
            client_node_keydir,
        )) as Arc<dyn ResolvesClientCert>;

        // Create a resolver that can return the cert chain for this server so
        // the client can authenticate it, along with a mechanism for signing
        // transcripts.
        let server_resolver = Arc::new(LocalCertResolver::new(
            pki_keydir.clone(),
            server_node_keydir,
        )) as Arc<dyn ResolvesServerCert>;

        // Create our client
        let client = Client::new(&pki_keydir, client_resolver).unwrap();

        // Create our server
        let server = Server::new(&pki_keydir, server_resolver).unwrap();

        // Message to send over TLS
        const MSG: &[u8] = b"Hello Joe";

        // Accept a single connection and do some TLS
        std::thread::spawn(move || {
            let listener = TcpListener::bind("[::1]:46456").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut conn =
                rustls::ServerConnection::new(Arc::new(server.config.clone()))
                    .unwrap();
            conn.complete_io(&mut stream).unwrap();

            let mut buf = Vec::new();
            let _ = conn.reader().read_to_end(&mut buf).unwrap();
            assert_eq!(buf, MSG.to_vec());
        });

        // Our cert resolver and verifier currently ignore the hostname
        let mut conn = rustls::ClientConnection::new(
            Arc::new(client.config.clone()),
            "example.com".try_into().unwrap(),
        )
        .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));

        let mut sock = TcpStream::connect("[::1]:46456").unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(&MSG).unwrap();
    }
}
