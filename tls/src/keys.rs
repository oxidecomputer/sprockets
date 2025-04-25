// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS based connections

use camino::Utf8PathBuf;
use dice_verifier::PkiPathSignatureVerifier;
use ed25519_dalek::pkcs8::PrivateKeyInfo;
use ed25519_dalek::Signer as EdSigner;
use ed25519_dalek::Verifier;
use rustls::{
    client::danger::HandshakeSignatureValid,
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
    SignatureScheme,
};
use secrecy::{DebugSecret, ExposeSecret, Secret};
use sha3::Digest;
use slog::{error, info};
use std::io::prelude::*;
use std::iter;

use crate::ipcc::Ipcc;
use crate::Error;
use serde::Deserialize;
use std::{fs::File, sync::Arc};
use x509_cert::{
    der::{self, Decode, Encode, Reader},
    Certificate,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "which", rename_all = "snake_case")]
pub enum ResolveSetting {
    // Use certificates gathered over IPCC
    Ipcc,
    // Use specified chain/key
    Local {
        priv_key: Utf8PathBuf,
        cert_chain: Utf8PathBuf,
    },
}

#[derive(Debug)]
pub struct CertResolver {
    pub log: slog::Logger,
    pub resolve: ResolveSetting,
}

impl CertResolver {
    pub fn new(log: slog::Logger, resolve: ResolveSetting) -> Self {
        CertResolver { log, resolve }
    }

    fn load_ipcc_key(&self) -> Result<Arc<CertifiedKey>, crate::Error> {
        let ipcc = Ipcc::new().map_err(crate::Error::RotRequest)?;
        let cert_chain_bytes = ipcc.rot_get_tq_cert_chain()?;
        let mut idx = 0;
        let mut der_vec = vec![];
        // The cert chain returned is a concatenated series of DER certs.
        // rustls wants each cert as a member of a `Vec`. We don't know
        // the length of each cert so we have to parse the DER to find it.
        //
        // Note we could just return the length of each cert but that
        // either invovles more IPCC calls or more work on the RoT/SP.
        // This code runs on the Big CPU so we can do the Big Work here.
        // A note for our certificate manufacturing v2 would be to just
        // include the length of each cert along with the DER
        while idx < cert_chain_bytes.len() {
            let reader = der::SliceReader::new(&cert_chain_bytes[idx..])
                .map_err(crate::Error::Der)?;
            let header = reader.peek_header().map_err(crate::Error::Der)?;
            // DER certificates are supposed to be a `Sequence`.
            // We could check that here but we're going to get better
            // error messages by letting the cert parsing code say
            // exactly what went wrong
            let seq_len: usize =
                header.length.try_into().map_err(crate::Error::Der)?;
            let tag_len: usize = header
                .encoded_len()
                .map_err(crate::Error::Der)?
                .try_into()
                .map_err(crate::Error::Der)?;
            // Total len = length from the sequence plus the tag itself
            let end = idx + seq_len + tag_len;

            der_vec.push(CertificateDer::from(
                cert_chain_bytes[idx..end].to_vec(),
            ));
            idx += seq_len + tag_len;
        }
        for c in &der_vec {
            // Apart from printing out a bit of certificate information this
            // also serves as a validation on the DER certificate.
            let cert = Certificate::from_der(c).map_err(crate::Error::Der)?;
            info!(self.log, "Certificate => {}", cert.tbs_certificate.subject);
        }
        // TODO pass the existing ipcc handle. Right now we can't because
        // we need to review sync/send/copy/clone for libipcc
        Ok(Arc::new(CertifiedKey::new(der_vec, Arc::new(IpccKey {}))))
    }

    fn load_local_key(
        &self,
        priv_key: &Utf8PathBuf,
        cert_chain: &Utf8PathBuf,
    ) -> Result<Arc<CertifiedKey>, crate::Error> {
        let mut privkey_pem = Vec::new();
        File::open(priv_key)?.read_to_end(&mut privkey_pem)?;
        let (type_label, privkey_der) = pem_rfc7468::decode_vec(&privkey_pem)?;
        if type_label != "PRIVATE KEY" {
            return Err(crate::Error::BadPrivateKey(type_label.to_string()));
        }

        let signing_key = Arc::new(LocalEd25519SigningKey {
            privkey_der: Secret::new(PrivkeyDer(privkey_der)),
        }) as Arc<dyn SigningKey>;

        let pem_chain =
            Certificate::load_pem_chain(&std::fs::read(cert_chain)?)?;

        Ok(Arc::new(CertifiedKey::new(
            // The chain needs to be in reverse order
            // - Convert all our certs to der
            // - Convert the DER into the format rustls expects
            pem_chain
                .into_iter()
                .rev()
                .map(|x| x.to_der())
                .collect::<Result<Vec<Vec<u8>>, _>>()?
                .into_iter()
                .map(|x| x.into())
                .collect::<Vec<CertificateDer>>(),
            signing_key,
        )))
    }

    pub fn load_certified_key(&self) -> Result<Arc<CertifiedKey>, Error> {
        match &self.resolve {
            ResolveSetting::Ipcc => self.load_ipcc_key(),
            ResolveSetting::Local {
                priv_key,
                cert_chain,
            } => self.load_local_key(priv_key, cert_chain),
        }
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
        // XXX double check on the use of sha3-256 because that's what we need to use with
        // the RoT
        let mut prehashed = sha3::Sha3_256::new();
        prehashed.update(message);
        let sig = self.key.sign(&prehashed.finalize());

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

/// Represents the underlying key returned over IPCC
#[derive(Debug)]
pub struct IpccKey {}

impl SigningKey for IpccKey {
    fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if !offered.iter().any(|&s| s == SignatureScheme::ED25519) {
            return None;
        }
        Some(Box::new(IpccSigner {}) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

#[derive(Debug)]
pub struct IpccSigner {}

impl Signer for IpccSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // We require sha3_256
        let mut hash = sha3::Sha3_256::new();
        hash.update(message);

        let ipcc = Ipcc::new().map_err(|x| {
            rustls::Error::Other(rustls::OtherError(std::sync::Arc::new(x)))
        })?;
        let signature = ipcc.rot_tq_sign(&hash.finalize()).map_err(|x| {
            rustls::Error::Other(rustls::OtherError(std::sync::Arc::new(x)))
        })?;
        Ok(signature)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Uses `dice-verifier` to verify a certificate chain
/// We can't use the existing rustls verifier because our generated certificates
/// are not compatible with WebPKI
#[derive(Debug)]
pub struct RotCertVerifier {
    // We need to allow for multiple roots for verification
    verifiers: Vec<PkiPathSignatureVerifier>,
    pub log: slog::Logger,
}

impl RotCertVerifier {
    pub fn new(
        roots: Vec<Certificate>,
        log: slog::Logger,
    ) -> Result<Self, crate::Error> {
        let verifiers = roots
            .into_iter()
            .map(|r| PkiPathSignatureVerifier::new(Some(r)))
            .collect::<Result<Vec<PkiPathSignatureVerifier>, _>>()?;
        Ok(RotCertVerifier { verifiers, log })
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
        let mut err = vec![];
        for v in &self.verifiers {
            match v.verify(&pki_path) {
                Ok(_) => {
                    info!(self.log, "Certificate chain verified successfully");
                    return Ok(());
                }
                Err(e) => err.push(e),
            }
        }
        error!(self.log, "Failed to verify cert: {err:?}");
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ))
    }

    pub fn verify_signature(
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

        // XXX Need to double check. Right now on the RoT we assume a sha3-256
        // message but I guess TLS assumes sha-512?
        let mut prehashed = sha3::Sha3_256::new();
        prehashed.update(message);

        let signature =
            ed25519_dalek::Signature::from_slice(sig).map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )
            })?;
        verifying_key
            .verify(&prehashed.finalize(), &signature)
            .map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature,
                )
            })?;

        info!(self.log, "Signature verified successfully");

        Ok(HandshakeSignatureValid::assertion())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SprocketsConfig {
    pub resolve: ResolveSetting,
    pub roots: Vec<Utf8PathBuf>,
    pub corpus: Vec<Utf8PathBuf>,
}
