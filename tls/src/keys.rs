// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS based connections

use camino::Utf8PathBuf;
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

        // The cert chain returned is a concatenated series of DER certs.
        // rustls wants each cert as a member of a `Vec`. This loop uses a
        // `SliceReader` to walk the concatinated DER encoded cert chain parsing
        // each into an `x509_cert::Certificate` to ensure it's actually a cert.
        // It then collects the DER for each into the
        // `Vec<rustls::CertificateDer>` expected by rustls.
        let mut der_vec = vec![];
        let mut reader = der::SliceReader::new(&cert_chain_bytes)?;
        while !reader.is_finished() {
            let start: usize =
                reader.position().try_into().map_err(crate::Error::Der)?;
            let cert: Certificate = reader.decode()?;
            info!(self.log, "Certificate => {}", cert.tbs_certificate.subject);
            let end: usize =
                reader.position().try_into().map_err(crate::Error::Der)?;
            der_vec.push(CertificateDer::from(
                cert_chain_bytes[start..end].to_vec(),
            ));
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
            // Convert certs to der and transform into the type expected by
            // rustls
            pem_chain
                .into_iter()
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
        if !offered.contains(&SignatureScheme::ED25519) {
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
        if !offered.contains(&SignatureScheme::ED25519) {
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
    pub roots: Vec<Certificate>,
    pub log: slog::Logger,
}

impl RotCertVerifier {
    pub fn new(
        roots: Vec<Certificate>,
        log: slog::Logger,
    ) -> Result<Self, crate::Error> {
        Ok(RotCertVerifier { roots, log })
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
        match dice_verifier::verify_cert_chain(&pki_path, Some(&self.roots)) {
            Err(e) => {
                error!(self.log, "verifier failed: {e}");
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                ))
            }
            Ok(root) => {
                info!(
                    self.log,
                    "verifier succeeded against root w/ subject: {}",
                    root.tbs_certificate.subject
                );
                Ok(())
            }
        }
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
    pub attest: AttestConfig,
    pub roots: Vec<Utf8PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "which", rename_all = "snake_case")]
/// Configuration for attestation interface / artifacts.
pub enum AttestConfig {
    // Use `dice-verifier::AttestIpcc`.
    Ipcc,
    // Use artifacts from local files with `dice_verifier::AttestMock`.
    Local {
        priv_key: Utf8PathBuf,
        cert_chain: Utf8PathBuf,
        log: Utf8PathBuf,
    },
}

/// An attestation from the RoT and, provided the appropriate root, the
/// artifacts required to verify its authenticity.
pub struct AttestArtifacts {
    pub certs: Vec<Certificate>,
    pub log: dice_verifier::Log,
    pub attestation: dice_verifier::Attestation,
}

/// This function encapsulates our IPCC usage in a non-async function. This is
/// required till the Ipcc handle is `Send`.
///
/// NOTE: The `Nonce` parameter must be the nonce provided by the peer in an
/// attestation exchange.
pub fn get_attest_data(
    config: &AttestConfig,
    nonce: &dice_verifier::Nonce,
) -> Result<AttestArtifacts, Error> {
    use dice_verifier::{ipcc::AttestIpcc, Attest, AttestMock};

    // create the `Attest` impl prescribed by the config
    let attest: Box<dyn Attest> = match config {
        AttestConfig::Ipcc => Box::new(AttestIpcc::new()?),
        AttestConfig::Local {
            priv_key,
            cert_chain,
            log,
        } => Box::new(AttestMock::load(cert_chain, log, priv_key)?),
    };

    Ok(AttestArtifacts {
        certs: attest.get_certificates()?,
        log: attest.get_measurement_log()?,
        attestation: attest.attest(nonce)?,
    })
}
