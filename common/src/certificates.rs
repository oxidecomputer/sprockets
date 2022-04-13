// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use hubpack::SerializedSize;
use salty;
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

// Macro must be invoked to provide big array support for serde
big_array! { BigArray; }

pub use crate::{Ed25519PublicKey, Ed25519Signature};

/// The set of all certificates for a given RoT
///
/// There are actually two chains of trust here:
///
///  1. Manufacturing -> DeviceId -> Measurement
///  2. Manufacturing -> DeviceId -> Dhe
///
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519Certificates {
    // Some unique id for the Rot/Sled where these certificates are valid.
    //
    // TODO: This is just a placeholder for some metadata that we want to store
    // per RoT. It's possible this will live per certificate instead, and we
    // should also probably sign it.
    pub serial_number: SerialNumber,

    /// The certificate by the Manufacturing key for the DeviceId key
    pub device_id: Ed25519Certificate,

    /// The certificate by the DeviceId key for the Measurement key
    pub measurement: Ed25519Certificate,

    /// The certificate by the Measurement key for the DHE key
    pub dhe: Ed25519Certificate,
}

impl Ed25519Certificates {
    // TODO: We eventually must get rid of this as we will not have access to
    // the manufacturing secret key.
    // We do this all with salty so it will run on the RoT and host.
    pub fn bootstrap_for_testing(
        manufacturing_keypair: &salty::Keypair,
        device_id_keypair: &salty::Keypair,
        measurement_keypair: &salty::Keypair,
        dhe_keypair: &salty::Keypair,
    ) -> Ed25519Certificates {
        let serial_number = SerialNumber([0x1d; 16]);
        let device_id_public_key = Ed25519PublicKey(device_id_keypair.public.to_bytes());
        let device_id = Ed25519Certificate {
            subject_key_type: KeyType::DeviceId,
            signer_key_type: KeyType::Manufacturing,
            signature: Ed25519Signature(
                manufacturing_keypair
                    .sign(&device_id_public_key.0)
                    .to_bytes(),
            ),
            subject_public_key: device_id_public_key,
        };

        let measurement_public_key = Ed25519PublicKey(measurement_keypair.public.to_bytes());
        let measurement = Ed25519Certificate {
            subject_key_type: KeyType::Measurement,
            signer_key_type: KeyType::DeviceId,
            signature: Ed25519Signature(
                device_id_keypair.sign(&measurement_public_key.0).to_bytes(),
            ),
            subject_public_key: measurement_public_key,
        };

        let dhe_public_key = Ed25519PublicKey(dhe_keypair.public.to_bytes());
        let dhe = Ed25519Certificate {
            subject_key_type: KeyType::Dhe,
            signer_key_type: KeyType::DeviceId,
            signature: Ed25519Signature(device_id_keypair.sign(&dhe_public_key.0).to_bytes()),
            subject_public_key: dhe_public_key,
        };

        Ed25519Certificates {
            serial_number,
            device_id,
            measurement,
            dhe,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum Ed25519CertificatesError {
    InvalidDeviceIdSig,
    InvalidMeasurementSig,
    InvalidDheSig,
    IncorrectSubjectKeyType,
    IncorrectSignerKeyType,
    InvalidPublicKey,
    InvalidSignature,
}

/// A signature of a public key by a private key higher up the chain of trust.
///
/// This is a simplified replacement for x.509v3 certs that is suitable for
/// constrained devices.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519Certificate {
    pub subject_key_type: KeyType,
    pub subject_public_key: Ed25519PublicKey,
    pub signer_key_type: KeyType,
    pub signature: Ed25519Signature,
}

/// Users must implement this because only they know what crypto library they are
/// using for verification.
///
/// We could have just chosen 'ring' as our crypto provider, but that would
/// require build time configuration in the common crate which we seek to avoid.
pub trait Ed25519Verifier {
    fn verify(
        &self,
        signer_public_key: &Ed25519PublicKey,
        msg: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), ()>;
}

impl Ed25519Certificates {
    pub fn validate<V>(
        &self,
        manufacturing_public_key: &Ed25519PublicKey,
        verifier: &V,
    ) -> Result<(), Ed25519CertificatesError>
    where
        V: Ed25519Verifier,
    {
        self.validate_key_type_expectations()?;

        // Ensure the DHE key is signed by the DeviceId key
        verifier
            .verify(
                &self.device_id.subject_public_key,
                &self.dhe.subject_public_key.0,
                &self.dhe.signature,
            )
            .map_err(|_| Ed25519CertificatesError::InvalidDheSig)?;

        // Ensure the Measurement key is signed by the DeviceId key
        verifier
            .verify(
                &self.device_id.subject_public_key,
                &self.measurement.subject_public_key.0,
                &self.measurement.signature,
            )
            .map_err(|_| Ed25519CertificatesError::InvalidMeasurementSig)?;

        // Ensure the DeviceId key is signed by the Manufacturing key
        verifier
            .verify(
                manufacturing_public_key,
                &self.device_id.subject_public_key.0,
                &self.device_id.signature,
            )
            .map_err(|_| Ed25519CertificatesError::InvalidDheSig)?;

        Ok(())
    }

    fn validate_key_type_expectations(&self) -> Result<(), Ed25519CertificatesError> {
        // A DeviceId key signs a DHE key
        if self.dhe.subject_key_type != KeyType::Dhe {
            return Err(Ed25519CertificatesError::IncorrectSubjectKeyType);
        }
        if self.dhe.signer_key_type != KeyType::DeviceId {
            return Err(Ed25519CertificatesError::IncorrectSignerKeyType);
        }

        // A DeviceId key signs a measurement key
        if self.measurement.subject_key_type != KeyType::Measurement {
            return Err(Ed25519CertificatesError::IncorrectSubjectKeyType);
        }
        if self.measurement.signer_key_type != KeyType::DeviceId {
            return Err(Ed25519CertificatesError::IncorrectSignerKeyType);
        }

        // A Manufacturing key signs a DeviceId key
        if self.device_id.subject_key_type != KeyType::DeviceId {
            return Err(Ed25519CertificatesError::IncorrectSubjectKeyType);
        }
        if self.device_id.signer_key_type != KeyType::Manufacturing {
            return Err(Ed25519CertificatesError::IncorrectSignerKeyType);
        }

        Ok(())
    }
}

/// A unique identifier for a device.
#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct SerialNumber([u8; 16]);

/// The different types of public keys managed by the RoT.
///
/// All these keys are retrievable from the RoT, but only the DeviceId,
/// Measurement, and DHE keys are retrieved as part of the protocol. This is
/// because the manufacturing public key should be provisioned on all sleds as
/// the trust anchor.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum KeyType {
    /// The public key of the intermediate manufacturing cert that serves as the
    /// trust anchor for our certificate chain.
    Manufacturing,

    /// The immutable DeviceId public key based on the RoT PUF
    DeviceId,

    /// The Dice alias key used by the RoT *only* for signing measurements
    Measurement,

    /// The Key used for Diffie-Hellman key exchange to establish secure
    /// channels between sled agents.
    Dhe,
}

#[cfg(test)]
mod tests {

    use super::*;
    use ed25519;
    use ed25519_dalek::PublicKey;
    use rand::{rngs::OsRng, RngCore};

    pub fn random_buf() -> [u8; 32] {
        let mut data = [0u8; 32];
        OsRng.fill_bytes(&mut data);
        data
    }

    pub struct DalekVerifier;

    impl Ed25519Verifier for DalekVerifier {
        fn verify(
            &self,
            signer_public_key: &Ed25519PublicKey,
            msg: &[u8],
            signature: &Ed25519Signature,
        ) -> Result<(), ()> {
            let public_key = PublicKey::from_bytes(&signer_public_key.0).unwrap();
            let signature = ed25519::Signature::from_bytes(&signature.0).unwrap();
            public_key.verify_strict(msg, &signature).map_err(|_| ())?;
            Ok(())
        }
    }

    #[test]
    fn test_certificate_validation() {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let device_id_keypair = salty::Keypair::from(&random_buf());
        let measurement_keypair = salty::Keypair::from(&random_buf());
        let dhe_keypair = salty::Keypair::from(&random_buf());
        let certificates = Ed25519Certificates::bootstrap_for_testing(
            &manufacturing_keypair,
            &device_id_keypair,
            &measurement_keypair,
            &dhe_keypair,
        );

        let manufacturing_public_key = Ed25519PublicKey(manufacturing_keypair.public.to_bytes());
        assert!(certificates
            .validate(&manufacturing_public_key, &DalekVerifier)
            .is_ok());
    }

    #[test]
    fn test_certificate_failure() {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let device_id_keypair = salty::Keypair::from(&random_buf());
        let measurement_keypair = salty::Keypair::from(&random_buf());
        let dhe_keypair = salty::Keypair::from(&random_buf());
        let mut certificates = Ed25519Certificates::bootstrap_for_testing(
            &manufacturing_keypair,
            &device_id_keypair,
            &measurement_keypair,
            &dhe_keypair,
        );

        // Modify DHE signature so validation fails
        certificates.dhe.signature.0[0] += 1;

        let manufacturing_public_key = Ed25519PublicKey(manufacturing_keypair.public.to_bytes());
        assert_eq!(
            Err(Ed25519CertificatesError::InvalidDheSig),
            certificates.validate(&manufacturing_public_key, &DalekVerifier)
        );
    }
}
