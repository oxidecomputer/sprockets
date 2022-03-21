// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "sled-agent")]
use ed25519_dalek::{PublicKey, SecretKey, Signature, Signer};

use derive_more::From;
use hubpack::SerializedSize;
use salty;
use serde::{Deserialize, Serialize};

use crate::keys::{random_buf, Ed25519PublicKey, Ed25519Signature};

/// The set of all endorsements for a given RoT
///
/// There are actually two chains of trust here:
///
///  1. Manufacturing -> DeviceId -> Measurement
///  2. Manufacturing -> DeviceId -> Dhe
///
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519EndorsementsV1 {
    // Some unique id for the Rot/Sled where these endorsements are valid.
    pub serial_number: SerialNumber,

    /// The endorsement by the Manufacturing key for the DeviceId key
    pub device_id: Ed25519EndorsementV1,

    /// The endorsement by the DeviceId key for the Measurement key
    pub measurement: Ed25519EndorsementV1,

    /// The endorsement by the Measurement key for the DHE key
    pub dhe: Ed25519EndorsementV1,
}

impl Ed25519EndorsementsV1 {
    // TODO: We eventually must get rid of this as we will not have access to
    // the manufacturing secret key.
    // We do this all with salty so it will run on the RoT and host.
    pub fn bootstrap_for_testing(
        manufacturing_keypair: &salty::Keypair,
        device_id_keypair: &salty::Keypair,
        measurement_keypair: &salty::Keypair,
        dhe_keypair: &salty::Keypair,
    ) -> Ed25519EndorsementsV1 {
        let serial_number = SerialNumber([0x1d; 16]);
        let device_id_public_key = Ed25519PublicKey(device_id_keypair.public.to_bytes());
        let device_id = Ed25519EndorsementV1 {
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
        let measurement = Ed25519EndorsementV1 {
            subject_key_type: KeyType::Measurement,
            signer_key_type: KeyType::DeviceId,
            signature: Ed25519Signature(
                device_id_keypair.sign(&measurement_public_key.0).to_bytes(),
            ),
            subject_public_key: measurement_public_key,
        };

        let dhe_public_key = Ed25519PublicKey(dhe_keypair.public.to_bytes());
        let dhe = Ed25519EndorsementV1 {
            subject_key_type: KeyType::Dhe,
            signer_key_type: KeyType::DeviceId,
            signature: Ed25519Signature(device_id_keypair.sign(&dhe_public_key.0).to_bytes()),
            subject_public_key: dhe_public_key,
        };

        Ed25519EndorsementsV1 {
            serial_number,
            device_id,
            measurement,
            dhe,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum Ed25519EndorsementsErrorV1 {
    InvalidDeviceIdSig,
    InvalidMeasurementSig,
    InvalidDheSig,
    IncorrectSubjectKeyType,
    IncorrectSignerKeyType,
    InvalidPublicKey,
    InvalidSignature,
}

/// Validation is done on the host, so use Dalek.
#[cfg(feature = "sled-agent")]
impl Ed25519EndorsementsV1 {
    pub fn validate(
        &self,
        manufacturing_public_key: &Ed25519PublicKey,
    ) -> Result<(), Ed25519EndorsementsErrorV1> {
        self.validate_key_type_expectations()?;

        // Convert the raw bytes into Dalek types
        let device_id_public_key = PublicKey::from_bytes(&(self.device_id.subject_public_key.0))
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidPublicKey)?;
        let manufacturing_public_key = PublicKey::from_bytes(&manufacturing_public_key.0)
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidPublicKey)?;
        let signed_dhe_key = ed25519::Signature::from_bytes(&self.dhe.signature.0)
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidSignature)?;
        let signed_measurement_key = ed25519::Signature::from_bytes(&self.measurement.signature.0)
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidSignature)?;
        let signed_device_id_key = ed25519::Signature::from_bytes(&self.device_id.signature.0)
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidSignature)?;

        // Ensure the DHE key is signed by the DeviceId key
        device_id_public_key
            .verify_strict(&self.dhe.subject_public_key.0, &signed_dhe_key)
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidDheSig)?;

        // Ensure the Measurement key is signed by the DeviceId key
        device_id_public_key
            .verify_strict(
                &self.measurement.subject_public_key.0,
                &signed_measurement_key,
            )
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidMeasurementSig)?;

        // Ensure the DeviceId key is signed by the Manufacturing key
        manufacturing_public_key
            .verify_strict(&self.device_id.subject_public_key.0, &signed_device_id_key)
            .map_err(|_| Ed25519EndorsementsErrorV1::InvalidDheSig)?;

        Ok(())
    }

    fn validate_key_type_expectations(&self) -> Result<(), Ed25519EndorsementsErrorV1> {
        // A DeviceId key signs a DHE key
        if self.dhe.subject_key_type != KeyType::Dhe {
            return Err(Ed25519EndorsementsErrorV1::IncorrectSubjectKeyType);
        }
        if self.dhe.signer_key_type != KeyType::DeviceId {
            return Err(Ed25519EndorsementsErrorV1::IncorrectSignerKeyType);
        }

        // A DeviceId key signs a measurement key
        if self.measurement.subject_key_type != KeyType::Measurement {
            return Err(Ed25519EndorsementsErrorV1::IncorrectSubjectKeyType);
        }
        if self.measurement.signer_key_type != KeyType::DeviceId {
            return Err(Ed25519EndorsementsErrorV1::IncorrectSignerKeyType);
        }

        // A Manufacturing key signs a DeviceId key
        if self.device_id.subject_key_type != KeyType::DeviceId {
            return Err(Ed25519EndorsementsErrorV1::IncorrectSubjectKeyType);
        }
        if self.device_id.signer_key_type != KeyType::Manufacturing {
            return Err(Ed25519EndorsementsErrorV1::IncorrectSignerKeyType);
        }

        Ok(())
    }
}

/// A signature of a public key by a private key higher up the chain of trust.
///
/// This is a simplified replacement for x.509v3 certs that is suitable for
/// constrained devices.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519EndorsementV1 {
    pub subject_key_type: KeyType,
    pub subject_public_key: Ed25519PublicKey,
    pub signer_key_type: KeyType,
    pub signature: Ed25519Signature,
}

/// A unique identifier for a device.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
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
    /// trust anchor for our endorsement chain.
    Manufacturing,

    /// The immutable DeviceId public key based on the RoT PUF
    DeviceId,

    /// The Dice alias key used by the RoT *only* for signing measurements
    Measurement,

    /// The Key used for Diffie-Hellman key exchange to establish secure
    /// channels between sled agents.
    Dhe,
}

#[cfg(feature = "sled-agent")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endorsement_validation() {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let device_id_keypair = salty::Keypair::from(&random_buf());
        let measurement_keypair = salty::Keypair::from(&random_buf());
        let dhe_keypair = salty::Keypair::from(&random_buf());
        let endorsements = Ed25519EndorsementsV1::bootstrap_for_testing(
            &manufacturing_keypair,
            &device_id_keypair,
            &measurement_keypair,
            &dhe_keypair,
        );

        let manufacturing_public_key = Ed25519PublicKey(manufacturing_keypair.public.to_bytes());
        assert!(endorsements.validate(&manufacturing_public_key).is_ok());
    }

    #[test]
    fn test_endorsement_failure() {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let device_id_keypair = salty::Keypair::from(&random_buf());
        let measurement_keypair = salty::Keypair::from(&random_buf());
        let dhe_keypair = salty::Keypair::from(&random_buf());
        let mut endorsements = Ed25519EndorsementsV1::bootstrap_for_testing(
            &manufacturing_keypair,
            &device_id_keypair,
            &measurement_keypair,
            &dhe_keypair,
        );

        // Modify DHE signature so validation fails
        endorsements.dhe.signature.0[0] += 1;

        let manufacturing_public_key = Ed25519PublicKey(manufacturing_keypair.public.to_bytes());
        assert_eq!(
            Err(Ed25519EndorsementsErrorV1::InvalidDheSig),
            endorsements.validate(&manufacturing_public_key)
        );
    }
}
