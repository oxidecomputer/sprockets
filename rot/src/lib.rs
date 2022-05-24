// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implementation of the RoT sprocket

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use sprockets_common::certificates::{
    Ed25519Certificates, Ed25519PublicKey, Ed25519Signature, SerialNumber,
};
use sprockets_common::measurements::{
    HbsMeasurements, Measurements, RotMeasurements, SpMeasurements,
};
use sprockets_common::msgs::*;
use sprockets_common::{random_buf, Nonce, Sha3_256Digest};

use hubpack::{deserialize, serialize};

pub use salty;
pub use sprockets_common as common;

/// A key management and measurement service run on the RoT
pub struct RotSprocket {
    measurement_keypair: salty::Keypair,
    dhe_keypair: salty::Keypair,

    certificates: Ed25519Certificates,

    /// Measurements get filled in by the running service
    measurements: Measurements,
}

impl RotSprocket {
    pub fn new(config: RotConfig) -> RotSprocket {
        let mut rot = RotSprocket {
            measurement_keypair: config.measurement_keypair,
            dhe_keypair: config.dhe_keypair,
            certificates: config.certificates,
            measurements: Measurements::default(),
        };
        rot.take_fake_measurements();
        rot
    }

    pub fn take_fake_measurements(&mut self) {
        self.measurements.rot = Some(RotMeasurements {
            tcb: Sha3_256Digest(random_buf()),
        });

        self.measurements.sp = Some(SpMeasurements {
            tcb: Sha3_256Digest(random_buf()),
        });

        self.measurements.hbs = Some(HbsMeasurements {
            tcb: Sha3_256Digest(random_buf()),
        });
    }

    /// Handle a serialized request
    pub fn handle(
        &mut self,
        req: &[u8],
        rsp: &mut [u8],
    ) -> Result<usize, RotSprocketError> {
        let (request, _) = deserialize::<RotRequestV1>(req)?;
        let response = self.handle_deserialized(request)?;
        let pos = serialize(rsp, &response)?;
        Ok(pos)
    }

    /// Handle a request and return a reply
    pub fn handle_deserialized(
        &mut self,
        request: RotRequestV1,
    ) -> Result<RotResponseV1, RotSprocketError> {
        let RotRequestV1 { version, id, op } = request;
        if version != 1 {
            return Ok(RotResponseV1 {
                version: 1,
                id,
                result: RotResultV1::Err(RotError::UnsupportedVersion),
            });
        }
        let result = match op {
            RotOpV1::GetCertificates => {
                RotResultV1::Certificates(self.certificates)
            }
            RotOpV1::AddHostMeasurements(measurements) => {
                if self.measurements.host.is_some() {
                    RotResultV1::Err(RotError::AddHostMeasurements(
                        AddHostMeasurementsError::AlreadyAdded,
                    ))
                } else {
                    // TODO: Check corpus for validity
                    self.measurements.host = Some(measurements);
                    RotResultV1::Ok
                }
            }
            RotOpV1::GetMeasurements(nonce) => {
                // We sign the serialized form.
                let mut buf = [0u8; Measurements::MAX_SIZE + Nonce::MAX_SIZE];
                let size =
                    self.measurements.serialize_with_nonce(&nonce, &mut buf)?;
                let sig = self.measurement_keypair.sign(&buf[..size]);
                let sig = Ed25519Signature(sig.to_bytes());
                RotResultV1::Measurements(self.measurements, nonce, sig)
            }
            RotOpV1::SignTranscript(transcript_hash) => {
                let sig = self.dhe_keypair.sign(&transcript_hash.0);
                RotResultV1::SignedTranscript(Ed25519Signature(sig.to_bytes()))
            }
        };
        Ok(RotResponseV1 {
            version,
            id,
            result,
        })
    }

    pub fn get_certificates(&self) -> Ed25519Certificates {
        self.certificates
    }
}

pub struct RotConfig {
    pub manufacturing_public_key: Ed25519PublicKey,
    pub certificates: Ed25519Certificates,

    // TODO: Should we instead use the generic array forms and convert to salty
    // as needed?
    pub device_id_keypair: salty::Keypair,
    pub measurement_keypair: salty::Keypair,
    pub dhe_keypair: salty::Keypair,
}

impl RotConfig {
    // TODO: remove this altogether eventually
    // Use salty to create the keys and do signing. This allows us to run
    // the code on the RoT and Host.
    pub fn bootstrap_for_testing(
        manufacturing_keypair: &salty::Keypair,
        device_id_keypair: salty::Keypair,
        serial_number: SerialNumber,
    ) -> RotConfig {
        let measurement_keypair = salty::Keypair::from(&random_buf());
        let dhe_keypair = salty::Keypair::from(&random_buf());
        let certificates = Ed25519Certificates::bootstrap_for_testing(
            manufacturing_keypair,
            &device_id_keypair,
            serial_number,
            &measurement_keypair,
            &dhe_keypair,
        );
        let manufacturing_public_key =
            Ed25519PublicKey(manufacturing_keypair.public.to_bytes());

        RotConfig {
            manufacturing_public_key,
            certificates,
            device_id_keypair,
            measurement_keypair,
            dhe_keypair,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RotSprocketError {
    InvalidSerializedReq,
    DeserializationBufferTooSmall,
    Hubpack(hubpack::error::Error),
}

impl From<hubpack::error::Error> for RotSprocketError {
    fn from(e: hubpack::error::Error) -> Self {
        RotSprocketError::Hubpack(e)
    }
}

impl core::fmt::Display for RotSprocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RotSprocketError::InvalidSerializedReq => {
                f.write_str("invalid serialized request")
            }
            RotSprocketError::DeserializationBufferTooSmall => {
                f.write_str("deserialization buffer too small")
            }
            RotSprocketError::Hubpack(err) => {
                f.write_str("hubpack error: ")?;
                err.fmt(f)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sprockets_common::measurements::HostMeasurements;
    use sprockets_common::Nonce;

    #[test]
    fn test_get_certificates() {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let config = RotConfig::bootstrap_for_testing(
            &manufacturing_keypair,
            salty::Keypair::from(&random_buf()),
            SerialNumber(random_buf()),
        );
        let expected_certificates = config.certificates.clone();
        let mut rot = RotSprocket::new(config);
        let req = RotRequestV1 {
            version: 1,
            id: 0,
            op: RotOpV1::GetCertificates,
        };
        let mut reqbuf = [0u8; RotRequestV1::MAX_SIZE];
        let mut rspbuf = [0u8; RotResponseV1::MAX_SIZE];
        serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf, &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponseV1>(&rspbuf).unwrap();
        if let RotResponseV1 {
            result: RotResultV1::Certificates(certificates),
            ..
        } = rsp
        {
            assert_eq!(certificates, expected_certificates);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_measurements() {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let config = RotConfig::bootstrap_for_testing(
            &manufacturing_keypair,
            salty::Keypair::from(&random_buf()),
            SerialNumber(random_buf()),
        );
        let certificates = config.certificates.clone();
        let mut rot = RotSprocket::new(config);
        let nonce = Nonce::new();

        // Get measurements before we have added host measurements
        let req = RotRequestV1 {
            version: 1,
            id: 1,
            op: RotOpV1::GetMeasurements(nonce.clone()),
        };
        let mut reqbuf = [0u8; RotRequestV1::MAX_SIZE];
        let mut rspbuf = [0u8; RotResponseV1::MAX_SIZE];
        let size = serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf[..size], &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponseV1>(&rspbuf).unwrap();
        if let RotResponseV1 {
            result: RotResultV1::Measurements(measurements, nonce_received, sig),
            ..
        } = rsp
        {
            assert_eq!(nonce_received, nonce);

            // Recreate the buffer that was signed
            let mut signed_buf =
                [0u8; Measurements::MAX_SIZE + Nonce::MAX_SIZE];
            let size = measurements
                .serialize_with_nonce(&nonce, &mut signed_buf)
                .unwrap();

            let measurement_pub_key = salty::PublicKey::try_from(
                &certificates.measurement.subject_public_key.0,
            )
            .unwrap();
            assert!(measurement_pub_key
                .verify(&signed_buf[..size], &salty::Signature::from(&sig.0))
                .is_ok());

            assert!(measurements.host.is_none());
        } else {
            panic!();
        }

        // Add host measurements

        let host_measurements = HostMeasurements {
            tcb: Sha3_256Digest(random_buf()),
        };
        let req = RotRequestV1 {
            version: 1,
            id: 2,
            op: RotOpV1::AddHostMeasurements(host_measurements),
        };
        let size = serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf[..size], &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponseV1>(&rspbuf).unwrap();
        assert!(matches!(
            rsp,
            RotResponseV1 {
                version: 1,
                id: 2,
                result: RotResultV1::Ok
            }
        ));

        let nonce = Nonce::new();
        // Now recheck to ensure the host measurement was added.
        let req = RotRequestV1 {
            version: 1,
            id: 3,
            op: RotOpV1::GetMeasurements(nonce.clone()),
        };
        let size = serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf[..size], &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponseV1>(&rspbuf).unwrap();
        if let RotResponseV1 {
            version: 1,
            result: RotResultV1::Measurements(measurements, nonce_received, sig),
            id: 3,
        } = rsp
        {
            assert_eq!(nonce_received, nonce);

            // Recreate the buffer that was signed
            let mut signed_buf =
                [0u8; Measurements::MAX_SIZE + Nonce::MAX_SIZE];
            let size = measurements
                .serialize_with_nonce(&nonce, &mut signed_buf)
                .unwrap();

            let measurement_pub_key = salty::PublicKey::try_from(
                &certificates.measurement.subject_public_key.0,
            )
            .unwrap();
            assert!(measurement_pub_key
                .verify(&signed_buf[..size], &salty::Signature::from(&sig.0))
                .is_ok());

            // Ensure we got back the measurements we sent
            assert_eq!(measurements.host, Some(host_measurements));
        } else {
            panic!();
        }
    }

    #[test]
    fn error_display_impl_forwards_hubpack_errors() {
        let err = RotSprocketError::Hubpack(hubpack::error::Error::Truncated);
        assert_eq!(err.to_string(), "hubpack error: truncated");
    }
}
