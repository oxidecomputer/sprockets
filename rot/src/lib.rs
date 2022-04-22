// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implementation of the RoT sprocket

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use sprockets_common::certificates::{Ed25519Certificates, Ed25519PublicKey, Ed25519Signature};
use sprockets_common::measurements::{
    HbsMeasurements, Measurements, RotMeasurements, SpMeasurements,
};
use sprockets_common::msgs::*;
use sprockets_common::{random_buf, Sha3_256Digest};

use hubpack::{deserialize, serialize};
use salty;

/// A key management and measurement service run on the RoT
pub struct RotSprocket {
    /// The key of the intermediate manufacturing cert that serves as the root
    /// of trust of this platform.
    manufacturing_public_key: Ed25519PublicKey,

    device_id_keypair: salty::Keypair,
    measurement_keypair: salty::Keypair,
    dhe_keypair: salty::Keypair,

    certificates: Ed25519Certificates,

    /// Measurements get filled in by the running service
    measurements: Measurements,
}

impl RotSprocket {
    pub fn new(config: RotConfig) -> RotSprocket {
        let mut rot = RotSprocket {
            manufacturing_public_key: config.manufacturing_public_key,
            device_id_keypair: config.device_id_keypair,
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
    pub fn handle(&mut self, req: &[u8], rsp: &mut [u8]) -> Result<usize, RotSprocketError> {
        let (request, _) = deserialize::<RotRequest>(req)?;
        let response = self.handle_deserialized(request)?;
        let pos = serialize(rsp, &response)?;
        Ok(pos)
    }

    /// Handle a request and return a reply
    pub fn handle_deserialized(
        &mut self,
        request: RotRequest,
    ) -> Result<RotResponse, RotSprocketError> {
        let RotRequest::V1 { id, op } = request;
        let result = match op {
            RotOp::GetCertificates => RotResult::Certificates(self.certificates.clone()),
            RotOp::AddHostMeasurements(measurements) => {
                if self.measurements.host.is_some() {
                    RotResult::Err(RotError::AddHostMeasurements(
                        AddHostMeasurementsError::AlreadyAdded,
                    ))
                } else {
                    // TODO: Check corpus for validity
                    self.measurements.host = Some(measurements);
                    RotResult::Ok
                }
            }
            RotOp::GetMeasurements(nonce) => {
                // We sign the serialized form.
                let (buf, size) = self.measurements.serialize_with_nonce(&nonce);
                let sig = self.measurement_keypair.sign(&buf[..size]);
                let sig = Ed25519Signature(sig.to_bytes());
                RotResult::Measurements(self.measurements.clone(), nonce, sig)
            }
            RotOp::SignTranscript(transcript_hash) => {
                let sig = self.dhe_keypair.sign(&transcript_hash.0);
                RotResult::SignedTranscript(Ed25519Signature(sig.to_bytes()))
            }
        };
        Ok(RotResponse::V1 { id, result })
    }

    pub fn get_certificates(&self) -> Ed25519Certificates {
        self.certificates.clone()
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
    pub fn bootstrap_for_testing(manufacturing_keypair: &salty::Keypair) -> RotConfig {
        let device_id_keypair = salty::Keypair::from(&random_buf());
        let measurement_keypair = salty::Keypair::from(&random_buf());
        let dhe_keypair = salty::Keypair::from(&random_buf());
        let certificates = Ed25519Certificates::bootstrap_for_testing(
            manufacturing_keypair,
            &device_id_keypair,
            &measurement_keypair,
            &dhe_keypair,
        );
        let manufacturing_public_key = Ed25519PublicKey(manufacturing_keypair.public.to_bytes());

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

#[cfg(test)]
mod tests {
    use super::*;
    use sprockets_common::measurements::HostMeasurements;
    use sprockets_common::Nonce;

    #[test]
    fn test_get_certificates() {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let config = RotConfig::bootstrap_for_testing(&manufacturing_keypair);
        let expected_certificates = config.certificates.clone();
        let mut rot = RotSprocket::new(config);
        let req = RotRequest::V1 {
            id: 0,
            op: RotOp::GetCertificates,
        };
        let mut reqbuf = [0u8; RotRequest::MAX_SIZE];
        let mut rspbuf = [0u8; RotResponse::MAX_SIZE];
        serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf, &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponse>(&rspbuf).unwrap();
        if let RotResponse::V1 {
            result: RotResult::Certificates(certificates),
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
        let config = RotConfig::bootstrap_for_testing(&manufacturing_keypair);
        let certificates = config.certificates.clone();
        let mut rot = RotSprocket::new(config);
        let nonce = Nonce::new();

        // Get measurements before we have added host measurements
        let req = RotRequest::V1 {
            id: 1,
            op: RotOp::GetMeasurements(nonce.clone()),
        };
        let mut reqbuf = [0u8; RotRequest::MAX_SIZE];
        let mut rspbuf = [0u8; RotResponse::MAX_SIZE];
        let size = serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf[..size], &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponse>(&rspbuf).unwrap();
        if let RotResponse::V1 {
            result: RotResult::Measurements(measurements, nonce_received, sig),
            ..
        } = rsp
        {
            assert_eq!(nonce_received, nonce);

            // Recreate the buffer that was signed
            let (signed_buf, size) = measurements.serialize_with_nonce(&nonce);

            let measurement_pub_key =
                salty::PublicKey::try_from(&certificates.measurement.subject_public_key.0).unwrap();
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
        let req = RotRequest::V1 {
            id: 2,
            op: RotOp::AddHostMeasurements(host_measurements),
        };
        let size = serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf[..size], &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponse>(&rspbuf).unwrap();
        assert!(matches!(
            rsp,
            RotResponse::V1 {
                id: 2,
                result: RotResult::Ok,
            }
        ));

        let nonce = Nonce::new();
        // Now recheck to ensure the host measurement was added.
        let req = RotRequest::V1 {
            id: 3,
            op: RotOp::GetMeasurements(nonce.clone()),
        };
        let size = serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf[..size], &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponse>(&rspbuf).unwrap();
        if let RotResponse::V1 {
            result: RotResult::Measurements(measurements, nonce_received, sig),
            id: 3,
        } = rsp
        {
            assert_eq!(nonce_received, nonce);

            // Recreate the buffer that was signed
            let (signed_buf, size) = measurements.serialize_with_nonce(&nonce);

            let measurement_pub_key =
                salty::PublicKey::try_from(&certificates.measurement.subject_public_key.0).unwrap();
            assert!(measurement_pub_key
                .verify(&signed_buf[..size], &salty::Signature::from(&sig.0))
                .is_ok());

            // Ensure we got back the measurements we sent
            assert_eq!(measurements.host, Some(host_measurements));
        } else {
            panic!();
        }
    }
}
