//! Implementation of the RoT sprocket

use crate::endorsements::Ed25519EndorsementsV1;
use crate::keys::{random_buf, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
use crate::measurements::{
    HbsMeasurementsV1, HostMeasurementsV1, MeasurementCorpusV1, MeasurementsV1, RotMeasurementsV1,
    SpMeasurementsV1,
};
use crate::msgs::*;

use hubpack::{deserialize, serialize, SerializedSize};
use salty;
use serde::{Deserialize, Serialize};

/// A key management and measurement service run on the RoT
pub struct RotSprocket {
    /// The key of the intermediate manufacturing cert that serves as the root
    /// of trust of this platform.
    manufacturing_public_key: Ed25519PublicKey,

    device_id_keypair: salty::Keypair,
    measurement_keypair: salty::Keypair,
    dhe_keypair: salty::Keypair,

    endorsements: Ed25519EndorsementsV1,

    /// Measurements get filled in by the running service
    rot_measurements: Option<RotMeasurementsV1>,
    sp_measurements: Option<SpMeasurementsV1>,
    hbs_measurements: Option<HbsMeasurementsV1>,
    host_measurements: Option<HostMeasurementsV1>,

    /// The expected value of measurements (shipped with fw update)
    corpus: MeasurementCorpusV1,
}

impl RotSprocket {
    pub fn new(config: RotConfig) -> RotSprocket {
        RotSprocket {
            manufacturing_public_key: config.manufacturing_public_key,
            device_id_keypair: config.device_id_keypair,
            measurement_keypair: config.measurement_keypair,
            dhe_keypair: config.dhe_keypair,
            endorsements: config.endorsements,

            rot_measurements: None,
            sp_measurements: None,
            hbs_measurements: None,
            host_measurements: None,

            corpus: config.corpus,
        }
    }
}

pub struct RotConfig {
    pub manufacturing_public_key: Ed25519PublicKey,
    pub endorsements: Ed25519EndorsementsV1,
    pub corpus: MeasurementCorpusV1,

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
    pub fn bootstrap_for_testing() -> RotConfig {
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
        let corpus = MeasurementCorpusV1::default();
        let manufacturing_public_key = Ed25519PublicKey(manufacturing_keypair.public.to_bytes());

        RotConfig {
            manufacturing_public_key,
            endorsements,
            corpus,
            device_id_keypair,
            measurement_keypair,
            dhe_keypair,
        }
    }
}

#[derive(Debug, Clone)]
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

impl RotSprocket {
    /// Handle a serialized request
    pub fn handle(&mut self, req: &[u8], rsp: &mut [u8]) -> Result<(), RotSprocketError> {
        let (request, _) = deserialize::<RotRequest>(req)?;
        let response = self.handle_deserialized(request);
        serialize(rsp, &response)?;
        Ok(())
    }

    /// Handle a request and return a reply
    pub fn handle_deserialized(&mut self, request: RotRequest) -> RotResponse {
        if request.version != 1 {
            return RotResponse {
                id: request.id,
                version: request.version,
                result: RotResultV1::Err(RotErrorV1::UnsupportedVersion),
            };
        }
        match request.op {
            RotOpV1::GetEndorsements => RotResponse {
                id: request.id,
                version: request.version,
                result: RotResultV1::Endorsements(self.endorsements.clone()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_endorsements() {
        let config = RotConfig::bootstrap_for_testing();
        let endorsements = config.endorsements.clone();
        let mut rot = RotSprocket::new(config);
        let req = RotRequest {
            id: 0,
            version: 1,
            op: RotOpV1::GetEndorsements,
        };
        let mut reqbuf = [0u8; RotRequest::MAX_SIZE];
        let mut rspbuf = [0u8; RotResponse::MAX_SIZE];
        serialize(&mut reqbuf, &req).unwrap();
        rot.handle(&reqbuf, &mut rspbuf).unwrap();
        let (rsp, _) = deserialize::<RotResponse>(&rspbuf).unwrap();
        println!("{:?}", rsp);
        assert!(matches!(
            rsp.result,
            RotResultV1::Endorsements(endorsements)
        ));
    }
}
