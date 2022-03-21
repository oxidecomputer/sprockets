//! Implementation of the RoT sprocket

use crate::endorsements::Ed25519EndorsementsV1;
use crate::keys::{random_buf, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
use crate::measurements::{
    HbsMeasurementsV1, HostMeasurementsV1, MeasurementCorpusV1, MeasurementsV1, RotMeasurementsV1,
    SpMeasurementsV1,
};
use crate::msgs::*;

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
    /*    pub fn new(RotConfig) -> RotSprocket {

    }
    */

    // TODO: remove this altogether eventually
    // Use salty to create the keys and do signing. This allows us to run
    // the code on the RoT and Host.
    /*    pub fn bootstrap_for_testing() -> RotSprocket {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        let device_id_keypair = salty::Keypair::from(&random_buf());
        let measurement_keypair = salty::Keypair::from(&random_buf());
        let dhe_keypair = salty::Keypair::from(&random_buf());
    }
    */
}

pub struct RotConfig {
    pub manufacturing_public_key: Ed25519PublicKey,
    pub endorsements: Ed25519EndorsementsV1,
    pub corpus: MeasurementCorpusV1,

    // TODO: Should we instead use the generic array forms and convert to salty
    // as needed?
    pub device_keypair: salty::Keypair,
    pub measurement_keypair: salty::Keypair,
    pub dhe_keypair: salty::Keypair,
}

pub struct RotSecretConfig {
    pub device_secret_key: Ed25519SecretKey,
    pub measurements_secret_key: Ed25519SecretKey,
    pub dhe_secret_key: Ed25519SecretKey,
}

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
