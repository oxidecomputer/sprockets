//! Implementation of the RoT sprocket

use crate::msgs::*;

use hubpack::{deserialize, serialize};

/// A key management and measurement service run on the RoT
pub struct RotSprocket {
    /// The key of the intermediate manufacturing cert that serves as the root
    /// of trust of this platform.
    manufacturing_public_key: Ed25519PublicKey,

    device_secret_key: Ed25519SecretKey,
    measurements_secret_key: Ed25519SecretKey,
    dhe_secret_key: Ed25519SecretKey,

    endorsements: Ed25519EndorsementsV1,

    /// Measurements get filled in by the running service
    rot_measurements: Option<RotMeasurementsV1>,
    sp_measurements: Option<SpMeasurementsV1>,
    hbs_measurements: Option<HbsMeasurementsV1>,
    host_measurements: Option<HostMeasurementsV1>,

    /// The expected value of measurements (shipped with fw update)
    corpus: MeasurementCorpusV1,
}

pub struct RotPublicConfig {
    pub manufacturing_public_key: Ed25519PublicKey,
    pub endorsements: Ed25519EndorsementsV1,
    pub corpus: MeasurementCorpusV1,
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
