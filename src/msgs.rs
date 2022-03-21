use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

use crate::endorsements::Ed25519EndorsementsV1;
use crate::keys::{Ed25519Signature, Nonce};
use crate::measurements::{HostMeasurementsV1, MeasurementsV1};

/// A request to an RoT from an SP
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct RotRequest {
    /// A monotonic counter used to differentiate requests
    pub id: u32,

    // The version of this request format
    pub version: u32,

    // The operation requested of the RoT
    pub op: RotOpV1,
}

/// Requested operations of the RoT by the SP.
///
/// Note that these requests may be proxied for the sled-agent, or MGS, but
/// that is not relevant to the RoT.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotOpV1 {
    GetEndorsements,
    AddHostMeasurements(HostMeasurementsV1),
    GetMeasurements(Nonce),
    // TODO: DHE related ops
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct RotResponse {
    /// A monotonic counter used to differentiate requests
    pub id: u32,

    // The version of this request format
    pub version: u32,

    // The result of a requested operation from the RoT
    pub result: RotResultV1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotResultV1 {
    Ok,
    Err(RotErrorV1),
    Endorsements(Ed25519EndorsementsV1),
    Measurements(MeasurementsV1, Nonce, Ed25519Signature),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotErrorV1 {
    UnsupportedVersion,
    InvalidOperation,
    GetEndorsements(GetEndorsementsError),
    AddHostMeasurements(AddHostMeasurementsError),
    GetMeasurements(GetMeasurementsError),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum GetEndorsementsError {
    NotFound,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum AddHostMeasurementsError {
    AlreadyAdded,
    IncorrectMeasurements,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum GetMeasurementsError {
    NotFound,
}
