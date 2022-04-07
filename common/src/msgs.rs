use derive_more::From;
pub use hubpack::{deserialize, serialize, SerializedSize};
use serde::{Deserialize, Serialize};

use crate::certificates::Ed25519Certificates;
use crate::keys::{Ed25519Signature, Nonce};
use crate::measurements::{HostMeasurements, Measurements};

/// A request to an RoT from an SP
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotRequest {
    V1 {
        /// A monotonic counter used to differentiate requests
        id: u32,

        /// The operation requested of the RoT
        op: RotOp,
    },
}

/// Requested operations of the RoT by the SP.
///
/// Note that these requests may be proxied for the sled-agent, or MGS, but
/// that is not relevant to the RoT.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotOp {
    GetCertificates,
    AddHostMeasurements(HostMeasurements),
    GetMeasurements(Nonce),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotResponse {
    V1 {
        /// A monotonic counter used to differentiate requests
        id: u32,

        // The result of a requested operation from the RoT
        //
        // TODO: Same as in the RotRequest. Make this an opcode
        result: RotResult,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotResult {
    Ok,
    Err(RotError),
    Certificates(Ed25519Certificates),
    Measurements(Measurements, Nonce, Ed25519Signature),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotError {
    UnsupportedVersion,
    InvalidOperation,
    GetCertificates(GetCertificatesError),
    AddHostMeasurements(AddHostMeasurementsError),
    GetMeasurements(GetMeasurementsError),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum GetCertificatesError {
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
