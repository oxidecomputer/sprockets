// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
pub use hubpack::{deserialize, serialize, SerializedSize};
use serde::{Deserialize, Serialize};

use crate::certificates::{Ed25519Certificates, Ed25519Signature};
use crate::measurements::{HostMeasurements, Measurements};
use crate::{Nonce, Sha3_256Digest};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub struct RotRequestV1 {
    /// Every version of an RotRequest should start with a u32 version
    /// We can extract this into its own type using the zero-overhead struct
    /// capability of Hubpack, when we want to differentiate requests on the
    /// wire.
    pub version: u32,

    /// A monotonic counter used to differentiate requests
    pub id: u64,

    /// The operation requested of the RoT
    pub op: RotOpV1,
}

/// Requested operations of the RoT by the SP.
///
/// Note that these requests may be proxied for the sled-agent, or MGS, but
/// that is not relevant to the RoT.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub enum RotOpV1 {
    GetCertificates,
    AddHostMeasurements(HostMeasurements),
    GetMeasurements(Nonce),
    SignTranscript(Sha3_256Digest),
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub struct RotResponseV1 {
    pub version: u32,

    /// A monotonic counter used to differentiate requests
    /// This matches the RotRequestV1 value.
    pub id: u64,

    // The result of a requested operation from the RoT
    pub result: RotResultV1,
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub enum RotResultV1 {
    Ok,
    Err(RotError),
    Certificates(Ed25519Certificates),
    Measurements(Measurements, Nonce, Ed25519Signature),
    SignedTranscript(Ed25519Signature),
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub enum RotError {
    BadEncoding,
    UnsupportedVersion,
    InvalidOperation,
    GetCertificates(GetCertificatesError),
    AddHostMeasurements(AddHostMeasurementsError),
    GetMeasurements(GetMeasurementsError),

    // Failed to send over the transport
    SendError,
    // Failed to receive over the transport
    RecvError,
    // An RoT request timed out
    Timeout,

    // There was an error with the transport
    TransportError,
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub enum GetCertificatesError {
    NotFound,
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub enum AddHostMeasurementsError {
    AlreadyAdded,
    IncorrectMeasurements,
}
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub enum GetMeasurementsError {
    NotFound,
}
