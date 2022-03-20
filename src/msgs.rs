use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

// Macro must be invoked to provide big array support for serde
big_array! { BigArray; }

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519PublicKey([u8; 32]);

#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519SecretKey([u8; 32]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519Signature(#[serde(with = "BigArray")] [u8; 64]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Sha256Digest([u8; 32]);

/// A request to an RoT from an SP
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct RotRequest {
    /// A monotonic counter used to differentiate requests
    id: u32,

    // The version of this request format
    version: u32,

    // The operation requested of the RoT
    op: RotOpV1,
}

/// Requested operations of the RoT by the SP.
///
/// Note that these requests may be proxied for the sled-agent, or MGS, but
/// that is not relevant to the RoT.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotOpV1 {
    GetEndorsements,
    AddHostMeasurements,
    GetMeasurements,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct RotResponse {
    /// A monotonic counter used to differentiate requests
    id: u32,

    // The version of this request format
    version: u32,

    // The result of a requested operation from the RoT
    op: RotResultV1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum RotResultV1 {
    Endorsements(Result<Ed25519EndorsementsV1, GetEndorsementsError>),
    AddHostMeasurementsReply(Result<(), AddHostMeasurementsError>),
    Measurements(Result<MeasurementsV1, GetMeasurementsError>),
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct MeasurementsV1 {
    rot: RotMeasurementsV1,
    sp: SpMeasurementsV1,
    hbs: HbsMeasurementsV1,
    host: HostMeasurementsV1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct RotMeasurementsV1 {
    tcb: Sha256Digest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct SpMeasurementsV1 {
    tcb: Sha256Digest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct HbsMeasurementsV1 {
    tcb: Sha256Digest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct HostMeasurementsV1 {
    tcb: Sha256Digest,
}

//#[derive(
//  Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
//)]
/// All allowable hashes for a given version of sw/hw.
pub struct MeasurementCorpusV1 {}

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
    serial_number: SerialNumber,

    /// The endorsement by the Manufacturing key for the DeviceId key
    device_id: Ed25519Endorsement,

    /// The endorsement by the DeviceId key for the Measurement key
    measurement: Ed25519Endorsement,

    /// The endorsement by the Measurement key for the DHE key
    dhe: Ed25519Endorsement,
}

/// A signature of a public key by a private key higher up the chain of trust.
///
/// This is a simplified replacement for x.509v3 certs that is suitable for
/// constrained devices.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519Endorsement {
    subject_key_type: KeyType,
    subject_public_key: Ed25519PublicKey,
    signer_key_type: KeyType,
    signature: Ed25519Signature,
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
