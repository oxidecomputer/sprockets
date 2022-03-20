// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

use crate::keys::{Ed25519PublicKey, Ed25519Signature};

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
    device_id: Ed25519EndorsementV1,

    /// The endorsement by the DeviceId key for the Measurement key
    measurement: Ed25519EndorsementV1,

    /// The endorsement by the Measurement key for the DHE key
    dhe: Ed25519EndorsementV1,
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
