// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Messages used for setting up a trusted session

use derive_more::From;

pub use hubpack::{deserialize, serialize, SerializedSize};
use serde::{Deserialize, Serialize};
use sprockets_common::certificates::Ed25519Certificates;
use sprockets_common::measurements::Measurements;
use sprockets_common::{
    Ed25519PublicKey, Ed25519Signature, HmacSha3_256, Nonce,
};

/// Every version of the handshake message should start with a HandshakeVersion
///
/// As hubpack deterministically serializes bytes in order off the wire an
/// endpoint can always just deserialize the header if we need to later on verify
/// that it can handle the message.
///
/// By including the HandshakeVersion inside the message, we don't have to
/// serialize twice.
///
/// Alternatively we could have used an enum for versioning, but that requires
/// maintaining proper ordering and keeping around old versions forever, at
/// least as a placeholder variant. It also limits us to 256 versions based on
/// hubpack serialization decisions.
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
pub struct HandshakeVersion {
    pub version: u32,
}

/// A handshake request from one host to another
///
/// In an Oxide rack the sled-agents send these messages to each other over the
/// Bootsrap network.
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
pub struct HandshakeMsgV1 {
    // The header for all versions of a handshake message
    pub version: HandshakeVersion,

    /// The specific handshake message data
    pub data: HandshakeMsgDataV1,
}

impl HandshakeMsgV1 {
    pub fn new(data: HandshakeMsgDataV1) -> HandshakeMsgV1 {
        HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data,
        }
    }
}

/// The actual message contents of HandshakeMsgV1
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
#[allow(clippy::large_enum_variant)] // clippy suggests `Box`; we're no_std
pub enum HandshakeMsgDataV1 {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Identity(Identity),
    IdentityVerify(IdentityVerify),
    Finished(Finished),
}

/// The first message sent in a secure session handshake
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
pub struct ClientHello {
    pub nonce: Nonce,
    pub public_key: Ed25519PublicKey,
}

/// The first message sent by the server in a secure session handshake.
/// This is sent after the `ClientHello` is received.
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
pub struct ServerHello {
    pub nonce: Nonce,
    pub public_key: Ed25519PublicKey,
}

/// A message containing certs and measurements, along with a measurement
/// signature, sent by each side before that side sends any authentication messages.
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
pub struct Identity {
    pub certs: Ed25519Certificates,
    pub measurements: Measurements,
    pub measurements_sig: Ed25519Signature,
}

/// Prove to the the receiver that the sender possesses the private key
/// corresponding to the DHE cert sent in the Identity message.
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
pub struct IdentityVerify {
    pub transcript_signature: Ed25519Signature,
}

/// Authenticate the transcript hash with an HMAC
///
/// This is the final message of a handshake from a sender. After receipt and
/// verification of this message, the receiver trusts the sender.
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
pub struct Finished {
    pub mac: HmacSha3_256,
}
