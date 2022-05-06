// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use chacha20poly1305::aead::heapless;
use derive_more::From;
use ed25519;
use ed25519_dalek;
pub use hubpack::{deserialize, serialize, SerializedSize};
use sprockets_common::certificates::Ed25519Verifier;
use sprockets_common::msgs::RotOpV1;
use sprockets_common::{Ed25519PublicKey, Ed25519Signature};

mod client;
mod error;
mod handshake_state;
mod msgs;
mod server;
mod session;

pub use chacha20poly1305::aead::Buffer;
pub use chacha20poly1305::Tag;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use chacha20poly1305::aead::generic_array;
pub use chacha20poly1305::aead::AeadCore;
pub use client::ClientHandshake;
pub use error::Error;
pub use msgs::Identity;
pub use server::ServerHandshake;
pub use session::Session;

use crate::msgs::HandshakeMsgV1;

// The length of the nonce for ChaCha20Poly1305
pub const NONCE_LEN: usize = 12;

// The length of a digest or nonce as a big endian u16
pub const ENCODED_LEN: usize = 2;

// The length of a SHA3-256 digest
pub const DIGEST_LEN: usize = 32;

// The length of a ChaCha20Poly1305 Key
pub const KEY_LEN: usize = 32;

// The length of a ChaCha20Poly1305 authentication tag
pub const TAG_LEN: usize = 16;

pub const MAX_HANDSHAKE_MSG_SIZE: usize = HandshakeMsgV1::MAX_SIZE + TAG_LEN;

pub type HandshakeMsgVec = heapless::Vec<u8, MAX_HANDSHAKE_MSG_SIZE>;

// Is endpoint a client or server
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Role {
    Client,
    Server,
}

impl Role {
    // Return the role of the peer
    //
    // Happy Opposite Day!
    fn peer(&self) -> Role {
        match self {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }
}

// Return a 2-byte big endian encoded buf containing digest size
pub(crate) fn digest_len_buf() -> [u8; ENCODED_LEN] {
    let digest_len = u16::try_from(DIGEST_LEN).unwrap();
    digest_len.to_be_bytes()
}

// Return a 2 byte big endian encoded buf containing nonce size
//
// Note that nonce size = iv size
pub(crate) fn nonce_len_buf() -> [u8; ENCODED_LEN] {
    let nonce_len = u16::try_from(NONCE_LEN).unwrap();
    nonce_len.to_be_bytes()
}

/// A token that allows calling the `handle` method of a `ClientHandshake`
#[derive(Debug)]
pub struct RecvToken(usize);

impl RecvToken {
    fn new() -> RecvToken {
        RecvToken(0)
    }
}

/// A token that allows calling the `next_msg` method of a `ClientHandshake`
#[derive(Debug)]
pub struct SendToken(usize);

impl SendToken {
    fn new() -> SendToken {
        SendToken(0)
    }
}

/// A token that allows calling the `new_session` method of a `ClientHandshake`
#[derive(Debug)]
pub struct CompletionToken(Identity);

impl CompletionToken {
    fn new(remote_identity: Identity) -> CompletionToken {
        CompletionToken(remote_identity)
    }

    /// Retrieve the remote identity that was verified during the handshake.
    ///
    /// If we were the client, this is the identity of the server (and vice
    /// versa).
    pub fn remote_identity(&self) -> &Identity {
        &self.0
    }
}

/// This is the return value from a Client operation. It instructs the user what
/// to do next.
#[derive(Debug, From)]
pub enum UserAction {
    /// The user should receive a message over the transport and then call
    /// `handle`.
    Recv(RecvToken),

    /// The user should call the `next_msg` method to provide a message to be
    /// sent over the transport.
    Send(SendToken),

    /// The user should send the included `RotRequest` to the RoT and then call
    /// `handle_rot_result` with the reply received from the RoT.
    SendToRot(RotOpV1),

    /// The handshake is complete and the user should call the `new_session`
    /// method to get back a `Session` object that can be used to encrypt
    /// application messages to send and decrypt received application messages.
    Complete(CompletionToken),
}

pub(crate) struct DalekVerifier;

impl Ed25519Verifier for DalekVerifier {
    fn verify(
        &self,
        signer_public_key: &Ed25519PublicKey,
        msg: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), ()> {
        let public_key =
            ed25519_dalek::PublicKey::from_bytes(&signer_public_key.0).unwrap();
        let signature = ed25519::Signature::from_bytes(&signature.0).unwrap();
        public_key.verify_strict(msg, &signature).map_err(|_| ())?;
        Ok(())
    }
}
