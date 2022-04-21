// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use chacha20poly1305::aead::heapless;
pub use hubpack::{deserialize, serialize, SerializedSize};

mod client;
pub use client::ClientHandshake;
mod error;
mod handshake_state;
mod msgs;
mod session;

pub use error::Error;
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

pub type Vec = heapless::Vec<u8, MAX_HANDSHAKE_MSG_SIZE>;

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
