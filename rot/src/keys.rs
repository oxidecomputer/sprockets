// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.use derive_more::From;

//! Generic NewTypes that can be used with multiple implementations of
//! crypto algorithms.

use derive_more::From;
use hubpack::SerializedSize;

// This is temporary until I use Phil's code
#[cfg(feature = "rand")]
use rand::{rngs::OsRng, RngCore};

use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

// Macro must be invoked to provide big array support for serde
big_array! { BigArray; }

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519PublicKey(pub [u8; 32]);

#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519SecretKey(pub [u8; 32]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519Signature(#[serde(with = "BigArray")] pub [u8; 64]);

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct Sha256Digest(pub [u8; 32]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Nonce(pub [u8; 32]);

impl Nonce {
    pub const SIZE: usize = 32;

    pub fn new() -> Nonce {
        Nonce(random_buf())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

// Return 32-bytes of randomness for use in a Nonce or Secret Key
#[cfg(feature = "rand")]
pub fn random_buf() -> [u8; 32] {
    let mut data = [0u8; 32];
    OsRng.fill_bytes(&mut data);
    data
}

// This is temporary until I use Phil's hardware drivers
#[cfg(not(feature = "rand"))]
pub fn random_buf() -> [u8; 32] {
    [0u8; 32]
}
