// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

// This is temporary until I use Phil's code on the RoT
#[cfg(feature = "rand")]
use rand::{rngs::OsRng, RngCore};

use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

pub mod certificates;
pub mod measurements;
pub mod msgs;

pub use measurements::Measurements;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub struct Ed25519PublicKey(pub [u8; 32]);

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    From,
    Serialize,
    Deserialize,
    SerializedSize,
)]
pub struct Ed25519Signature(#[serde(with = "BigArray")] pub [u8; 64]);

// Output of HMAC<Sha3_256>
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
pub struct HmacSha3_256(pub [u8; 32]);

#[derive(
    Default,
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
pub struct Sha3_256Digest(pub [u8; 32]);

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
pub struct Nonce(pub [u8; 32]);

// `Nonce` isn't a container, so `is_empty()` doesn't make sense; inform clippy
#[allow(clippy::len_without_is_empty)]
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

impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}

// Return 32-bytes of randomness for use in a Nonce or Secret Key
//
// TODO: If we are actually using this to generate a secret key it should
// probably use zeroize
#[cfg(feature = "rand")]
pub fn random_buf<const T: usize>() -> [u8; T] {
    let mut data = [0u8; T];
    OsRng.fill_bytes(&mut data);
    data
}

// This is temporary until I use Phil's hardware drivers
#[cfg(not(feature = "rand"))]
pub fn random_buf<const T: usize>() -> [u8; T] {
    [0u8; T]
}
