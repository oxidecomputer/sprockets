// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.use derive_more::From;

// This is temporary until I use Phil's code on the RoT
#[cfg(feature = "rand")]
use rand::{rngs::OsRng, RngCore};

use serde::{Deserialize, Serialize};

pub mod certificates;
pub mod measurements;
pub mod msgs;

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
//
// TODO: If we are actually using this to generate a secret key it should
// probably use zeroize
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
use derive_more::From;
use hubpack::SerializedSize;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
