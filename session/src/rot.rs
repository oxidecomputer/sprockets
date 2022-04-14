// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Trait for interacting with an RoT
//!
//! On a host, this will use the Uart.
//! On an SP, this will use SPI
//! For testing we will use mock implementations.

use sprockets_common::measurements::Measurements;
use sprockets_common::{Ed25519Signature, Nonce, Sha3_256Digest};

trait RoTMeasure {
    fn get_measurements(nonce: &Nonce) -> (Measurements, Ed25519Signature);
}

trait RotSign {
    fn sign_transcript(hash: Sha3_256Digest) -> Ed25519Signature;
}
