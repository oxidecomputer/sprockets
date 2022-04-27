// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use hubpack::{serialize, SerializedSize};
use serde::{Deserialize, Serialize};

use crate::certificates::SerialNumber;
use crate::{Nonce, Sha3_256Digest};

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct Measurements {
    pub serial_number: SerialNumber,
    pub rot: Option<RotMeasurements>,
    pub sp: Option<SpMeasurements>,
    pub hbs: Option<HbsMeasurements>,
    pub host: Option<HostMeasurements>,
}

impl Measurements {
    /// Serialize the measurements and concatenate with a nonce in the buffer.
    /// This is useful for signing and verification.
    pub fn serialize_with_nonce(
        &self,
        nonce: &Nonce,
        out: &mut [u8],
    ) -> hubpack::error::Result<usize> {
        let size = serialize(out, self).unwrap();
        out[size..size + nonce.len()].copy_from_slice(nonce.as_slice());
        Ok(size + nonce.len())
    }
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct RotMeasurements {
    pub tcb: Sha3_256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct SpMeasurements {
    pub tcb: Sha3_256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct HbsMeasurements {
    pub tcb: Sha3_256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct HostMeasurements {
    pub tcb: Sha3_256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
/// All allowable hashes for a given version of sw/hw.
pub struct MeasurementCorpus {
    measurements: [Measurements; 1],
}
