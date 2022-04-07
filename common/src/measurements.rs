// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

use crate::certificates::SerialNumber;
use crate::Sha256Digest;

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

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct RotMeasurements {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct SpMeasurements {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct HbsMeasurements {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct HostMeasurements {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
/// All allowable hashes for a given version of sw/hw.
pub struct MeasurementCorpus {
    measurements: [Measurements; 1],
}
