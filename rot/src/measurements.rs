// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

use crate::endorsements::SerialNumber;
use crate::keys::Sha256Digest;

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct MeasurementsV1 {
    pub serial_number: SerialNumber,
    pub rot: Option<RotMeasurementsV1>,
    pub sp: Option<SpMeasurementsV1>,
    pub hbs: Option<HbsMeasurementsV1>,
    pub host: Option<HostMeasurementsV1>,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct RotMeasurementsV1 {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct SpMeasurementsV1 {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct HbsMeasurementsV1 {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
pub struct HostMeasurementsV1 {
    pub tcb: Sha256Digest,
}

#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize,
)]
/// All allowable hashes for a given version of sw/hw.
pub struct MeasurementCorpusV1 {
    measurements: [MeasurementsV1; 1],
}
