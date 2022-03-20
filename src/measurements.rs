// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

use crate::endorsements::SerialNumber;
use crate::keys::Sha256Digest;

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct MeasurementsV1 {
    serial_number: SerialNumber,
    rot: RotMeasurementsV1,
    sp: SpMeasurementsV1,
    hbs: HbsMeasurementsV1,
    host: HostMeasurementsV1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct RotMeasurementsV1 {
    tcb: Sha256Digest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct SpMeasurementsV1 {
    tcb: Sha256Digest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct HbsMeasurementsV1 {
    tcb: Sha256Digest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct HostMeasurementsV1 {
    tcb: Sha256Digest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
/// All allowable hashes for a given version of sw/hw.
pub struct MeasurementCorpusV1 {
    measurements: [MeasurementsV1; 1],
}
