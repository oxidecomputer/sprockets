// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use sprockets_common::certificates::Ed25519CertificatesError;

#[derive(Debug, PartialEq, Eq, From)]
pub enum Error {
    BadVersion,
    UnexpectedMsg,
    UnexpecteRotMsg,
    Hubpack(hubpack::error::Error),
    DecryptError,
    EncryptError,
    Certificates(Ed25519CertificatesError),
    BadMeasurementsSig,
    BadTranscriptSig,
    BadMac,
    BadNonce,
}
