// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! An interface to libipcc (inter-processor communications channel) which
//! currently supports looking up values stored in the SP by key. These
//! values are variously static, passed from the control plane to the SP
//! (through MGS) or set from userland via libipcc.

use attest_data::messages::{HostToRotCommand, HostToRotError, RotToHost};
use cfg_if::cfg_if;
use thiserror::Error;

cfg_if! {
    if #[cfg(target_os = "illumos")] {
        mod ffi;
        mod handle;
        use handle::IpccHandle;
    } else {
        mod handle_stub;
        use handle_stub::IpccHandle;
    }
}

#[derive(Debug, Error)]
pub enum RotRequestError {
    #[error(transparent)]
    Ipcc(#[from] IpccError),
    #[error("Error from RotRequest call {0:?}")]
    RotRequest(HostToRotError),
}

#[derive(Error, Debug)]
pub enum IpccError {
    #[error("Memory allocation error")]
    NoMem(#[source] IpccErrorInner),
    #[error("Invalid parameter")]
    InvalidParam(#[source] IpccErrorInner),
    #[error("Internal error occurred")]
    Internal(#[source] IpccErrorInner),
    #[error("Requested lookup key was not known to the SP")]
    KeyUnknown(#[source] IpccErrorInner),
    #[error("Value for the requested lookup key was too large for the supplied buffer")]
    KeyBufTooSmall(#[source] IpccErrorInner),
    #[error("Attempted to write to read-only key")]
    KeyReadonly(#[source] IpccErrorInner),
    #[error("Attempted write to key failed because the value is too long")]
    KeyValTooLong(#[source] IpccErrorInner),
    #[error("Compression or decompression failed")]
    KeyZerr(#[source] IpccErrorInner),
    #[error("Unknown libipcc error")]
    UnknownErr(#[source] IpccErrorInner),
}

#[derive(Error, Debug)]
#[error("{context}: {errmsg} ({syserr})")]
pub struct IpccErrorInner {
    pub context: String,
    pub errmsg: String,
    pub syserr: String,
}

/// Interface to the inter-processor communications channel.
/// For more information see rfd 316.
pub struct Ipcc {
    handle: IpccHandle,
}

impl Ipcc {
    /// Creates a new `Ipcc` instance.
    pub fn new() -> Result<Self, IpccError> {
        let handle = IpccHandle::new()?;
        Ok(Self { handle })
    }

    /// Makes a request to the RoT. The details of the request are
    /// entirely opaque and are expected to be ecoded elsewhere per
    /// RFD 497
    pub fn rot_get_cert_chain(&self) -> Result<Vec<u8>, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; ffi::IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetCertificates,
            |_| 0,
        )
        .map_err(|e| RotRequestError::RotRequest(HostToRotError::from(e)))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotCertificates,
        )
        .map_err(RotRequestError::RotRequest)?;
        Ok(data.to_vec())
    }

    pub fn rot_get_measurement_log(&self) -> Result<Vec<u8>, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; ffi::IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetMeasurementLog,
            |_| 0,
        )
        .map_err(|e| RotRequestError::RotRequest(HostToRotError::from(e)))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotMeasurementLog,
        )
        .map_err(RotRequestError::RotRequest)?;
        Ok(data.to_vec())
    }

    pub fn rot_attest(&self, nonce: &[u8]) -> Result<Vec<u8>, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; ffi::IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::Attest,
            |buf| {
                buf[..nonce.len()].copy_from_slice(nonce);
                nonce.len()
            },
        )
        .map_err(|e| RotRequestError::RotRequest(HostToRotError::from(e)))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotAttestation,
        )
        .map_err(RotRequestError::RotRequest)?;
        Ok(data.to_vec())
    }

    pub fn rot_get_tq_cert_chain(&self) -> Result<Vec<u8>, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; ffi::IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetTqCertificates,
            |_| 0,
        )
        .map_err(|e| RotRequestError::RotRequest(HostToRotError::from(e)))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotTqCertificates,
        )
        .map_err(RotRequestError::RotRequest)?;
        Ok(data.to_vec())
    }

    pub fn rot_tq_sign(&self, hash: &[u8]) -> Result<Vec<u8>, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; ffi::IPCC_MAX_DATA_SIZE];
        println!("hmmm? {} {}", rot_message.len(), hash.len());
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::TqSign,
            |buf| {
                buf[..hash.len()].copy_from_slice(hash);
                hash.len()
            },
        )
        .map_err(|e| RotRequestError::RotRequest(HostToRotError::from(e)))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotTqSign,
        )
        .map_err(RotRequestError::RotRequest)?;
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_strategy::proptest;

    #[proptest]
    fn installinator_image_id_round_trip(image_id: InstallinatorImageId) {
        let serialized = image_id.serialize();
        assert_eq!(
            InstallinatorImageId::deserialize(&serialized),
            Ok(image_id)
        );
    }

    #[proptest]
    fn serialized_size(image_id: InstallinatorImageId) {
        let serialized = image_id.serialize();
        assert!(serialized.len() == InstallinatorImageId::CBOR_SERIALIZED_SIZE);
    }

    #[test]
    fn deserialize_fixed_value() {
        // Encoding an `InstallinatorImageId` at https://cbor.me with the
        // host_phase_2 hash [1, 2, ..., 32] and the control_plane hash [33, 34,
        // ..., 64]:
        const SERIALIZED: &[u8] = &[
            0xA3, // map(3)
            0x69, // text(9)
            0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x69,
            0x64, // "update_id"
            0x50, // bytes(16),
            0x41, // byte(65)
            0x42, // byte(66)
            0x43, // byte(67)
            0x44, // byte(68)
            0x45, // byte(69)
            0x46, // byte(70)
            0x47, // byte(71)
            0x48, // byte(72)
            0x49, // byte(73)
            0x4a, // byte(74)
            0x4b, // byte(75)
            0x4c, // byte(76)
            0x4d, // byte(77)
            0x4e, // byte(78)
            0x4f, // byte(79)
            0x50, // byte(80)
            0x6C, // text(12)
            0x68, 0x6F, 0x73, 0x74, 0x5F, 0x70, 0x68, 0x61, 0x73, 0x65, 0x5F,
            0x32, // "host_phase_2"
            0x58, 0x20, // bytes(32)
            0x01, // unsigned(1)
            0x02, // unsigned(2)
            0x03, // unsigned(3)
            0x04, // unsigned(4)
            0x05, // unsigned(5)
            0x06, // unsigned(6)
            0x07, // unsigned(7)
            0x08, // unsigned(8)
            0x09, // unsigned(9)
            0x0A, // unsigned(10)
            0x0B, // unsigned(11)
            0x0C, // unsigned(12)
            0x0D, // unsigned(13)
            0x0E, // unsigned(14)
            0x0F, // unsigned(15)
            0x10, // unsigned(16)
            0x11, // unsigned(17)
            0x12, // unsigned(18)
            0x13, // unsigned(19)
            0x14, // unsigned(20)
            0x15, // unsigned(21)
            0x16, // unsigned(22)
            0x17, // unsigned(23)
            0x18, // unsigned(24)
            0x19, // unsigned(25)
            0x1A, // unsigned(26)
            0x1B, // unsigned(27)
            0x1C, // unsigned(28)
            0x1D, // unsigned(29)
            0x1E, // unsigned(30)
            0x1F, // unsigned(31)
            0x20, // unsigned(32)
            0x6D, // text(13)
            0x63, 0x6F, 0x6E, 0x74, 0x72, 0x6F, 0x6C, 0x5F, 0x70, 0x6C, 0x61,
            0x6E, 0x65, // "control_plane"
            0x58, 0x20, // bytes(32)
            0x21, // unsigned(33)
            0x22, // unsigned(34)
            0x23, // unsigned(35)
            0x24, // unsigned(36)
            0x25, // unsigned(37)
            0x26, // unsigned(38)
            0x27, // unsigned(39)
            0x28, // unsigned(40)
            0x29, // unsigned(41)
            0x2A, // unsigned(42)
            0x2B, // unsigned(43)
            0x2C, // unsigned(44)
            0x2D, // unsigned(45)
            0x2E, // unsigned(46)
            0x2F, // unsigned(47)
            0x30, // unsigned(48)
            0x31, // unsigned(49)
            0x32, // unsigned(50)
            0x33, // unsigned(51)
            0x34, // unsigned(52)
            0x35, // unsigned(53)
            0x36, // unsigned(54)
            0x37, // unsigned(55)
            0x38, // unsigned(56)
            0x39, // unsigned(57)
            0x3A, // unsigned(58)
            0x3B, // unsigned(59)
            0x3C, // unsigned(60)
            0x3D, // unsigned(61)
            0x3E, // unsigned(62)
            0x3F, // unsigned(63)
            0x40, // unsigned(64)
        ];

        let expected = InstallinatorImageId {
            update_id: Uuid::from_bytes([
                65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
            ]),
            host_phase_2: ArtifactHash([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            control_plane: ArtifactHash([
                33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
            ]),
        };

        assert_eq!(InstallinatorImageId::deserialize(SERIALIZED), Ok(expected));
    }
}
