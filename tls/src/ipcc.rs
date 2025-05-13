// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Requests over IPCC (Inter Processor Communication Channel)
use attest_data::messages::{HostToRotCommand, HostToRotError, RotToHost};
use attest_data::Log;
use libipcc::{IpccError, IpccHandle};
use thiserror::Error;
use x509_cert::{
    der::{self, Decode, Encode, Reader},
    Certificate, PkiPath,
};

// A slight hack. These are only defined right now in the `ffi` part
// of libipcc which isn't available on non-illumos targets. Probably
// indicates those constants belong elsewhere...
const IPCC_MAX_DATA_SIZE: usize = 4123 - 19;

#[derive(Debug, Error)]
pub enum RotRequestError {
    #[error(transparent)]
    Ipcc(#[from] IpccError),
    #[error("Error from RotRequest call {0:?}")]
    RotRequest(HostToRotError),
    #[error("Bad sign length")]
    BadSignLen,
}

pub struct Ipcc {
    handle: IpccHandle,
}

impl Ipcc {
    /// Creates a new `Ipcc` instance.
    pub fn new() -> Result<Self, RotRequestError> {
        let handle = IpccHandle::new().map_err(RotRequestError::Ipcc)?;
        Ok(Self { handle })
    }

    pub fn rot_get_tq_cert_chain(&self) -> Result<Vec<u8>, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
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
        // We expect this to be a sha3_256 hash == 32 bytes
        if hash.len() != 32 {
            return Err(RotRequestError::BadSignLen);
        }
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
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

    pub fn get_measurement_log(&self) -> Result<Log, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
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

        // XXX FIXME
        let (log, _): (Log, _) = hubpack::deserialize(data).unwrap();

        Ok(log)
    }

    pub fn get_certificates(&self) -> Result<PkiPath, RotRequestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetCertificates,
            |_| 0,
        )
        .map_err(|e| RotRequestError::RotRequest(HostToRotError::from(e)))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let cert_chain_bytes = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotCertificates,
        )
        .map_err(RotRequestError::RotRequest)?;

        let mut idx = 0;

        let mut certs = PkiPath::new();
        // Turn the DER chain into something we can actually use
        while idx < cert_chain_bytes.len() {
            let reader =
                der::SliceReader::new(&cert_chain_bytes[idx..]).unwrap();
            let header = reader.peek_header().unwrap();
            // DER certificates are supposed to be a `Sequence`.
            // We could check that here but we're going to get better
            // error messages by letting the cert parsing code say
            // exactly what went wrong
            let seq_len: usize = header.length.try_into().unwrap();
            let tag_len: usize =
                header.encoded_len().unwrap().try_into().unwrap();
            // Total len = length from the sequence plus the tag itself
            let end = idx + seq_len + tag_len;

            certs.push(
                Certificate::from_der(&cert_chain_bytes[idx..end]).unwrap(),
            );
            idx += seq_len + tag_len;
        }

        Ok(certs)
    }
}
