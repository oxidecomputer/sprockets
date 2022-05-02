// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Communicate to the SP over a UART.
//!
//! All messages sent to the local SP or RoT must go over this channel.

use corncobs::{self, CobsError};
use hubpack::{deserialize, serialize, SerializedSize};
use serialport::{self, SerialPort};
use sprockets_common::msgs::{RotRequestV1, RotResponseV1};
use std::time::Duration;
use thiserror::Error;

pub struct Uart {
    inner: Box<dyn SerialPort>,
}

#[derive(Error, Debug)]
pub enum AttachError {
    #[error("uart doesn't exist at specified path")]
    DoesNotExist,
    #[error("serial port clear error: {0}")]
    SerialPort(#[from] serialport::Error),
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("hubpack serialization error: {0}")]
    Hubpack(#[from] hubpack::error::Error),
    #[error("serial port write_all error: {0}")]
    SerialPort(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum RecvError {
    #[error("hubpack deserialization error: {0}")]
    Hubpack(#[from] hubpack::error::Error),
    #[error("serial port read error: {0}")]
    SerialPortIoError(#[from] std::io::Error),
    #[error("serial port attach error: {0}")]
    SerialPortAttachError(#[from] serialport::Error),

    #[error("message exceeds maximum COBS encoded size")]
    MsgTooLarge,
    #[error("message is not COBS encoded: {0}")]
    Cobs(#[from] CobsError),
}

impl Uart {
    // Attach to a uart device
    pub fn attach(
        device_path: &str,
        baud_rate: u32,
    ) -> Result<Uart, AttachError> {
        let inner = serialport::new(device_path, baud_rate)
            .timeout(Duration::from_secs(3))
            .open()?;

        Ok(Uart { inner })
    }

    // Send an RotRequest over the UART, where it will be proxied by the SP and
    // eventually reach the RoT.
    pub fn send(&mut self, req: RotRequestV1) -> Result<(), SendError> {
        let mut req_buf = [0u8; RotRequestV1::MAX_SIZE];
        let size = serialize(&mut req_buf, &req)?;
        let mut encoded_buf =
            [0xFFu8; corncobs::max_encoded_len(RotRequestV1::MAX_SIZE)];
        let size = corncobs::encode_buf(&req_buf[..size], &mut encoded_buf);
        let _ = self.inner.write_all(&encoded_buf[..size])?;
        Ok(())
    }

    // Receive a response to the prior request.
    pub fn recv(&mut self) -> Result<RotResponseV1, RecvError> {
        let mut encoded_rsp_buf =
            [0xFFu8; corncobs::max_encoded_len(RotResponseV1::MAX_SIZE)];
        let mut pos = 0;
        // TODO: Should we wait between reads or timeout if a COBS message isn't
        // received in time?
        loop {
            let bytes_read = self.inner.read(&mut encoded_rsp_buf[pos..])?;
            // The last byte should always be a 0
            pos += bytes_read;
            if encoded_rsp_buf[pos - 1] == 0 {
                break;
            } else {
                if pos == encoded_rsp_buf.len() {
                    return Err(RecvError::MsgTooLarge);
                }
            }
        }

        let mut rsp_buf = [0u8; RotResponseV1::MAX_SIZE];
        let size = corncobs::decode_buf(&encoded_rsp_buf[..pos], &mut rsp_buf)?;

        let (response, _) = deserialize::<RotResponseV1>(&rsp_buf[..size])?;
        Ok(response)
    }
}
