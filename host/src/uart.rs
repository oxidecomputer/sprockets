// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Communicate to the SP over a UART.
//!
//! All messages sent to the local SP or RoT must go over this channel.

use serialport::{self, SerialPort};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("uart doesn't exist at specified path")]
pub struct UartDoesNotExist;

pub struct Uart {
    inner: Box<dyn SerialPort>,
}

impl Uart {
    // Attach to a uart device
    pub fn attach(device_path: &str, baud_rate: u32) -> Result<Uart, UartDoesNotExist> {
        let inner = serialport::new(device_path, baud_rate)
            .timeout(Duration::from_secs(3))
            .open()
            .map_err(|_| UartDoesNotExist)?;
        Ok(Uart { inner })
    }

    pub fn port(&mut self) -> &mut Box<dyn SerialPort> {
        &mut self.inner
    }
}
