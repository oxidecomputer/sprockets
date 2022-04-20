// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chacha20poly1305::aead::heapless;
pub use hubpack::{deserialize, serialize, SerializedSize};

mod client;
pub use client::Client;
mod error;
mod handshake_state;
mod msgs;

pub use error::Error;

use handshake_state::MAX_HANDSHAKE_MSG_SIZE;
pub type Vec = heapless::Vec<u8, MAX_HANDSHAKE_MSG_SIZE>;
