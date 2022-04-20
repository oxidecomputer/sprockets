// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
pub use hubpack::{deserialize, serialize, SerializedSize};
use serde::{Deserialize, Serialize};

mod uart;

pub use uart::Uart;

/// Every version of the handshake message should start with a HandshakeVersion
///
/// As hubpack deterministically serializes bytes in order off the wire an
/// endpoint can always just deserialize the header if we need to later on to verify
/// that it can handle the message.
///
/// By including the HandshakeVersion inside the message, we don't have to
/// serialize twice.
///
/// Alternatively we could have used an enum for versioning, but that requires
/// maintaining proper ordering and keeping around old versions forever, at
/// least as a placeholder variant. It also limits us to 256 versions based on
/// hubpack serialization decisions.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct HandshakeVersion {
    version: u32,
}

/// A handshake request from one host to another
///
/// In an Oxide rack the sled-agents send these messages to each other over the
/// Bootsrap network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct HandshakeMsgV1 {
    // The header for all versions of a handshake message
    pub version: HandshakeVersion,

    /// A monotonic counter used to differentiate requests
    pub id: u32,

    /// The specific handshake message data
    pub data: HandshakeMsgDataV1,
}

/// The actual message contents of HandshakeMsgV1
#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub enum HandshakeMsgDataV1 {
    ClientHello,
    ServerHello,
    Identity,
    IdentityVerify,
    Finished,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
