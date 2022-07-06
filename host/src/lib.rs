// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod rot_manager;
mod session;

#[cfg(feature = "uart")]
pub mod uart;

pub use sprockets_common::certificates::Ed25519Certificate;
pub use sprockets_common::certificates::Ed25519Certificates;
pub use sprockets_common::msgs::RotOpV1;
pub use sprockets_common::msgs::RotRequestV1;
pub use sprockets_common::msgs::RotResponseV1;
pub use sprockets_common::msgs::RotResultV1;
pub use sprockets_common::Ed25519PublicKey;
pub use sprockets_session::Identity;

pub use self::rot_manager::RotManager;
pub use self::rot_manager::RotManagerError;
pub use self::rot_manager::RotManagerHandle;
pub use self::rot_manager::RotTransport;
pub use self::session::Session;
pub use self::session::SessionError;
pub use self::session::SessionHandshakeError;
