// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use slog::Logger;
use sprockets_common::msgs::RotResponseV1;
use sprockets_common::random_buf;
use sprockets_host::Ed25519Certificates;
use sprockets_host::Ed25519PublicKey;
use sprockets_host::RotManager;
use sprockets_host::RotManagerHandle;
use sprockets_host::RotTransport;
use sprockets_rot::RotConfig;
use sprockets_rot::RotSprocket;
use sprockets_rot::RotSprocketError;
use std::collections::VecDeque;
use std::thread;
use thiserror::Error;

// Hardcoded key common between `hyper-client` and `hyper-server`.
const MANUFACTURING_SEED: [u8; 32] = *b"-sprockets-manufacturing-shared-";

pub(super) struct SimulatedRot {
    pub(super) manufacturing_public_key: Ed25519PublicKey,
    pub(super) certs: Ed25519Certificates,
    pub(super) handle: RotManagerHandle<TransportError>,
}

impl SimulatedRot {
    pub(super) fn new(device_id: [u8; 32], log: Logger) -> Self {
        let manufacturing_keypair = salty::Keypair::from(&MANUFACTURING_SEED);
        let rot = RotSprocket::new(RotConfig::bootstrap_for_testing(
            &manufacturing_keypair,
            salty::Keypair::from(&device_id),
            sprockets_common::certificates::SerialNumber(random_buf()),
        ));
        let certs = rot.get_certificates();
        let transport = Transport::new(rot);

        let (manager, handle) = RotManager::new(1, transport, log);
        thread::spawn(move || manager.run());

        Self {
            manufacturing_public_key: Ed25519PublicKey(
                manufacturing_keypair.public.to_bytes(),
            ),
            certs,
            handle,
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub(super) enum TransportError {
    #[error("recv called without a corresponding send")]
    RecvWithoutSend,
    #[error("RoT sprocket failure: {0:?}")]
    RotSprocketError(RotSprocketError),
}

pub(super) struct Transport {
    responses: VecDeque<Result<RotResponseV1, RotSprocketError>>,
    rot: RotSprocket,
}

impl Transport {
    fn new(rot: RotSprocket) -> Self {
        Self {
            rot,
            responses: VecDeque::new(),
        }
    }
}

impl RotTransport for Transport {
    type Error = TransportError;

    fn send(
        &mut self,
        req: sprockets_common::msgs::RotRequestV1,
        _deadline: std::time::Instant,
    ) -> Result<(), Self::Error> {
        self.responses.push_back(self.rot.handle_deserialized(req));
        Ok(())
    }

    fn recv(
        &mut self,
        _deadline: std::time::Instant,
    ) -> Result<sprockets_common::msgs::RotResponseV1, Self::Error> {
        let resp = self
            .responses
            .pop_front()
            .ok_or(TransportError::RecvWithoutSend)?;
        resp.map_err(TransportError::RotSprocketError)
    }
}
