// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use clap::ValueEnum;
use slog::info;
use slog::o;
use slog::Drain;
use slog::Logger;
use sprockets_common::msgs::RotResponseV1;
use sprockets_common::random_buf;
use sprockets_host::Ed25519Certificates;
use sprockets_host::RotManager;
use sprockets_host::RotManagerHandle;
use sprockets_host::RotTransport;
use sprockets_proxy::Config;
use sprockets_proxy::Proxy;
use sprockets_rot::RotConfig;
use sprockets_rot::RotSprocket;
use sprockets_rot::RotSprocketError;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    bind_address: SocketAddr,
    #[clap(long)]
    target_address: SocketAddr,
    #[clap(long, value_enum)]
    role: Role,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
enum Role {
    Client,
    Server,
}

impl From<Role> for sprockets_proxy::Role {
    fn from(role: Role) -> Self {
        match role {
            Role::Client => sprockets_proxy::Role::Client,
            Role::Server => sprockets_proxy::Role::Server,
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = Logger::root(drain, o!());

    let rot = SimulatedRot::new(
        random_buf(),
        log.new(o!("component" => "simulated-rot")),
    );

    let proxy = match Proxy::new(
        &Config {
            bind_address: args.bind_address,
            target_address: args.target_address,
            role: args.role.into(),
        },
        rot.handle,
        rot.certs,
        Duration::ZERO,
        log.new(o!("component" => "proxy")),
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(err) => {
            eprintln!("failed to start proxy: {}", err);
            return;
        }
    };

    info!(log, "sprockets proxy listening on {}", proxy.local_addr());

    if let Err(err) = proxy.run().await {
        eprintln!("proxy failed: {}", err);
    }
}

const MANUFACTURING_SEED: [u8; 32] = *b"sprocksy-demo-manufacturing-seed";

struct SimulatedRot {
    certs: Ed25519Certificates,
    handle: RotManagerHandle<TransportError>,
}

impl SimulatedRot {
    fn new(device_id: [u8; 32], log: Logger) -> Self {
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

        Self { certs, handle }
    }
}

#[derive(Debug, Error, PartialEq)]
enum TransportError {
    #[error("recv called without a corresponding send")]
    RecvWithoutSend,
    #[error("RoT sprocket failure: {0:?}")]
    RotSprocketError(RotSprocketError),
}

struct Transport {
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
