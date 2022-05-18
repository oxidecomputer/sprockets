// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hyper::server::conn::AddrIncoming;
use hyper::service::make_service_fn;
use hyper::service::service_fn;
use hyper::Body;
use hyper::Request;
use hyper::Response;
use hyper::Server;
use hyper_sprockets::server::SprocketsAcceptor;
use slog::o;
use slog::Drain;
use slog::Logger;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

mod common;

use self::common::SimulatedRot;

const DEVICE_ID_SEED: [u8; 32] = *b"-sprockets-hyper-server-example-";

async fn hello_world(
    _req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    Ok(Response::new("Hello, World".into()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = Logger::root(drain, o!());

    // Simulate an RoT.
    let rot =
        SimulatedRot::new(DEVICE_ID_SEED, log.new(o!("context" => "sim-rot")));

    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // Standard TCP acceptor...
    let acceptor = AddrIncoming::bind(&addr)?;

    // ... wrapped in an adaptor that secures connections via sprockets.
    let acceptor = SprocketsAcceptor::new(
        acceptor,
        rot.manufacturing_public_key,
        rot.certs,
        rot.handle,
        Duration::from_secs(1), // simulated RoT never times out
    );

    // Always serve hello world
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(hello_world))
    });

    let server = Server::builder(acceptor).serve(make_svc);

    server.await?;

    Ok(())
}
