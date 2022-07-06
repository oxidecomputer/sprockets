// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hyper::body::HttpBody;
use hyper::client::HttpConnector;
use hyper::Body;
use hyper::Client;
use hyper_sprockets::client::SprocketsConnector;
use slog::o;
use slog::Drain;
use slog::Logger;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

mod common;

use self::common::SimulatedRot;

const DEVICE_ID_SEED: [u8; 32] = *b"-sprockets-hyper-client-example-";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = Logger::root(drain, o!());

    // Simulate an RoT.
    let rot =
        SimulatedRot::new(DEVICE_ID_SEED, log.new(o!("context" => "sim-rot")));

    // Wrap a hyper HttpConnector in our sprockets adaptor.
    let connector = SprocketsConnector::new(
        HttpConnector::new(),
        rot.certs,
        rot.handle,
        Duration::from_secs(1), // simulated RoT never times out
    );

    let client = Client::builder().build::<_, Body>(connector);

    let uri = "http://127.0.0.1:3000".parse()?;

    let mut resp = client.get(uri).await?;

    println!("Response: {}", resp.status());
    while let Some(chunk) = resp.body_mut().data().await {
        tokio::io::stdout().write_all(&chunk?).await?;
    }

    Ok(())
}
