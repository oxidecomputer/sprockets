// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example IPCC client that echos out whatever it gets back
use camino::Utf8PathBuf;
use clap::Parser;
use slog::Drain;
use sprockets_tls::client::{Client, SprocketsClientConfig};
use std::net::SocketAddrV6;
use std::str::FromStr;
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::io::{stdin as tokio_stdin, stdout as tokio_stdout};

#[derive(Debug, Parser)]
struct Args {
    /// Root Certificates
    #[clap(long)]
    root: Vec<Utf8PathBuf>,
    /// Certificate chain (local only)
    #[clap(long)]
    cert_chain: Utf8PathBuf,
    /// Private key (local only)
    #[clap(long)]
    priv_key: Utf8PathBuf,
    /// Address and port to bind
    #[clap(long)]
    addr: String,
}

#[tokio::main]
async fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!("component" => "sprockets"));

    let args = Args::parse();

    let addr = SocketAddrV6::from_str(&args.addr).unwrap();

    let client_config = SprocketsClientConfig {
        roots: args.root,
        priv_key: args.priv_key,
        cert_chain: args.cert_chain,
        addr,
    };

    let stream = Client::connect_via_local_certs(client_config, log.clone())
        .await
        .unwrap();

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());
    let (mut reader, mut writer) = split(stream);

    tokio::select! {
        ret = copy(&mut reader, &mut stdout) => {
            let _ = ret;
        },
        ret = copy(&mut stdin, &mut writer) => {
            ret.unwrap();
            writer.shutdown().await.unwrap()
        }
    }
}
