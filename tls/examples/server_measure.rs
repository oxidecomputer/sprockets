// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example IPCC server that echos back whatever was sent
use camino::Utf8PathBuf;
use clap::Parser;
use slog::{info, Drain};
use sprockets_tls::keys::{ResolveSetting, SprocketsConfig};
use sprockets_tls::server::Server;
use std::net::SocketAddrV6;
use std::str::FromStr;
use tokio::io::{copy, split, AsyncWriteExt};

#[derive(Debug, Parser)]
enum Setting {
    Ipcc,
    Local {
        priv_key: Utf8PathBuf,
        cert_chain: Utf8PathBuf,
    },
}

#[derive(Debug, Parser)]
struct Args {
    /// Root Certificates
    #[clap(long)]
    roots: Vec<Utf8PathBuf>,
    #[clap(subcommand)]
    resolve: Setting,
    /// Address and port to bind
    #[clap(long)]
    addr: String,
    #[clap(long)]
    /// Measurements
    measure: Vec<Utf8PathBuf>,
}

#[tokio::main]
async fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!("component" => "sprockets"));

    let args = Args::parse();

    if args.roots.is_empty() {
        panic!("Must specify at least one root");
    }

    let listen_addr = SocketAddrV6::from_str(&args.addr).unwrap();

    let server_config = SprocketsConfig {
        roots: args.roots,
        resolve: match args.resolve {
            Setting::Ipcc => ResolveSetting::Ipcc,
            Setting::Local {
                priv_key,
                cert_chain,
            } => ResolveSetting::Local {
                priv_key,
                cert_chain,
            },
        },
    };

    let mut server = Server::new(server_config, listen_addr, log.clone())
        .await
        .unwrap();

    loop {
        let (stream, _, platform_id) =
            server.accept_measured(&args.measure).await.unwrap();
        if let Some(id) = platform_id {
            info!(log, "Connection from peer {}", id);
        }
        let (mut reader, mut writer) = split(stream);
        let n = copy(&mut reader, &mut writer).await.unwrap();
        writer.flush().await.unwrap();
        info!(log, "Echo: {}", n);
    }
}
