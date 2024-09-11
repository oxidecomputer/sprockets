// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example IPCC client that echos out whatever it gets back
use camino::Utf8PathBuf;
use clap::Parser;
use slog::Drain;
use sprockets_tls::client::Client;
use sprockets_tls::keys::{ResolveSetting, SprocketsConfig};
use std::net::SocketAddrV6;
use std::str::FromStr;
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::io::{stdin as tokio_stdin, stdout as tokio_stdout};

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
}

#[tokio::main]
async fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!("component" => "sprockets"));

    let args = Args::parse();

    if args.roots.len() < 1 {
        panic!("Need at least one root");
    }

    let client_config = SprocketsConfig {
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

    let addr = SocketAddrV6::from_str(&args.addr).unwrap();

    let stream = Client::connect(client_config, addr, log.clone())
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
