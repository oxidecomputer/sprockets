// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example IPCC client that echos out whatever it gets back
use camino::Utf8PathBuf;
use clap::Parser;
use slog::{info, Drain};
use sprockets_tls::client::Client;
use sprockets_tls::keys::{AttestConfig, ResolveSetting, SprocketsConfig};
use std::net::SocketAddrV6;
use std::str::FromStr;
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::io::{stdin as tokio_stdin, stdout as tokio_stdout};

#[derive(Debug, Parser)]
enum Setting {
    Ipcc,
    Local {
        /// TLS signing key used in Trust Quorum
        tq_priv_key: Utf8PathBuf,
        /// Cert chain for TLS signing key
        tq_cert_chain: Utf8PathBuf,
        /// Key used to sign the attestations produced by AttestMock
        attest_priv_key: Utf8PathBuf,
        /// Cert chain for attestation signing key
        attest_cert_chain: Utf8PathBuf,
        /// Measurement log produced by AttestMock
        log: Utf8PathBuf,
    },
}

#[derive(Debug, Parser)]
struct Args {
    /// Root Certificates
    #[clap(long)]
    roots: Vec<Utf8PathBuf>,
    #[clap(subcommand)]
    config: Setting,
    /// CBOR encoded CoRIM documents used as reference measurements in the
    /// attestation appraisal process
    #[clap(long)]
    corpus: Vec<Utf8PathBuf>,
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

    let (attest, resolve) = match args.config {
        Setting::Ipcc => (AttestConfig::Ipcc, ResolveSetting::Ipcc),
        Setting::Local {
            tq_priv_key,
            tq_cert_chain,
            attest_priv_key,
            attest_cert_chain,
            log,
        } => (
            AttestConfig::Local {
                priv_key: attest_priv_key,
                cert_chain: attest_cert_chain,
                log,
            },
            ResolveSetting::Local {
                priv_key: tq_priv_key,
                cert_chain: tq_cert_chain,
            },
        ),
    };

    let client_config = SprocketsConfig {
        attest,
        roots: args.roots,
        resolve,
    };

    let addr = SocketAddrV6::from_str(&args.addr).unwrap();

    let (stream, platform_id) =
        Client::connect(client_config, addr, args.corpus, log.clone())
            .await
            .unwrap();
    let platform_id = platform_id.as_str().unwrap();
    info!(log, "connected to attested peer: {platform_id}");

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
