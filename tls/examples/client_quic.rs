// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example QUIC client that echoes out whatever it gets back.
//!
//! The QUIC analog of the `client` example: identical CLI, but the transport
//! is a sprockets QUIC connection rather than TCP.
use camino::Utf8PathBuf;
use clap::Parser;
use slog::{info, Drain};
use sprockets_tls::keys::{
    AttestConfig, MeasurementConnectionPolicy, ResolveSetting, SprocketsConfig,
};
use sprockets_tls::quic::Client;
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
    /// Address and port to connect to
    #[clap(long)]
    addr: String,
    #[clap(long)]
    enforce: bool,
}

#[tokio::main]
async fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!("component" => "sprockets"));

    let args = Args::parse();

    if args.roots.is_empty() {
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
                test_corpus: vec![],
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
        enforce: if args.enforce {
            MeasurementConnectionPolicy::Enforced
        } else {
            MeasurementConnectionPolicy::Permissive
        },
    };

    let addr = SocketAddrV6::from_str(&args.addr).unwrap();

    let conn = Client::connect(client_config, addr, args.corpus, log.clone())
        .await
        .unwrap();
    let platform_id = conn.peer_platform_id().as_str();
    info!(log, "connected to attested peer: {platform_id}");

    let mut stdin = tokio_stdin();
    let (mut reader, mut writer) = split(conn);

    // Unlike the TCP client example's select!, the echo is drained to EOF
    // after stdin ends: exiting as soon as stdin closes would drop the
    // connection (close code 0) and could truncate the in-flight echo — see
    // the drop semantics in the `quic` module docs. Reading the server's
    // stream FIN is the application-level delivery acknowledgment.
    let stdout_task = tokio::spawn(async move {
        let mut stdout = tokio_stdout();
        let _ = copy(&mut reader, &mut stdout).await;
    });

    copy(&mut stdin, &mut writer).await.unwrap();
    writer.shutdown().await.unwrap();
    stdout_task.await.unwrap();
}
