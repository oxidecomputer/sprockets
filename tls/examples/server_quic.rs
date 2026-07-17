// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example QUIC server that echoes back whatever was sent.
//!
//! The QUIC analog of the `server` example: identical CLI, but the transport
//! is a sprockets QUIC endpoint rather than a TCP listener.
use camino::Utf8PathBuf;
use clap::Parser;
use slog::{info, Drain};
use sprockets_tls::keys::{
    AttestConfig, MeasurementConnectionPolicy, ResolveSetting, SprocketsConfig,
};
use sprockets_tls::quic::Server;
use std::net::SocketAddrV6;
use std::str::FromStr;
use tokio::io::{copy, split, AsyncWriteExt};

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
        panic!("Must specify at least one root");
    }

    let listen_addr = SocketAddrV6::from_str(&args.addr).unwrap();

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

    let server_config = SprocketsConfig {
        attest,
        roots: args.roots,
        resolve,
        enforce: if args.enforce {
            MeasurementConnectionPolicy::Enforced
        } else {
            MeasurementConnectionPolicy::Permissive
        },
    };

    // Unlike the TCP `Server::new`, the QUIC constructor is synchronous; it
    // binds the UDP socket and spawns quinn's endpoint driver on the current
    // runtime.
    let server = Server::new(server_config, listen_addr, log.clone()).unwrap();

    loop {
        let (conn, _) = server
            .accept(args.corpus.clone())
            .await
            .unwrap()
            .handshake()
            .await
            .unwrap();
        let platform_id = conn.peer_platform_id().as_str();
        info!(log, "connected to attested peer: {platform_id}");

        // A handle on the quinn connection, kept to await the client's
        // departure below after `split` consumes the sprockets connection.
        let quinn_conn = conn.connection().clone();
        let (mut reader, mut writer) = split(conn);

        // A client that departs by closing the connection (rather than
        // finishing its stream) surfaces here as an error: that ends this
        // connection, not the server.
        match copy(&mut reader, &mut writer).await {
            Ok(n) => {
                // Finish the echo stream so the client reads EOF after the
                // last echoed byte, then hold the connection open until the
                // client has read everything and closed: dropping our handle
                // first could discard the in-flight echo tail (see the drop
                // semantics in the `quic` module docs).
                let _ = writer.shutdown().await;
                quinn_conn.closed().await;
                info!(log, "Echo: {}", n);
            }
            Err(e) => info!(log, "connection ended: {e}"),
        }
    }
}
