use camino::Utf8PathBuf;
use clap::Parser;
use slog::{info, Drain};
use sprockets_tls::server::{Server, SprocketsServerConfig};
use std::net::SocketAddrV6;
use std::str::FromStr;
/// Example IPCC server that echos back whatever was sent
use tokio::io::{copy, split, AsyncWriteExt};

#[derive(Debug, Parser)]
struct Args {
    /// PkiPath
    #[clap(long)]
    root: Vec<Utf8PathBuf>,
    #[clap(long, required = false)]
    cert_chain: Utf8PathBuf,
    /// Private key (local only)
    #[clap(long, required = false)]
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

    let listen_addr = SocketAddrV6::from_str(&args.addr).unwrap();

    let server_config = SprocketsServerConfig {
        roots: args.root,
        priv_key: args.priv_key,
        cert_chain: args.cert_chain,
        listen_addr,
    };

    let mut server = Server::listen_via_local_certs(server_config, log.clone())
        .await
        .unwrap();

    loop {
        let (stream, _) = server.accept().await.unwrap();
        let (mut reader, mut writer) = split(stream);
        let n = copy(&mut reader, &mut writer).await.unwrap();
        writer.flush().await.unwrap();
        info!(log, "Echo: {}", n);
    }
}
