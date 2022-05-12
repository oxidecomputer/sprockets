#![no_main]
use libfuzzer_sys::fuzz_target;

use slog::o;
use slog::Drain;
use slog::Logger;
use sprockets_common::certificates::SerialNumber;
use sprockets_common::msgs::RotRequestV1;
use sprockets_common::msgs::RotResponseV1;
use sprockets_common::random_buf;
use sprockets_host::Ed25519PublicKey;
use sprockets_host::RotManager;
use sprockets_host::RotTransport;
use sprockets_host::Session;
use sprockets_rot::RotConfig;
use sprockets_rot::RotSprocket;
use std::convert::Infallible;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::DuplexStream;
use tokio::runtime::Runtime;

fn test_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!("ctx" => "test"))
}

fn new_rot(manufacturing_keypair: &salty::Keypair) -> RotSprocket {
    RotSprocket::new(RotConfig::bootstrap_for_testing(
        &manufacturing_keypair,
        salty::Keypair::from(&random_buf()),
        SerialNumber(random_buf()),
    ))
}

struct TestTransport {
    rot: RotSprocket,
    req: Option<RotRequestV1>,
}

impl TestTransport {
    fn from_manufacturing_keypair(
        manufacturing_keypair: &salty::Keypair,
    ) -> Self {
        TestTransport {
            rot: new_rot(manufacturing_keypair),
            req: None,
        }
    }
}

impl RotTransport for TestTransport {
    type Error = Infallible;

    fn send(
        &mut self,
        req: RotRequestV1,
        _: Instant,
    ) -> Result<(), Self::Error> {
        self.req = Some(req);
        Ok(())
    }

    fn recv(&mut self, _: Instant) -> Result<RotResponseV1, Self::Error> {
        Ok(self
            .rot
            .handle_deserialized(self.req.take().unwrap())
            .unwrap())
    }
}

async fn bootstrap() -> (Session<DuplexStream>, Session<DuplexStream>) {
    let manufacturing_keypair = salty::Keypair::from(&random_buf());
    let manufacturing_public_key =
        Ed25519PublicKey(manufacturing_keypair.public.to_bytes());

    let client_rot =
        TestTransport::from_manufacturing_keypair(&manufacturing_keypair);
    let server_rot =
        TestTransport::from_manufacturing_keypair(&manufacturing_keypair);

    let client_certs = client_rot.rot.get_certificates();
    let server_certs = server_rot.rot.get_certificates();

    let logger = test_logger();

    let (client_mgr, client_handle) =
        RotManager::new(32, client_rot, logger.clone());
    let (server_mgr, server_handle) = RotManager::new(32, server_rot, logger);

    thread::spawn(move || client_mgr.run());
    thread::spawn(move || server_mgr.run());

    let (client_stream, server_stream) = tokio::io::duplex(1024);

    let client_fut = Session::new_client(
        client_stream,
        manufacturing_public_key,
        &client_handle,
        client_certs,
        Duration::from_secs(10),
    );
    let server_fut = Session::new_server(
        server_stream,
        manufacturing_public_key,
        &server_handle,
        server_certs,
        Duration::from_secs(10),
    );

    let (client, server) = tokio::join!(client_fut, server_fut);
    let client = client.unwrap();
    let server = server.unwrap();

    client_handle.shutdown().await;
    server_handle.shutdown().await;

    (client, server)
}

fuzz_target!(|data: &[u8]| {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let (client, server) = bootstrap().await;

        let (mut client_rd, mut client_wr) = tokio::io::split(client);
        let (mut server_rd, mut server_wr) = tokio::io::split(server);

        let client_wr_data = data.to_vec();
        tokio::spawn(async move {
            client_wr.write_all(&client_wr_data).await.unwrap();
            client_wr.shutdown().await.unwrap();
        });
        let server_wr_data = data.to_vec();
        tokio::spawn(async move {
            server_wr.write_all(&server_wr_data).await.unwrap();
            server_wr.shutdown().await.unwrap();
        });

        let from_client = tokio::spawn(async move {
            let mut buf = Vec::new();
            server_rd.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let from_server = tokio::spawn(async move {
            let mut buf = Vec::new();
            client_rd.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let from_client = from_client.await.unwrap();
        let from_server = from_server.await.unwrap();

        assert_eq!(data, from_client);
        assert_eq!(data, from_server);
    });
});
