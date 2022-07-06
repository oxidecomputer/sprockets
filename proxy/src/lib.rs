// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use serde::Serialize;
use slog::debug;
use slog::error;
use slog::Logger;
use sprockets_host::Ed25519Certificates;
use sprockets_host::RotManagerHandle;
use sprockets_host::Session;
use std::error::Error as StdError;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub bind_address: SocketAddr,
    pub target_address: SocketAddr,
    pub role: Role,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to bind to {addr}: {err}")]
    BindFailed { addr: SocketAddr, err: io::Error },
    #[error("failed to accept new connection: {0}")]
    AcceptFailed(io::Error),
}

pub struct Proxy<E: StdError> {
    listener: TcpListener,
    local_addr: SocketAddr,
    inner: Arc<Inner<E>>,
}

struct Inner<E: StdError> {
    target_address: SocketAddr,
    role: Role,
    rot: RotManagerHandle<E>,
    rot_certs: Ed25519Certificates,
    rot_timeout: Duration,
    log: Logger,
}

impl<E: StdError + Send + 'static> Proxy<E> {
    pub async fn new(
        config: &Config,
        rot: RotManagerHandle<E>,
        rot_certs: Ed25519Certificates,
        rot_timeout: Duration,
        log: Logger,
    ) -> Result<Self, Error> {
        let listener =
            TcpListener::bind(config.bind_address)
                .await
                .map_err(|err| Error::BindFailed {
                    addr: config.bind_address,
                    err,
                })?;

        // Can `bind()` succeed but we fail to get a local address? For now wrap
        // that into `BindFailed`; this is likely impossible.
        let local_addr =
            listener.local_addr().map_err(|err| Error::BindFailed {
                addr: config.bind_address,
                err,
            })?;

        let inner = Inner {
            target_address: config.target_address,
            role: config.role,
            rot,
            rot_certs,
            rot_timeout,
            log,
        };

        Ok(Self {
            listener,
            local_addr,
            inner: Arc::new(inner),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Run the proxy.
    ///
    /// If this method is called in an async task, the proxy can be shut down by
    /// aborting the task. Any existing connections will continue to run, but
    /// the proxy will no longer accept new connections (unless it is shared
    /// with another task that is still running it).
    pub async fn run(&self) -> Result<(), Error> {
        loop {
            let (socket, addr) =
                self.listener.accept().await.map_err(Error::AcceptFailed)?;

            // TODO Should we limit the max number of open connections? We're a
            // raw proxy so the only option we have for backpressure to our
            // client is to close the connection.
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move { inner.handle(socket, addr).await });
        }
    }
}

impl<E: StdError + Send + 'static> Inner<E> {
    async fn handle(&self, socket: TcpStream, addr: SocketAddr) {
        debug!(self.log, "accepted connection"; "addr" => addr);

        let (mut session, mut unencrypted_stream) =
            match self.establish_session_with_target(socket).await {
                Ok(session) => session,
                Err(err) => {
                    error!(
                        self.log, "failed to establish sprockets session";
                        "target" => self.target_address,
                        "err" => err,
                    );
                    return;
                }
            };

        match tokio::io::copy_bidirectional(
            &mut unencrypted_stream,
            &mut session,
        )
        .await
        {
            Ok((a, b)) => {
                debug!(
                    self.log, "connection closed";
                    "addr" => addr,
                    "plaintext-bytes-copied" => a,
                    "sprockets-bytes-copied" => b,
                );
            }
            Err(err) => {
                error!(
                    self.log, "I/O error while proxying connection";
                    "err" => err,
                );
            }
        }
    }

    // Errors from this function aren't returned and are only logged, so we use
    // `String`.
    async fn establish_session_with_target(
        &self,
        proxy_client: TcpStream,
    ) -> Result<(Session<TcpStream>, TcpStream), String> {
        // Connect to our target.
        let target_stream = TcpStream::connect(self.target_address)
            .await
            .map_err(|err| {
                format!(
                    "connected to target {} failed: {err}",
                    self.target_address
                )
            })?;

        // If we're the client, our target is a sprocksy server; if we're the
        // server, the incoming socket is a sprocksy client.
        match self.role {
            Role::Client => {
                let session = Session::new_client(
                    target_stream,
                    self.rot.clone(),
                    self.rot_certs,
                    self.rot_timeout,
                )
                .await
                .map_err(|err| format!("sprockets handshake failed: {err}"))?;
                Ok((session, proxy_client))
            }
            Role::Server => {
                let session = Session::new_server(
                    proxy_client,
                    self.rot.clone(),
                    self.rot_certs,
                    self.rot_timeout,
                )
                .await
                .map_err(|err| format!("sprockets handshake failed: {err}"))?;
                Ok((session, target_stream))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sprockets_common::certificates::SerialNumber;
    use sprockets_common::msgs::RotRequestV1;
    use sprockets_common::msgs::RotResponseV1;
    use sprockets_common::random_buf;
    use sprockets_host::RotManager;
    use sprockets_host::RotTransport;
    use sprockets_rot::RotConfig;
    use sprockets_rot::RotSprocket;
    use std::thread;
    use std::time::Instant;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    struct Harness {
        client_rot: RotManagerHandle<TestTransportError>,
        client_rot_certs: Ed25519Certificates,
        server_rot: RotManagerHandle<TestTransportError>,
        server_rot_certs: Ed25519Certificates,
        log: Logger,
    }

    #[derive(Error, Debug, PartialEq)]
    pub(crate) enum TestTransportError {
        #[error("Recv")]
        Recv,
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
                rot: RotSprocket::new(RotConfig::bootstrap_for_testing(
                    &manufacturing_keypair,
                    salty::Keypair::from(&random_buf()),
                    SerialNumber(random_buf()),
                )),
                req: None,
            }
        }
    }

    impl RotTransport for TestTransport {
        type Error = TestTransportError;

        fn send(
            &mut self,
            req: RotRequestV1,
            _: Instant,
        ) -> Result<(), Self::Error> {
            self.req = Some(req);
            Ok(())
        }

        fn recv(&mut self, _: Instant) -> Result<RotResponseV1, Self::Error> {
            self.rot
                .handle_deserialized(
                    self.req.take().ok_or(TestTransportError::Recv)?,
                )
                .map_err(|_| TestTransportError::Recv)
        }
    }

    impl Harness {
        async fn bootstrap() -> Self {
            let manufacturing_keypair = salty::Keypair::from(&random_buf());

            let client_rot = TestTransport::from_manufacturing_keypair(
                &manufacturing_keypair,
            );
            let server_rot = TestTransport::from_manufacturing_keypair(
                &manufacturing_keypair,
            );

            let client_certs = client_rot.rot.get_certificates();
            let server_certs = server_rot.rot.get_certificates();

            let log = Logger::root(slog::Discard, slog::o!());

            let (client_mgr, client_handle) =
                RotManager::new(32, client_rot, log.clone());
            let (server_mgr, server_handle) =
                RotManager::new(32, server_rot, log.clone());

            thread::spawn(move || client_mgr.run());
            thread::spawn(move || server_mgr.run());

            Self {
                client_rot: client_handle,
                client_rot_certs: client_certs,
                server_rot: server_handle,
                server_rot_certs: server_certs,
                log,
            }
        }
    }

    #[tokio::test]
    async fn hello_world() {
        let harness = Harness::bootstrap().await;

        // set up client -> proxy-client -> proxy-server -> server, where
        // "client" and "server" are both standard TCP sockets
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let proxy_server = Proxy::new(
            &Config {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                target_address: server_addr,
                role: Role::Server,
            },
            harness.server_rot.clone(),
            harness.server_rot_certs,
            Duration::ZERO,
            harness.log.clone(),
        )
        .await
        .unwrap();

        let proxy_client = Proxy::new(
            &Config {
                bind_address: "127.0.0.1:0".parse().unwrap(),
                target_address: proxy_server.local_addr(),
                role: Role::Client,
            },
            harness.client_rot.clone(),
            harness.client_rot_certs,
            Duration::ZERO,
            harness.log.clone(),
        )
        .await
        .unwrap();
        let proxy_client_addr = proxy_client.local_addr();

        let proxy_task = tokio::spawn(async move {
            tokio::try_join!(proxy_server.run(), proxy_client.run()).unwrap();
        });

        let server_task = tokio::spawn(async move {
            let (mut conn, _addr) = server.accept().await.unwrap();
            let mut buf = [0; 5];
            conn.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), b"hello");
            conn.write_all(b"world").await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let mut conn = TcpStream::connect(proxy_client_addr).await.unwrap();
            conn.write_all(b"hello").await.unwrap();
            let mut buf = [0; 5];
            conn.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), b"world");
        });

        tokio::try_join!(client_task, server_task).unwrap();

        proxy_task.abort();
    }
}
