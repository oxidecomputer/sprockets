// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Integration tests for the QUIC transport.
//!
//! These reuse the crate's test PKI (built by `build.rs` under the `unittest`
//! feature) and the shared helpers in [`crate::tests`]. Each server binds
//! `[::1]:0` and the real bound port is read back via
//! [`Server::listen_addr`](super::Server::listen_addr), so tests never race on a
//! fixed port and can run concurrently.

use super::*;
use crate::tests::{local_config, logger, mock_datadir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use MeasurementConnectionPolicy::{Enforced, Permissive};

/// A loopback bind address on an OS-assigned port.
fn localhost() -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)
}

/// The bound address of a server, as a `SocketAddrV6` for `connect`.
fn as_v6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V6(addr) => addr,
        SocketAddr::V4(addr) => panic!("expected an IPv6 address, got {addr}"),
    }
}

/// The standard two-CoRIM reference corpus used by the enforcing tests.
fn corpus(dir: &Utf8PathBuf) -> Vec<Utf8PathBuf> {
    vec![dir.join("corim-rot.cbor"), dir.join("corim-sp.cbor")]
}

/// A bare quinn client endpoint using the real sprockets TLS client config
/// (valid credentials), for tests that drive the connection manually without
/// running the attestation exchange.
fn raw_client_endpoint(
    config: SprocketsConfig,
    log: &slog::Logger,
) -> quinn::Endpoint {
    let roots = crate::config::load_roots(&config.roots).unwrap();
    let transport = Arc::new(transport_config());
    let client_config =
        new_quic_client_config(config.resolve, roots, log, transport).unwrap();
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
            .unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// A quinn client endpoint that authenticates the server but presents *no*
/// client certificate, for the mandatory-client-auth test.
fn no_client_auth_endpoint(
    config: SprocketsConfig,
    log: &slog::Logger,
) -> quinn::Endpoint {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::version::TLS13;

    let roots = crate::config::load_roots(&config.roots).unwrap();
    let verifier = Arc::new(
        crate::keys::RotCertVerifier::new(roots, log.clone()).unwrap(),
    ) as Arc<dyn ServerCertVerifier>;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        crate::crypto_provider(),
    ))
    .with_protocol_versions(&[&TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_SPROCKETS.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::with_initial(
        Arc::new(tls),
        initial_suite(),
    )
    .unwrap();
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
            .unwrap();
    endpoint
        .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    endpoint
}

/// A quinn client endpoint identical to the real one except that it offers the
/// wrong ALPN token, for the ALPN-enforcement test.
fn wrong_alpn_endpoint(
    config: SprocketsConfig,
    log: &slog::Logger,
) -> quinn::Endpoint {
    let roots = crate::config::load_roots(&config.roots).unwrap();
    let mut tls =
        crate::config::new_tls_client_config(config.resolve, roots, log)
            .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::with_initial(
        Arc::new(tls),
        initial_suite(),
    )
    .unwrap();
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
            .unwrap();
    endpoint
        .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    endpoint
}

/// A quinn client endpoint with valid credentials and correct ALPN, but whose
/// TLS config offers *all* of aws-lc-rs's default cipher suites (including
/// AES-GCM) as session suites, for the cipher-suite-pin test.
fn all_suites_endpoint(
    config: SprocketsConfig,
    log: &slog::Logger,
) -> quinn::Endpoint {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::ResolvesClientCert;
    use rustls::version::TLS13;

    let roots = crate::config::load_roots(&config.roots).unwrap();
    let verifier = Arc::new(
        crate::keys::RotCertVerifier::new(roots, log.clone()).unwrap(),
    ) as Arc<dyn ServerCertVerifier>;
    let resolver =
        Arc::new(crate::keys::CertResolver::new(log.clone(), config.resolve))
            as Arc<dyn ResolvesClientCert>;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_cert_resolver(resolver);
    tls.alpn_protocols = vec![ALPN_SPROCKETS.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::with_initial(
        Arc::new(tls),
        initial_suite(),
    )
    .unwrap();
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
            .unwrap();
    endpoint
        .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    endpoint
}

/// A config whose TLS/trust-quorum identity and attestation identity come from
/// *different* key sets, so the two chains disagree on `PlatformId`.
fn mismatched_config() -> SprocketsConfig {
    let tls = local_config(1, Enforced);
    let attest = local_config(2, Enforced);
    SprocketsConfig {
        resolve: tls.resolve,
        attest: attest.attest,
        roots: tls.roots,
        enforce: Enforced,
    }
}

/// Walks an error's source chain (peeking inside `io::Error` wrappers, which
/// `source()` would otherwise skip) for a QUIC application close code the peer
/// sent.
fn application_close_code(err: &Error) -> Option<VarInt> {
    fn code_of(e: &(dyn std::error::Error + 'static)) -> Option<VarInt> {
        if let Some(quinn::ConnectionError::ApplicationClosed(close)) =
            e.downcast_ref::<quinn::ConnectionError>()
        {
            return Some(close.error_code);
        }
        if let Some(quinn::ReadError::ConnectionLost(
            quinn::ConnectionError::ApplicationClosed(close),
        )) = e.downcast_ref::<quinn::ReadError>()
        {
            return Some(close.error_code);
        }
        None
    }

    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if let Some(code) = code_of(e) {
            return Some(code);
        }
        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            if let Some(code) =
                io_err.get_ref().and_then(|inner| code_of(inner))
            {
                return Some(code);
            }
        }
        current = e.source();
    }
    None
}

/// A full enforcing handshake succeeds and both peers see the other's attested
/// identity, and application data flows over the primary stream.
#[tokio::test]
async fn basic() {
    let log = logger();
    let dir = mock_datadir();
    const MSG: &str = "Hello Joe";

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let (mut conn, _peer_addr) = server
            .accept(server_corpus)
            .await
            .unwrap()
            .handshake()
            .await
            .unwrap();
        assert!(conn.appraisal_success());
        let mut buf = String::new();
        conn.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, MSG);
        *conn.peer_platform_id()
    });

    let mut client =
        Client::connect(local_config(2, Enforced), addr, corpus(&dir), log)
            .await
            .unwrap();
    assert!(client.appraisal_success());
    let server_id = *client.peer_platform_id();
    client.write_all(MSG.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    let client_id = server_task.await.unwrap();

    // Each peer derived the other's attested identity, and the two test configs
    // provision distinct platforms, so the identities differ.
    assert_ne!(server_id, client_id);
}

/// Under `Permissive` with an empty corpus, the handshake completes but
/// `appraisal_success()` reports false on both sides.
#[tokio::test]
async fn no_corpus() {
    let log = logger();
    const MSG: &str = "Hello Joe";

    let server =
        Server::new(local_config(1, Permissive), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_task = tokio::spawn(async move {
        let (mut conn, _) = server
            .accept(vec![])
            .await
            .unwrap()
            .handshake()
            .await
            .unwrap();
        assert!(!conn.appraisal_success());
        let mut buf = String::new();
        conn.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, MSG);
    });

    let mut client =
        Client::connect(local_config(2, Permissive), addr, vec![], log)
            .await
            .unwrap();
    assert!(!client.appraisal_success());
    client.write_all(MSG.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    server_task.await.unwrap();
}

/// A client with valid TLS credentials that never runs the attestation
/// exchange (it just writes application bytes) must not complete a handshake.
#[tokio::test]
async fn unattested_client() {
    let log = logger();
    let dir = mock_datadir();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let acceptor = server.accept(server_corpus).await.unwrap();
        let result = acceptor.handshake().await;
        assert!(
            result.is_err(),
            "a client that skips attestation must not complete the handshake"
        );
    });

    let endpoint = raw_client_endpoint(local_config(2, Enforced), &log);
    let conn = endpoint
        .connect(addr.into(), SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    // Fewer bytes than the exchange's leading length prefix, then EOF: the
    // server's first `recv_msg` fails rather than reading a valid message.
    send.write_all(b"xy").await.unwrap();
    let _ = send.finish();

    server_task.await.unwrap();
    drop(conn);
    drop(endpoint);
}

/// A version message whose body is shorter than the 4-byte version is
/// rejected as [`Error::ProtocolVersion`] — the server task must error, not
/// panic on a short slice.
#[tokio::test]
async fn short_version_message_rejected() {
    let log = logger();
    let dir = mock_datadir();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let result = server
            .accept(server_corpus)
            .await
            .unwrap()
            .handshake()
            .await;
        match result {
            Err(Error::ProtocolVersion) => {}
            Err(other) => panic!("expected ProtocolVersion, got {other:?}"),
            Ok(_) => {
                panic!("a malformed version message must not complete")
            }
        }
    });

    let endpoint = raw_client_endpoint(local_config(2, Enforced), &log);
    let conn = endpoint
        .connect(addr.into(), SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    // A valid length prefix (2) followed by a 2-byte body: the server's
    // recv_msg succeeds, but the body is shorter than the 4-byte version it
    // must contain.
    send.write_all(&2u32.to_le_bytes()).await.unwrap();
    send.write_all(b"xy").await.unwrap();
    let _ = send.finish();

    server_task.await.unwrap();
    drop(conn);
    drop(endpoint);
}

/// A message whose length prefix exceeds `MAX_MSG_SIZE` is rejected as
/// [`Error::MessageTooLarge`] before the message buffer is allocated, and
/// the client observes the [`close_code::PROTOCOL`] close code.
#[tokio::test]
async fn oversized_message_rejected() {
    let log = logger();
    let dir = mock_datadir();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let result = server
            .accept(server_corpus)
            .await
            .unwrap()
            .handshake()
            .await;
        match result {
            Err(Error::MessageTooLarge { .. }) => {}
            Err(other) => panic!("expected MessageTooLarge, got {other:?}"),
            Ok(_) => panic!("an oversized message must not complete"),
        }
    });

    let endpoint = raw_client_endpoint(local_config(2, Enforced), &log);
    let conn = endpoint
        .connect(addr.into(), SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    // A length prefix claiming a 4 GiB message; no body ever follows. The
    // server must reject on the prefix alone.
    send.write_all(&u32::MAX.to_le_bytes()).await.unwrap();

    // The server closes with PROTOCOL; observe it from the read half.
    let read_err = recv
        .read_to_end(usize::MAX)
        .await
        .expect_err("server must close the connection");
    match read_err {
        quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(
            quinn::ConnectionError::ApplicationClosed(close),
        )) => {
            assert_eq!(close.error_code, close_code::PROTOCOL);
        }
        other => panic!("expected an application close, got {other:?}"),
    }

    server_task.await.unwrap();
    drop(conn);
    drop(endpoint);
}

/// One server endpoint handshakes with several concurrent clients.
#[tokio::test]
async fn spawn_accept() {
    let log = logger();
    let dir = mock_datadir();
    const MSG: &str = "Hello Joe";
    const CLIENTS: usize = 3;

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let mut reads = Vec::new();
        for _ in 0..CLIENTS {
            let acceptor = server.accept(server_corpus.clone()).await.unwrap();
            reads.push(tokio::spawn(async move {
                let (mut conn, _) = acceptor.handshake().await.unwrap();
                let mut buf = String::new();
                conn.read_to_string(&mut buf).await.unwrap();
                assert_eq!(buf, MSG);
            }));
        }
        for read in reads {
            read.await.unwrap();
        }
    });

    // Keep each client connection alive (held in its JoinHandle) until every
    // server-side read has finished. Dropping a connection early would close it
    // with code 0 and truncate the still-unread message.
    let mut clients = Vec::new();
    for _ in 0..CLIENTS {
        let log = log.clone();
        let dir = dir.clone();
        clients.push(tokio::spawn(async move {
            let mut client = Client::connect(
                local_config(2, Enforced),
                addr,
                corpus(&dir),
                log,
            )
            .await
            .unwrap();
            client.write_all(MSG.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();
            client
        }));
    }

    tokio::time::timeout(Duration::from_secs(30), server_task)
        .await
        .expect("server handshakes did not complete in time")
        .unwrap();

    for client in clients {
        let _client = client.await.unwrap();
    }
}

/// A second stream opened after the handshake inherits the connection's
/// attested identity and carries data independently of the primary stream.
#[tokio::test]
async fn multi_stream() {
    let log = logger();
    let dir = mock_datadir();
    const PRIMARY: &str = "primary stream";
    const SECOND: &str = "second stream";

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let (mut conn, _) = server
            .accept(server_corpus)
            .await
            .unwrap()
            .handshake()
            .await
            .unwrap();

        let mut primary = String::new();
        conn.read_to_string(&mut primary).await.unwrap();
        assert_eq!(primary, PRIMARY);

        let mut second = conn.accept_bi().await.unwrap();
        let mut secondary = String::new();
        second.read_to_string(&mut secondary).await.unwrap();
        assert_eq!(secondary, SECOND);
    });

    let mut client =
        Client::connect(local_config(2, Enforced), addr, corpus(&dir), log)
            .await
            .unwrap();
    client.write_all(PRIMARY.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    let mut second = client.open_bi().await.unwrap();
    second.write_all(SECOND.as_bytes()).await.unwrap();
    second.shutdown().await.unwrap();

    server_task.await.unwrap();
}

/// When the server rejects measurements under `Enforced`, it closes the
/// connection with [`close_code::APPRAISAL`], which the client observes.
#[tokio::test]
async fn appraisal_failure_close_code() {
    let log = logger();
    let dir = mock_datadir();

    // Enforcing, but with an empty corpus, so appraisal necessarily fails.
    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_task = tokio::spawn(async move {
        let result = server.accept(vec![]).await.unwrap().handshake().await;
        match result {
            Err(Error::AttestMeasurementsVerifier { .. }) => {}
            Err(other) => {
                panic!("expected an appraisal failure, got {other:?}")
            }
            Ok(_) => panic!("server must not complete a failing handshake"),
        }
    });

    let result =
        Client::connect(local_config(2, Enforced), addr, corpus(&dir), log)
            .await;
    let err = match result {
        Ok(_) => {
            panic!("client must not complete a handshake the server rejects")
        }
        Err(err) => err,
    };
    assert_eq!(
        application_close_code(&err),
        Some(close_code::APPRAISAL),
        "client should observe the server's APPRAISAL close code; got: {err:?}"
    );

    server_task.await.unwrap();
}

/// A client presenting no certificate cannot complete the handshake: the
/// server's connection future errors before any stream or peer identity is
/// reachable.
#[tokio::test]
async fn client_auth_required() {
    let log = logger();
    let dir = mock_datadir();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let acceptor = server.accept(server_corpus).await.unwrap();
        let result = acceptor.handshake().await;
        assert!(
            result.is_err(),
            "server must reject a client that presents no certificate"
        );
    });

    let endpoint = no_client_auth_endpoint(local_config(2, Enforced), &log);
    // The client-side connection also fails once the server aborts; we only
    // assert on the server's rejection.
    let _ = endpoint.connect(addr.into(), SERVER_NAME).unwrap().await;

    server_task.await.unwrap();
    drop(endpoint);
}

/// A peer whose TLS/trust-quorum chain and attestation chain disagree on
/// `PlatformId` is rejected: the server errors with
/// [`Error::PlatformIdMismatch`] and closes with
/// [`close_code::PLATFORM_ID_MISMATCH`], which the client observes. This pins
/// the load-bearing TLS-to-attestation identity binding.
#[tokio::test]
async fn platform_id_mismatch() {
    let log = logger();
    let dir = mock_datadir();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let server_task = tokio::spawn(async move {
        let result = server
            .accept(server_corpus)
            .await
            .unwrap()
            .handshake()
            .await;
        match result {
            Err(Error::PlatformIdMismatch) => {}
            Err(other) => panic!("expected PlatformIdMismatch, got {other:?}"),
            Ok(_) => panic!("a mismatched client must not complete"),
        }
    });

    let result =
        Client::connect(mismatched_config(), addr, corpus(&dir), log).await;
    let err = match result {
        Ok(_) => panic!("client with mismatched identities must not connect"),
        Err(err) => err,
    };
    assert_eq!(
        application_close_code(&err),
        Some(close_code::PLATFORM_ID_MISMATCH),
        "client should observe the PLATFORM_ID_MISMATCH close code; got: {err:?}"
    );

    server_task.await.unwrap();
}

/// A client offering the wrong ALPN token cannot complete the handshake, even
/// with otherwise-valid credentials: rustls enforces strict ALPN matching in
/// QUIC mode.
#[tokio::test]
async fn wrong_alpn_rejected() {
    let log = logger();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_task = tokio::spawn(async move {
        let acceptor = server.accept(vec![]).await.unwrap();
        assert!(
            acceptor.handshake().await.is_err(),
            "server must reject a client offering the wrong ALPN"
        );
    });

    let endpoint = wrong_alpn_endpoint(local_config(2, Enforced), &log);
    let _ = endpoint.connect(addr.into(), SERVER_NAME).unwrap().await;

    server_task.await.unwrap();
    drop(endpoint);
}

/// A client offering AES-GCM session cipher suites is rejected: the server's
/// resolver pins ChaCha20-Poly1305 as the only permitted session suite. The
/// AES-128-GCM used for RFC 9001 Initial packets is separate and does not
/// satisfy this.
#[tokio::test]
async fn session_cipher_pinned_to_chacha20() {
    let log = logger();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_task = tokio::spawn(async move {
        let acceptor = server.accept(vec![]).await.unwrap();
        assert!(
            acceptor.handshake().await.is_err(),
            "server must reject a client offering non-ChaCha20 session suites"
        );
    });

    let endpoint = all_suites_endpoint(local_config(2, Enforced), &log);
    let _ = endpoint.connect(addr.into(), SERVER_NAME).unwrap().await;

    server_task.await.unwrap();
    drop(endpoint);
}

/// A payload far larger than the path MTU and a single packet round-trips
/// intact over the attested stream, exercising QUIC stream flow control and
/// the `BiStream` duplex under load in both directions.
#[tokio::test]
async fn large_payload() {
    let log = logger();
    let dir = mock_datadir();

    // 1 MiB: hundreds of packets, near quinn's default stream receive window.
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| i as u8).collect();

    let server =
        Server::new(local_config(1, Enforced), localhost(), log.clone())
            .unwrap();
    let addr = as_v6(server.listen_addr().unwrap());

    let server_corpus = corpus(&dir);
    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let (mut conn, _) = server
            .accept(server_corpus)
            .await
            .unwrap()
            .handshake()
            .await
            .unwrap();
        let mut buf = vec![0u8; expected.len()];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, expected);
        // Echo it back, then keep the connection alive (returned to the caller)
        // until the client has read the echo.
        conn.write_all(&buf).await.unwrap();
        conn.shutdown().await.unwrap();
        conn
    });

    let mut client =
        Client::connect(local_config(2, Enforced), addr, corpus(&dir), log)
            .await
            .unwrap();
    client.write_all(&payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    let _server_conn = server_task.await.unwrap();
}

/// The RFC 9001 Initial suite is AES-128-GCM. Guards against a future
/// "simplification" to quinn's `TryFrom` path, which would fail at runtime
/// because the sprockets provider deliberately lacks AES-128-GCM as a
/// session suite.
#[test]
fn initial_suite_is_aes_128_gcm() {
    let suite = initial_suite();
    assert_eq!(
        suite.suite.common.suite,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
    );
}
