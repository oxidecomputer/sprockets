// This Source Code Form is subject to the terms of the Mozilla Public License,
// v. 2.0. If a copy of the MPL was not distributed with this file, You can
// obtain one at https://mozilla.org/MPL/2.0/.

//! QUIC transport for sprockets connections.
//!
//! This module carries the exact same mutually-authenticated, RoT-attested
//! channel that the TCP API ([`Client`](crate::Client) /
//! [`Server`](crate::Server)) provides, over QUIC instead of TCP. It is
//! feature-gated (`quic`).
//!
//! The core primitive is [`Endpoint`]: one UDP socket that can both
//! [`connect`](Endpoint::connect) and [`accept`](Endpoint::accept). Each
//! direction yields an [`AttestedConnection`], the QUIC analog of
//! [`Stream`](crate::Stream).
//!
//! # Security model: identical to TCP
//!
//! QUIC uses TLS 1.3 for its handshake by construction (RFC 9001), and this
//! module drives it with the very same rustls configuration the TCP transport
//! uses: the same [`crypto_provider`](crate::crypto_provider) pins (X25519,
//! ChaCha20-Poly1305, TLS 1.3 only), the same [`RotCertVerifier`] and
//! [`CertResolver`] enforcing mandatory mutual authentication over the same
//! roots, and the same Ed25519-only, time-and-name-ignoring DICE chain
//! verification. After the handshake, the *same* attestation protocol bytes run
//! over a QUIC bidirectional stream, and the same PlatformId binding (equality
//! between the TLS/trust-quorum chain and the attestation chain) is enforced.
//! No cryptographic property changes.
//!
//! [`RotCertVerifier`]: crate::keys::RotCertVerifier
//! [`CertResolver`]: crate::keys::CertResolver
//!
//! # QUIC-specific surfaces
//!
//! - **Initial-packet AES-128-GCM.** RFC 9001 §5 mandates AES-128-GCM for the
//!   protection of Initial packets, whose keys are derived from the (public)
//!   Destination Connection ID. This carries no confidentiality or
//!   authentication claim — it is obfuscation over public values — so it does
//!   not weaken the ChaCha20-Poly1305-only session guarantee. The handshake and
//!   all application data continue to offer and use only ChaCha20-Poly1305; the
//!   Initial suite is supplied separately via
//!   [`QuicClientConfig::with_initial`](quinn::crypto::rustls::QuicClientConfig::with_initial).
//! - **ALPN.** Connections negotiate the ALPN token `b"sprockets"`. rustls
//!   enforces strict ALPN matching in QUIC mode, and the token is authenticated
//!   by the handshake transcript. This is a frozen wire constant: it must never
//!   encode a protocol version — version negotiation stays in-band so a mixed
//!   fleet can roll forward.
//! - **Resumption and 0-RTT are disabled.** The client sets
//!   [`Resumption::disabled`](rustls::client::Resumption::disabled) and the
//!   server sets `send_tls13_tickets = 0`; `max_early_data_size` stays 0. This
//!   makes the de-facto no-resumption behavior of the TCP path an explicit
//!   guarantee.
//! - **Migration is disabled.** The server sets
//!   [`migration(false)`](quinn::ServerConfig::migration): bootstrap addresses
//!   are stable, and disabling migration keeps a peer from silently changing
//!   address mid-connection.
//! - **Client-auth gating.** The server obtains a connection only by awaiting
//!   the full connection future, never quinn's `into_0rtt` path, so a
//!   connection becomes usable only after the client's certificate has been
//!   verified.
//!
//! ## Close codes
//!
//! On a failed handshake the connection is closed with an application error
//! code from [`close_code`], letting the peer distinguish the failure class:
//!
//! | Code | Meaning |
//! |------|---------|
//! | [`PROTOCOL`](close_code::PROTOCOL) | Version negotiation failed |
//! | [`ATTESTATION`](close_code::ATTESTATION) | Peer attestation did not verify |
//! | [`APPRAISAL`](close_code::APPRAISAL) | Measurements failed appraisal under `Enforced` |
//! | [`PLATFORM_ID_MISMATCH`](close_code::PLATFORM_ID_MISMATCH) | TLS and attestation chains disagreed on PlatformId |
//! | [`LOCAL_ERROR`](close_code::LOCAL_ERROR) | A local (I/O, encoding, transport) failure |
//!
//! # Liveness and shutdown
//!
//! quinn closes an idle connection after `MAX_IDLE_TIMEOUT` (30 s). To keep a
//! quiet connection alive (akin to how TCP lives indefinitely when silent) the
//! transport automatically sends keep-alives every `KEEP_ALIVE_INTERVAL` (10
//! s), covering even a stalled application writer. Dropping the last handle to
//! a connection closes it with code 0 and may discard undelivered in-flight
//! data; the FIN queued by
//! [`AsyncWrite::poll_shutdown`](tokio::io::AsyncWrite::poll_shutdown) is not
//! waited on. Delivery assurance therefore comes from application-level
//! acknowledgment or an explicit [`Endpoint::close`] followed by
//! [`Endpoint::wait_idle`].
//!
//! # Version compatibility
//!
//! quinn 0.11 types appear in this module's public API (via the [`quinn`]
//! re-export, so consumers get version-matched types). sprockets and its
//! consumers must therefore bump quinn in lockstep.

use crate::keys::{AttestConfig, MeasurementConnectionPolicy, SprocketsConfig};
use crate::{attest, config, platform_id_from_tls_certs, Error};
use camino::Utf8PathBuf;
use dice_mfg_msgs::PlatformId;
use dice_verifier::Corim;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{IdleTimeout, TransportConfig, VarInt};
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
use std::any::Any;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use x509_cert::Certificate;

mod stream;

#[cfg(test)]
mod tests;

pub use stream::{AttestedConnection, BiStream};

/// Re-export of the exact `quinn` this crate is built against, so consumers can
/// name version-matched quinn types (`VarInt`, `Connection`, `SendStream`, …).
pub use quinn;

/// The ALPN protocol identifier negotiated on every sprockets QUIC connection.
///
/// A frozen wire constant: it names the sprockets protocol family, never a
/// version. Version negotiation happens in-band after the handshake.
const ALPN_SPROCKETS: &[u8] = b"sprockets";

/// The dummy server name offered on connect. Bootstrap-network nodes have no
/// DNS names; the [`RotCertVerifier`](crate::keys::RotCertVerifier) ignores it,
/// exactly as on the TCP path.
const SERVER_NAME: &str = "unknown.com";

/// Idle timeout: a connection with no traffic for this long is closed. quinn's
/// default, made explicit so it reads next to [`KEEP_ALIVE_INTERVAL`].
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Keep-alive interval. quinn sends no keep-alives by default; without this a
/// quiet connection would hit [`MAX_IDLE_TIMEOUT`] and drop, a liveness
/// regression against TCP. Kept well under the idle timeout.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum concurrent peer-initiated bidirectional streams. quinn's default,
/// made explicit.
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 100;

/// Maximum concurrent peer-initiated unidirectional streams. sprockets uses
/// only bidirectional streams, so none are permitted.
const MAX_CONCURRENT_UNI_STREAMS: u32 = 0;

/// Maximum half-open incoming connections the server buffers before
/// authentication. Replaces quinn's permissive 65,536 default; a rack is ~32
/// sleds.
const MAX_INCOMING: usize = 256;

/// Total bytes buffered across all pre-authentication incoming connections.
/// Replaces quinn's permissive 100 MiB default.
const INCOMING_BUFFER_SIZE_TOTAL: u64 = 10 << 20; // 10 MiB

/// Application error codes used to close a connection on a failed handshake.
///
/// These are QUIC application close codes, observable by the peer as the reason
/// a connection was refused. See the [module documentation](self#close-codes).
pub mod close_code {
    use quinn::VarInt;

    /// Protocol-version negotiation failed.
    pub const PROTOCOL: VarInt = VarInt::from_u32(1);
    /// The peer's attestation did not verify.
    pub const ATTESTATION: VarInt = VarInt::from_u32(2);
    /// The peer's measurements failed appraisal under `Enforced`.
    pub const APPRAISAL: VarInt = VarInt::from_u32(3);
    /// The TLS and attestation cert chains disagreed on the peer PlatformId.
    pub const PLATFORM_ID_MISMATCH: VarInt = VarInt::from_u32(4);
    /// A local failure (I/O, encoding, or transport) aborted the handshake.
    pub const LOCAL_ERROR: VarInt = VarInt::from_u32(5);
}

/// The RFC 9001 Initial-packet cipher suite: AES-128-GCM.
///
/// Supplied to quinn separately from the handshake suite list, which continues
/// to offer only ChaCha20-Poly1305. This is infallible by construction (since
/// aws-lc-rs always provides AES-128-GCM with QUIC support) and the panics
/// below can only fire if that provider is swapped for one that lacks it.
fn initial_suite() -> rustls::quic::Suite {
    TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite")
        .quic_suite()
        .expect("aws-lc-rs provides QUIC support for AES-128-GCM")
}

/// The shared transport policy applied to both directions of an endpoint.
fn transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            IdleTimeout::try_from(MAX_IDLE_TIMEOUT)
                .expect("30s is a valid idle timeout"),
        ))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .max_concurrent_bidi_streams(VarInt::from_u32(
            MAX_CONCURRENT_BIDI_STREAMS,
        ))
        .max_concurrent_uni_streams(VarInt::from_u32(
            MAX_CONCURRENT_UNI_STREAMS,
        ));
    transport
}

/// Builds the quinn client configuration for a sprockets QUIC endpoint.
fn new_quic_client_config(
    resolve: crate::keys::ResolveSetting,
    roots: Vec<Certificate>,
    log: &slog::Logger,
    transport: Arc<TransportConfig>,
) -> Result<quinn::ClientConfig, Error> {
    let mut tls = config::new_tls_client_config(resolve, roots, log)?;
    tls.alpn_protocols = vec![ALPN_SPROCKETS.to_vec()];
    tls.resumption = rustls::client::Resumption::disabled();

    let quic = QuicClientConfig::with_initial(Arc::new(tls), initial_suite())?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
    client_config.transport_config(transport);
    Ok(client_config)
}

/// Builds the quinn server configuration for a sprockets QUIC endpoint.
fn new_quic_server_config(
    resolve: crate::keys::ResolveSetting,
    roots: Vec<Certificate>,
    log: &slog::Logger,
    transport: Arc<TransportConfig>,
) -> Result<quinn::ServerConfig, Error> {
    let mut tls = config::new_tls_server_config(resolve, roots, log)?;
    tls.alpn_protocols = vec![ALPN_SPROCKETS.to_vec()];
    tls.send_tls13_tickets = 0;

    let quic = QuicServerConfig::with_initial(Arc::new(tls), initial_suite())?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server_config
        .transport_config(transport)
        .migration(false)
        .max_incoming(MAX_INCOMING)
        .incoming_buffer_size_total(INCOMING_BUFFER_SIZE_TOTAL);
    Ok(server_config)
}

/// Derives the peer [`PlatformId`] from a quinn connection's peer identity.
///
/// quinn returns the peer's TLS certificate chain as an `Option<Box<dyn Any>>`
/// that, for the rustls backend, downcasts to a
/// `Vec<CertificateDer<'static>>`. A missing identity or a failed downcast — the
/// latter only possible if two incompatible rustls versions coexist in the
/// dependency graph — is reported as [`Error::NoTQCerts`], the same error the
/// TCP path raises for an unauthenticated peer.
fn platform_id_from_peer_identity(
    identity: Option<Box<dyn Any>>,
) -> Result<PlatformId, Error> {
    let certs = identity
        .and_then(|id| {
            id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .map(|boxed| *boxed);
    platform_id_from_tls_certs(certs.as_deref())
}

/// Maps a handshake error to the QUIC close code the peer will observe.
fn close_code_for_error(err: &Error) -> VarInt {
    match err {
        Error::ProtocolVersion
        | Error::ClientMismatch
        | Error::ClientGaveUp => close_code::PROTOCOL,
        Error::PlatformIdMismatch => close_code::PLATFORM_ID_MISMATCH,
        Error::AttestMeasurementsVerifier { .. } => close_code::APPRAISAL,
        Error::AttestationVerifier(_)
        | Error::AttestCertVerifier(_)
        | Error::MeasurementSet(_)
        | Error::ReferenceMeasurements(_)
        | Error::Attest(_)
        | Error::AttestData(_)
        | Error::NonceError(_)
        | Error::PlatformIdPkiPath(_)
        | Error::PlatformId(_)
        | Error::CorimError(_)
        | Error::AttestMock(_)
        | Error::AttestIpcc(_)
        | Error::RotRequest(_)
        | Error::NoTQCerts => close_code::ATTESTATION,
        _ => close_code::LOCAL_ERROR,
    }
}

/// Closes `connection` with the code and reason derived from `err`.
fn close_for_error(connection: &quinn::Connection, err: &Error) {
    connection.close(close_code_for_error(err), err.to_string().as_bytes());
}

/// A sprockets QUIC endpoint: one UDP socket that both dials and listens.
///
/// Construct with [`new`](Endpoint::new), then [`connect`](Endpoint::connect)
/// to a peer or [`accept`](Endpoint::accept) an inbound connection. Both
/// directions run the same attestation exchange and yield an
/// [`AttestedConnection`].
pub struct Endpoint {
    inner: quinn::Endpoint,
    attest_config: AttestConfig,
    roots: Vec<Certificate>,
    enforce: MeasurementConnectionPolicy,
    log: slog::Logger,
}

impl Endpoint {
    /// Binds a UDP socket at `bind` and prepares it to both dial and listen
    /// using `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FailedRead`] if a root or key file cannot be read,
    /// [`Error::QuicNoInitialCipherSuite`] if the crypto provider lacks the
    /// Initial suite (unreachable with the default aws-lc-rs provider), or
    /// [`Error::Io`] if the socket cannot be bound.
    pub fn new(
        config: SprocketsConfig,
        bind: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<Self, Error> {
        let roots = config::load_roots(&config.roots)?;
        let transport = Arc::new(transport_config());
        let client_config = new_quic_client_config(
            config.resolve.clone(),
            roots.clone(),
            &log,
            transport.clone(),
        )?;
        let server_config = new_quic_server_config(
            config.resolve.clone(),
            roots.clone(),
            &log,
            transport,
        )?;

        let mut inner = quinn::Endpoint::server(server_config, bind.into())?;
        inner.set_default_client_config(client_config);

        Ok(Endpoint {
            inner,
            attest_config: config.attest,
            roots,
            enforce: config.enforce,
            log,
        })
    }

    /// Returns the local address the endpoint is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the underlying quinn endpoint, an escape hatch for configuration
    /// this API does not surface.
    pub fn inner(&self) -> &quinn::Endpoint {
        &self.inner
    }

    /// Dials `addr`, completes the QUIC/TLS handshake, and runs the attestation
    /// exchange, returning the attested connection.
    ///
    /// `corpus` is the reference-measurement corpus the peer's measurements are
    /// appraised against. Not cancel safe: run in a dedicated task.
    pub async fn connect(
        &self,
        addr: SocketAddrV6,
        corpus: Vec<Utf8PathBuf>,
    ) -> Result<AttestedConnection, Error> {
        let connection = self.inner.connect(addr.into(), SERVER_NAME)?.await?;

        // The peer identity is the server's TLS/trust-quorum chain, the QUIC
        // analog of `peer_certificates()` on the TCP path.
        let tq_platform_id =
            platform_id_from_peer_identity(connection.peer_identity())?;

        let (send, recv) = connection.open_bi().await?;
        let mut stream = BiStream::new(send, recv);

        let (peer_platform_id, appraisal) = match attest::client_exchange(
            &mut stream,
            tq_platform_id,
            &self.attest_config,
            &self.roots,
            corpus,
            self.enforce,
            &self.log,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                close_for_error(&connection, &err);
                return Err(err);
            }
        };

        Ok(AttestedConnection::new(
            connection,
            stream,
            peer_platform_id,
            appraisal,
        ))
    }

    /// Awaits the next inbound connection, returning an [`Acceptor`] whose
    /// [`handshake`](Acceptor::handshake) completes the exchange.
    ///
    /// `corpus` is loaded before any connection is awaited, so a malformed
    /// corpus fails here rather than mid-handshake — mirroring the TCP
    /// acceptor. Unvalidated incoming connections are forced through a Retry
    /// (address validation) and the validated re-dial is the one returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::QuicEndpointClosed`] if the endpoint has been closed.
    pub async fn accept(
        &self,
        corpus: Vec<Utf8PathBuf>,
    ) -> Result<Acceptor, Error> {
        let corims = attest::corims_from_paths(&corpus, &self.log)?;

        loop {
            let incoming =
                self.inner.accept().await.ok_or(Error::QuicEndpointClosed)?;

            // Require address validation. An unvalidated peer is sent a Retry;
            // it re-dials, and that attempt arrives already validated. This
            // bounds the pre-authentication amplification surface.
            if !incoming.remote_address_validated() {
                let _ = incoming.retry();
                continue;
            }

            let addr = incoming.remote_address();
            return Ok(Acceptor {
                incoming,
                corims,
                attest_config: self.attest_config.clone(),
                roots: self.roots.clone(),
                enforce: self.enforce,
                log: self.log.clone(),
                addr,
            });
        }
    }

    /// Closes the endpoint and all its connections with the given code and
    /// reason.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason);
    }

    /// Waits until all connections are cleanly shut down.
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

/// A pending inbound QUIC connection whose attestation exchange has not yet run.
///
/// Mirrors the TCP [`SprocketsAcceptor`](crate::server::SprocketsAcceptor):
/// [`handshake`](Acceptor::handshake) awaits the fully-authenticated connection
/// and runs the server side of the attestation exchange.
pub struct Acceptor {
    incoming: quinn::Incoming,
    corims: Vec<Corim>,
    attest_config: AttestConfig,
    roots: Vec<Certificate>,
    enforce: MeasurementConnectionPolicy,
    log: slog::Logger,
    addr: SocketAddr,
}

impl Acceptor {
    /// The address of the peer that initiated this connection.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Completes the QUIC/TLS handshake and runs the server attestation
    /// exchange, returning the attested connection and the peer address.
    ///
    /// The connection future is awaited in full — never quinn's `into_0rtt`
    /// path — so it resolves only after the client's certificate has been
    /// verified. The exchange runs over the first bidirectional stream the
    /// client opens. Not cancel safe: run in a dedicated task.
    pub async fn handshake(
        self,
    ) -> Result<(AttestedConnection, SocketAddr), Error> {
        let Acceptor {
            incoming,
            corims,
            attest_config,
            roots,
            enforce,
            log,
            addr,
        } = self;

        let connection = incoming.await?;

        let tq_platform_id =
            platform_id_from_peer_identity(connection.peer_identity())?;

        let (send, recv) = connection.accept_bi().await?;
        let mut stream = BiStream::new(send, recv);

        let (peer_platform_id, appraisal) = match attest::server_exchange(
            &mut stream,
            tq_platform_id,
            corims,
            &attest_config,
            &roots,
            enforce,
            &log,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                close_for_error(&connection, &err);
                return Err(err);
            }
        };

        Ok((
            AttestedConnection::new(
                connection,
                stream,
                peer_platform_id,
                appraisal,
            ),
            addr,
        ))
    }
}

/// A one-shot QUIC client, mirroring the TCP [`Client`](crate::Client).
///
/// For callers that only dial and do not need to hold an [`Endpoint`]. Each
/// [`connect`](Client::connect) binds a fresh UDP socket on an OS-assigned port
/// (`[::]:0`), performs the attested handshake, and returns the connection. The
/// endpoint handle is then dropped, but quinn keeps its I/O driver alive as long
/// as the returned connection lives, so the connection stays usable. Callers
/// that dial repeatedly, or that also listen, should share one [`Endpoint`]
/// instead.
pub struct Client {}

impl Client {
    /// Binds an ephemeral endpoint, connects to `addr`, and runs the attested
    /// handshake, returning the connection.
    ///
    /// Behaves like [`Client::connect`](crate::Client::connect) on the TCP path.
    /// Not cancel safe: run in a dedicated task.
    pub async fn connect(
        config: SprocketsConfig,
        addr: SocketAddrV6,
        corpus: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<AttestedConnection, Error> {
        let bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        let endpoint = Endpoint::new(config, bind, log)?;
        endpoint.connect(addr, corpus).await
    }
}

/// A QUIC server, mirroring the TCP [`Server`](crate::Server).
///
/// A thin wrapper over a listening [`Endpoint`] for callers that only accept
/// connections. Callers that also dial can use the underlying [`Endpoint`]
/// directly.
pub struct Server {
    endpoint: Endpoint,
}

impl Server {
    /// Binds a UDP socket at `addr` and prepares it to accept sprockets QUIC
    /// connections.
    ///
    /// Behaves like [`Server::new`](crate::Server::new) on the TCP path.
    pub fn new(
        config: SprocketsConfig,
        addr: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<Server, Error> {
        Ok(Server {
            endpoint: Endpoint::new(config, addr, log)?,
        })
    }

    /// Returns the local address the server is bound to.
    ///
    /// As with the TCP [`Server::listen_addr`](crate::Server::listen_addr),
    /// binding port 0 lets the OS assign a port; this reports the real one.
    pub fn listen_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Awaits the next inbound connection, returning an [`Acceptor`].
    ///
    /// Behaves like [`Server::accept`](crate::Server::accept) on the TCP path.
    pub async fn accept(
        &self,
        corpus: Vec<Utf8PathBuf>,
    ) -> Result<Acceptor, Error> {
        self.endpoint.accept(corpus).await
    }

    /// Returns the underlying endpoint, for callers that also need to dial or
    /// to close the endpoint explicitly.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}
