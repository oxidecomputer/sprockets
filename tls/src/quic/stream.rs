// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Stream and connection types for the sprockets QUIC transport.
//!
//! [`BiStream`] rejoins quinn's split send/receive halves into one duplex byte
//! stream; [`AttestedConnection`] is the attested connection handle returned by
//! the [`quic`](crate::quic) API, the QUIC analog of [`Stream`](crate::Stream).

use crate::Error;
use dice_mfg_msgs::PlatformId;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A QUIC bidirectional stream presented as a single duplex byte stream.
///
/// quinn splits a bidirectional stream into a [`quinn::SendStream`] and a
/// [`quinn::RecvStream`]; `BiStream` rejoins them so the stream satisfies both
/// [`AsyncRead`] and [`AsyncWrite`], the shape the attestation exchange and
/// application code expect from a TCP-backed [`Stream`](crate::Stream). Reads
/// are served by the receive half, writes by the send half.
///
/// [`AsyncWrite::poll_shutdown`] maps to [`quinn::SendStream::finish`], which
/// queues a FIN but does not wait for the peer to acknowledge delivery; see the
/// [module documentation](crate::quic#liveness-and-shutdown) for what that
/// implies about in-flight data. Unlike shutting down a TCP-backed
/// [`Stream`](crate::Stream), a *second* `shutdown().await` returns an error:
/// `finish` rejects a stream that is already finished.
pub struct BiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl BiStream {
    pub(crate) fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        BiStream { send, recv }
    }

    /// Returns the send and receive halves, consuming the stream.
    ///
    /// An escape hatch for code that needs the raw quinn streams (for example
    /// to call [`quinn::RecvStream::read_chunk`] or set stream priorities).
    pub fn into_inner(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }
}

// quinn's `SendStream`/`RecvStream` carry inherent `poll_write`/`poll_read`
// methods (returning quinn's own error types) that would shadow the tokio trait
// methods under plain method-call syntax, so every delegation names the trait
// explicitly.
impl AsyncRead for BiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write_vectored(
            Pin::new(&mut self.get_mut().send),
            cx,
            bufs,
        )
    }

    fn is_write_vectored(&self) -> bool {
        AsyncWrite::is_write_vectored(&self.send)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// An authenticated, attested QUIC connection: the QUIC analog of
/// [`Stream`](crate::Stream).
///
/// By the time an `AttestedConnection` exists, the QUIC/TLS 1.3 handshake has
/// completed with mutual authentication and both peers have run the sprockets
/// attestation exchange over the primary bidirectional stream. The attested
/// identity — [`peer_platform_id`](Self::peer_platform_id) — covers the whole
/// connection: further streams from [`open_bi`](Self::open_bi) /
/// [`accept_bi`](Self::accept_bi) inherit it without a new exchange.
///
/// `AttestedConnection` implements [`AsyncRead`] and [`AsyncWrite`] by
/// delegating to the primary stream, so code written against a
/// [`Stream<TcpStream>`](crate::Stream) ports over directly.
pub struct AttestedConnection {
    connection: quinn::Connection,
    stream: BiStream,
    platform_id: PlatformId,
    corpus_appraisal_success: bool,
}

impl AttestedConnection {
    pub(crate) fn new(
        connection: quinn::Connection,
        stream: BiStream,
        platform_id: PlatformId,
        corpus_appraisal_success: bool,
    ) -> Self {
        AttestedConnection {
            connection,
            stream,
            platform_id,
            corpus_appraisal_success,
        }
    }

    /// The attested [`PlatformId`] of the peer.
    pub fn peer_platform_id(&self) -> &PlatformId {
        &self.platform_id
    }

    /// Whether the peer's measurements appraised successfully against the
    /// reference corpus.
    ///
    /// Always `true` under
    /// [`Enforced`](crate::keys::MeasurementConnectionPolicy::Enforced), where a
    /// failed appraisal aborts the handshake rather than yielding a connection.
    pub fn appraisal_success(&self) -> bool {
        self.corpus_appraisal_success
    }

    /// The underlying quinn connection, for opening further streams or
    /// inspecting connection state.
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// The peer's current socket address.
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Opens a new outbound bidirectional stream.
    ///
    /// The stream inherits the connection's attested identity; no further
    /// attestation exchange is performed.
    pub async fn open_bi(&self) -> Result<BiStream, Error> {
        let (send, recv) = self.connection.open_bi().await?;
        Ok(BiStream::new(send, recv))
    }

    /// Accepts the next inbound bidirectional stream opened by the peer.
    ///
    /// The stream inherits the connection's attested identity; no further
    /// attestation exchange is performed.
    pub async fn accept_bi(&self) -> Result<BiStream, Error> {
        let (send, recv) = self.connection.accept_bi().await?;
        Ok(BiStream::new(send, recv))
    }

    /// Closes the connection immediately with the given application error code
    /// and reason.
    ///
    /// See [`quinn::Connection::close`] for the delivery semantics.
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.connection.close(error_code, reason);
    }

    /// Decomposes into the quinn connection, the primary stream, the attested
    /// peer identity, and the appraisal result.
    pub fn into_parts(self) -> (quinn::Connection, BiStream, PlatformId, bool) {
        (
            self.connection,
            self.stream,
            self.platform_id,
            self.corpus_appraisal_success,
        )
    }
}

impl AsyncRead for AttestedConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AttestedConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
