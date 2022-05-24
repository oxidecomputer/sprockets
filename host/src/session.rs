// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! High-level Sprockets session API, akin to a TLS session.

mod aead_read_buf;
mod aead_write_buf;
mod decrypting_buf_reader;
mod encrypting_buf_writer;

use crate::rot_manager::RotManagerError;
use crate::rot_manager::RotManagerHandle;
use futures::ready;
use pin_project::pin_project;
use sprockets_common::certificates::Ed25519Certificates;
use sprockets_common::msgs::RotError;
use sprockets_common::Ed25519PublicKey;
use sprockets_session::generic_array::typenum::Unsigned;
use sprockets_session::AeadCore;
use sprockets_session::ChaCha20Poly1305;
use sprockets_session::ClientHandshake;
use sprockets_session::CompletionToken;
use sprockets_session::HandshakeMsgVec;
use sprockets_session::Identity;
use sprockets_session::ServerHandshake;
use sprockets_session::Session as RawSession;
use sprockets_session::Tag;
use sprockets_session::UserAction;
use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;

use self::decrypting_buf_reader::DecryptingBufReader;
use self::encrypting_buf_writer::EncryptingBufWriter;

const TAG_SIZE: usize =
    <<ChaCha20Poly1305 as AeadCore>::TagSize as Unsigned>::USIZE;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("I/O error writing to underlying channel: {0}")]
    Write(io::Error),
    #[error("I/O error reading from underlying channel: {0}")]
    Read(io::Error),
    #[error("sprockets error: {0:?}")]
    SprocketsError(sprockets_session::Error),
    #[error("message too short (missing auth tag)")]
    TooShortForAuthTag,
    #[error("message too long (max message size is {max})")]
    TooLong { max: usize },
}

#[derive(Debug, Error)]
pub enum SessionHandshakeError<E: Error> {
    #[error(transparent)]
    SessionError(#[from] SessionError),
    #[error("RoT error: {0:?}")]
    RotError(RotError),
    #[error("communication with RoT failed: {0:?}")]
    RotCommunicationError(#[from] RotManagerError<E>),
}

#[pin_project]
pub struct Session<Chan> {
    #[pin]
    channel: Chan,
    remote_identity: Identity,
    session: RawSession,
    writer: EncryptingBufWriter,
    reader: DecryptingBufReader,
}

// Buffer size we use for reading/writing encrypted frames to the underlying channel.
//
// NOTE: The actual size of the buffer is the size of the frame which includes a
// 4 byte size header and an AEAD tag trailer of `TAG_SIZE`.
const BUFFER_SIZE: usize = 8192;

impl<Chan> Session<Chan>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn new_client<E: Error>(
        mut channel: Chan,
        manufacturing_public_key: Ed25519PublicKey,
        rot: RotManagerHandle<E>,
        rot_certs: Ed25519Certificates,
        rot_timeout: Duration,
    ) -> Result<Self, SessionHandshakeError<E>> {
        let (handshake, completion_token) = client_handshake(
            &mut channel,
            manufacturing_public_key,
            &rot,
            rot_certs,
            rot_timeout,
        )
        .await?;

        let remote_identity = *completion_token.remote_identity();
        let session = handshake.new_session(completion_token);

        Ok(Self {
            channel,
            remote_identity,
            session,
            writer: EncryptingBufWriter::with_capacity(BUFFER_SIZE),
            reader: DecryptingBufReader::with_capacity(BUFFER_SIZE),
        })
    }

    pub async fn new_server<E: Error>(
        mut channel: Chan,
        manufacturing_public_key: Ed25519PublicKey,
        rot: RotManagerHandle<E>,
        rot_certs: Ed25519Certificates,
        rot_timeout: Duration,
    ) -> Result<Self, SessionHandshakeError<E>> {
        let (handshake, completion_token) = server_handshake(
            &mut channel,
            manufacturing_public_key,
            &rot,
            rot_certs,
            rot_timeout,
        )
        .await?;

        let remote_identity = *completion_token.remote_identity();
        let session = handshake.new_session(completion_token);

        Ok(Self {
            channel,
            remote_identity,
            session,
            writer: EncryptingBufWriter::with_capacity(BUFFER_SIZE),
            reader: DecryptingBufReader::with_capacity(BUFFER_SIZE),
        })
    }

    /// Get a reference to the underlying communication channel.
    pub fn get_ref(&self) -> &Chan {
        &self.channel
    }

    /// Get the client's remote identity.
    pub fn remote_identity(&self) -> Identity {
        self.remote_identity
    }
}

// Helper function to avoid repeating this closure in each of the `AsyncWrite`
// methods below.
//
// Encryption errors are opaque to avoid leaking info so we return `()`.
fn encrypt_via_session(
    session: &mut RawSession,
) -> impl FnOnce(&mut [u8]) -> Result<Tag, ()> + '_ {
    |buf| session.encrypt_in_place_detached(buf).map_err(|_| ())
}

impl<Chan: AsyncWrite> AsyncWrite for Session<Chan> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let me = self.project();
        me.writer.poll_write(
            me.channel,
            cx,
            buf,
            encrypt_via_session(me.session),
        )
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut me = self.project();
        ready!(me.writer.poll_flush(
            me.channel.as_mut(),
            cx,
            encrypt_via_session(me.session)
        ))?;
        me.channel.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut me = self.project();
        ready!(me.writer.poll_flush(
            me.channel.as_mut(),
            cx,
            encrypt_via_session(me.session),
        ))?;
        me.channel.poll_shutdown(cx)
    }
}

impl<Chan: AsyncRead> AsyncRead for Session<Chan> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.project();
        me.reader.poll_read(me.channel, cx, buf, |buf, tag| {
            me.session
                .decrypt_in_place_detached(buf, tag)
                .map_err(|_| ())
        })
    }
}

// Helper function to send length-prefixed data during the handshake.
async fn send_length_prefixed<Chan>(
    channel: &mut Chan,
    buf: &HandshakeMsgVec,
) -> Result<(), SessionError>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
{
    let len = buf.len() as u32;
    channel
        .write_all(&len.to_be_bytes())
        .await
        .map_err(SessionError::Write)?;
    channel.write_all(buf).await.map_err(SessionError::Write)
}

// Helper function to receive length-prefixed data during the handshake.
async fn recv_length_prefixed<Chan>(
    channel: &mut Chan,
    buf: &mut HandshakeMsgVec,
) -> Result<(), SessionError>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = [0; 4];
    channel
        .read_exact(&mut prefix)
        .await
        .map_err(SessionError::Read)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > buf.capacity() {
        return Err(SessionError::TooLong {
            max: buf.capacity(),
        });
    }

    buf.resize_default(len).unwrap();
    channel.read_exact(buf).await.map_err(SessionError::Read)?;

    Ok(())
}

async fn client_handshake<Chan, E>(
    channel: &mut Chan,
    manufacturing_public_key: Ed25519PublicKey,
    rot: &RotManagerHandle<E>,
    rot_certs: Ed25519Certificates,
    rot_timeout: Duration,
) -> Result<(ClientHandshake, CompletionToken), SessionHandshakeError<E>>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
    E: Error,
{
    // We issue multiple write calls for length+payload, so wrap `channel` in a
    // buffering writer to avoid sending multiple packets per message. We
    // _cannot_ buffer reading, because we risk BufReader eagerly slurping
    // application data that comes in after handshake data.
    let mut channel = BufWriter::new(channel);
    let mut buf = HandshakeMsgVec::new();
    let (mut handshake, token) =
        ClientHandshake::init(manufacturing_public_key, rot_certs, &mut buf);

    // Send the ClientHello
    send_length_prefixed(&mut channel, &buf).await?;
    channel.flush().await.map_err(SessionError::Write)?;

    // Receive the ServerHello
    recv_length_prefixed(&mut channel, &mut buf).await?;

    // Handle the ServerHello and retrieve the next action to take
    let mut action = handshake
        .handle(&mut buf, token)
        .map_err(SessionError::SprocketsError)?;

    // Keep executing handshake actions until complete
    loop {
        action = match action {
            UserAction::Recv(token) => {
                // If we have buffered data to send, send it before receiving.
                //
                // TODO-perf: Flushing here means the server will receive
                // multiple messages simultaneously. This is better from a local
                // perspective (fewer sys calls, fewer network packets), but
                // might actually be slower overall if the remote RoT becomes
                // the bottleneck and it could've started working sooner if we
                // sent our earlier messages ASAP. We should profile flushing
                // here and in `Complete` compared to always flushing in `Send`.
                // This comment also applies to `server_handshake`.
                channel.flush().await.map_err(SessionError::Write)?;
                recv_length_prefixed(&mut channel, &mut buf).await?;
                handshake
                    .handle(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Send(token) => {
                let next_action = handshake
                    .create_next_msg(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?;
                send_length_prefixed(&mut channel, &buf).await?;
                next_action
            }
            UserAction::SendToRot(op) => {
                let resp = rot.call(op, Instant::now() + rot_timeout).await?;
                handshake
                    .handle_rot_reply(resp)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Complete(token) => {
                // If we have buffered data to send, send it before completing.
                channel.flush().await.map_err(SessionError::Write)?;
                return Ok((handshake, token));
            }
        }
    }
}

async fn server_handshake<Chan, E>(
    channel: &mut Chan,
    manufacturing_public_key: Ed25519PublicKey,
    rot: &RotManagerHandle<E>,
    rot_certs: Ed25519Certificates,
    rot_timeout: Duration,
) -> Result<(ServerHandshake, CompletionToken), SessionHandshakeError<E>>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
    E: Error,
{
    // We issue multiple write calls for length+payload, so wrap `channel` in a
    // buffering writer to avoid sending multiple packets per message. We
    // _cannot_ buffer reading, because we risk BufReader eagerly slurping
    // application data that comes in after handshake data.
    let mut channel = BufWriter::new(channel);
    let (mut handshake, token) =
        ServerHandshake::init(manufacturing_public_key, rot_certs);

    // Receive the ClientHello
    let mut buf = HandshakeMsgVec::new();
    recv_length_prefixed(&mut channel, &mut buf).await?;

    // Handle the ClientHello and retrieve the next action to take
    let mut action = handshake
        .handle(&mut buf, token)
        .map_err(SessionError::SprocketsError)?;

    // Keep executing handshake actions until complete
    loop {
        action = match action {
            UserAction::Recv(token) => {
                // If we have buffered data to send, send it before receiving.
                channel.flush().await.map_err(SessionError::Write)?;
                recv_length_prefixed(&mut channel, &mut buf).await?;
                handshake
                    .handle(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Send(token) => {
                let next_action = handshake
                    .create_next_msg(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?;
                send_length_prefixed(&mut channel, &buf).await?;
                next_action
            }
            UserAction::SendToRot(op) => {
                let resp = rot.call(op, Instant::now() + rot_timeout).await?;
                handshake
                    .handle_rot_reply(resp)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Complete(token) => {
                // If we have buffered data to send, send it before completing.
                channel.flush().await.map_err(SessionError::Write)?;
                return Ok((handshake, token));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rot_manager::tests::test_logger;
    use crate::rot_manager::tests::TestTransport;
    use crate::rot_manager::RotManager;
    use sprockets_common::random_buf;
    use std::mem;
    use std::thread;
    use tokio::io::DuplexStream;

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
        let (server_mgr, server_handle) =
            RotManager::new(32, server_rot, logger);

        thread::spawn(move || client_mgr.run());
        thread::spawn(move || server_mgr.run());

        let (client_stream, server_stream) = tokio::io::duplex(1024);

        let client_fut = Session::new_client(
            client_stream,
            manufacturing_public_key,
            client_handle.clone(),
            client_certs,
            Duration::from_secs(10),
        );
        let server_fut = Session::new_server(
            server_stream,
            manufacturing_public_key,
            server_handle.clone(),
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

    #[tokio::test]
    async fn hello_world() {
        let (mut client, mut server) = bootstrap().await;
        let mut buf = vec![0; 32];

        for i in 0..10 {
            let msg = format!("hello {} from client", i);
            client.write_all(msg.as_bytes()).await.unwrap();
            client.flush().await.unwrap();
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());

            // Every other test, also send a message from server -> client.
            if i % 2 == 0 {
                continue;
            }

            let msg = format!("hello {} from server", i);
            server.write_all(msg.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }
    }

    #[tokio::test]
    async fn detect_remote_end_closing_connection() {
        let (mut client, server) = bootstrap().await;
        mem::drop(server);

        client.write(b"hi").await.unwrap();
        let err = client.flush().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let mut buf = [0];
        let err = client.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
