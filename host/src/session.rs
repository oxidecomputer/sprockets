// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! High-level Sprockets session API, akin to a TLS session.

use crate::rot_manager::RotManagerError;
use crate::rot_manager::RotManagerHandle;
use crate::rot_manager::RotTransport;
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
use std::time::Duration;
use std::time::Instant;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::BufStream;

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

pub struct Session<Chan> {
    // We want to read/write small buffers (4-byte length prefixes and 16-byte
    // auth tags), so wrap `channel` in a `BufStream`. This requires us to
    // remember to flush at times, but allows the otherwise-straightline
    // read/write code.
    channel: BufStream<Chan>,
    remote_identity: Identity,
    session: RawSession,
    encrypt_buf: Vec<u8>,
}

impl<Chan> Session<Chan>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn new_client<T: RotTransport>(
        channel: Chan,
        manufacturing_public_key: Ed25519PublicKey,
        rot: &RotManagerHandle<T>,
        rot_certs: Ed25519Certificates,
        rot_timeout: Duration,
    ) -> Result<Self, SessionHandshakeError<T::Error>> {
        let mut channel = BufStream::new(channel);
        let (handshake, completion_token) = client_handshake(
            &mut channel,
            manufacturing_public_key,
            rot,
            rot_certs,
            rot_timeout,
        )
        .await?;

        let remote_identity = completion_token.remote_identity().clone();
        let session = handshake.new_session(completion_token);

        Ok(Self {
            channel,
            remote_identity,
            session,
            encrypt_buf: Vec::new(),
        })
    }

    pub async fn new_server<T: RotTransport>(
        channel: Chan,
        manufacturing_public_key: Ed25519PublicKey,
        rot: &RotManagerHandle<T>,
        rot_certs: Ed25519Certificates,
        rot_timeout: Duration,
    ) -> Result<Self, SessionHandshakeError<T::Error>> {
        let mut channel = BufStream::new(channel);
        let (handshake, completion_token) = server_handshake(
            &mut channel,
            manufacturing_public_key,
            rot,
            rot_certs,
            rot_timeout,
        )
        .await?;

        let remote_identity = completion_token.remote_identity().clone();
        let session = handshake.new_session(completion_token);

        Ok(Self {
            channel,
            remote_identity,
            session,
            encrypt_buf: Vec::new(),
        })
    }

    /// Send a message to the remote side through our encrypted session.
    ///
    /// `message` will first be copied into an internal buffer for encryption.
    /// To avoid this copy, use [`send_in_place()`](Self::send_in_place)
    /// instead.
    ///
    /// This method is NOT cancel-safe.
    pub async fn send(&mut self, message: &[u8]) -> Result<(), SessionError> {
        // Copy message into our buffer.
        self.encrypt_buf.clear();
        self.encrypt_buf.extend_from_slice(message);
        self.encrypt_and_send(None).await
    }

    /// Encrypt `message` in place and then send it to the remote side.
    ///
    /// This method is NOT cancel-safe.
    pub async fn send_in_place(
        &mut self,
        message: &mut [u8],
    ) -> Result<(), SessionError> {
        self.encrypt_and_send(Some(message)).await
    }

    // Private helper function to appease the borrow checker: if it's `Some(_)`,
    // it contains the plaintext in a caller-provided buffer; if it's `None`,
    // the plaintext is taken from `self.encrypt_buf`.
    async fn encrypt_and_send(
        &mut self,
        plaintext: Option<&mut [u8]>,
    ) -> Result<(), SessionError> {
        // Encrypt plaintext.
        let message = plaintext.unwrap_or(&mut self.encrypt_buf);
        let tag = self
            .session
            .encrypt_in_place_detached(message)
            .map_err(SessionError::SprocketsError)?;

        // Compute total message length.
        assert_eq!(tag.len(), TAG_SIZE);
        if message.len() + TAG_SIZE > u32::MAX as usize {
            return Err(SessionError::TooLong {
                max: u32::MAX as usize - TAG_SIZE,
            })
        }

        // Write [length | ciphertext | tag] to the underlying channel (which
        // buffers all of these messages).
        send_length_prefixed(&mut self.channel, &[message, &tag]).await?;

        // Flush the channel, forcing writes to the underlying stream.
        //
        // TODO-perf: Should we expose the option to flush or not to the user?
        // If most callers are doing paired send/recv it's probably not worth
        // the API overhead, but if some want to do multiple sends and have them
        // coaleseced, it would be an easy change for us.
        self.channel.flush().await.map_err(SessionError::Write)?;

        Ok(())
    }

    /// Receive a message from the server through our encrypted session.
    ///
    /// This method is NOT cancel-safe.
    pub async fn recv<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], SessionError> {
        // Read length prefix.
        let mut prefix = [0; 4];
        self.channel
            .read_exact(&mut prefix)
            .await
            .map_err(SessionError::Read)?;
        let len = u32::from_be_bytes(prefix) as usize;
        let len = len
            .checked_sub(TAG_SIZE)
            .ok_or(SessionError::TooShortForAuthTag)?;
        if len > buf.len() {
            return Err(SessionError::TooLong { max: buf.len() });
        }
        let buf = &mut buf[..len];

        // Read encrypted data.
        self.channel
            .read_exact(buf)
            .await
            .map_err(SessionError::Read)?;

        // Read tag.
        let mut tag = Tag::default();
        self.channel
            .read_exact(&mut tag)
            .await
            .map_err(SessionError::Read)?;

        // Perform decryption.
        self.session
            .decrypt_in_place_detached(buf, &tag)
            .map_err(SessionError::SprocketsError)?;

        Ok(buf)
    }

    /// Get the client's remote identity.
    pub fn remote_identity(&self) -> Identity {
        self.remote_identity
    }
}

/// Send a length-prefixed message on `channel`.
///
/// The message may be divided up into multiple slides for convenience to the
/// caller (e.g., separate encryption and auth tag buffers).
///
/// Panics if the sum of the lengths of all chunks overflows `u32`; callers
/// are responsible for keeping the total length below `u32::MAX`.
async fn send_length_prefixed<Chan>(
    channel: &mut BufStream<Chan>,
    chunks: &[&[u8]],
) -> Result<(), SessionError>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
{
    let len = chunks.iter().map(|chunk| chunk.len()).sum::<usize>();
    let len = u32::try_from(len).expect("message length overflows u32");
    channel
        .write_all(&len.to_be_bytes())
        .await
        .map_err(SessionError::Write)?;
    for chunk in chunks {
        channel
            .write_all(chunk)
            .await
            .map_err(SessionError::Write)?;
    }
    Ok(())
}

// Helper function to receive length-prefixed data during the handshake
// exchange.
async fn recv_length_prefixed<Chan>(
    channel: &mut BufStream<Chan>,
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

async fn client_handshake<Chan, T>(
    channel: &mut BufStream<Chan>,
    manufacturing_public_key: Ed25519PublicKey,
    rot: &RotManagerHandle<T>,
    rot_certs: Ed25519Certificates,
    rot_timeout: Duration,
) -> Result<(ClientHandshake, CompletionToken), SessionHandshakeError<T::Error>>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
    T: RotTransport,
{
    let mut buf = HandshakeMsgVec::new();
    let (mut handshake, token) =
        ClientHandshake::init(manufacturing_public_key, rot_certs, &mut buf);

    // Send the ClientHello
    send_length_prefixed(channel, &[&buf]).await?;
    channel.flush().await.map_err(SessionError::Write)?;

    // Receive the ServerHello
    recv_length_prefixed(channel, &mut buf).await?;

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
                recv_length_prefixed(channel, &mut buf).await?;
                handshake
                    .handle(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Send(token) => {
                let next_action = handshake
                    .create_next_msg(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?;
                send_length_prefixed(channel, &[&buf]).await?;
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

async fn server_handshake<Chan, T>(
    channel: &mut BufStream<Chan>,
    manufacturing_public_key: Ed25519PublicKey,
    rot: &RotManagerHandle<T>,
    rot_certs: Ed25519Certificates,
    rot_timeout: Duration,
) -> Result<(ServerHandshake, CompletionToken), SessionHandshakeError<T::Error>>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
    T: RotTransport,
{
    let (mut handshake, token) =
        ServerHandshake::init(manufacturing_public_key, rot_certs);

    // Receive the ClientHello
    let mut buf = HandshakeMsgVec::new();
    recv_length_prefixed(channel, &mut buf).await?;

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
                recv_length_prefixed(channel, &mut buf).await?;
                handshake
                    .handle(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Send(token) => {
                let next_action = handshake
                    .create_next_msg(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?;
                send_length_prefixed(channel, &[&buf]).await?;
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
    use std::mem;
    use std::thread;

    use super::*;
    use crate::rot_manager::tests::test_logger;
    use crate::rot_manager::tests::TestTransport;
    use crate::rot_manager::RotManager;
    use sprockets_common::random_buf;
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

    #[tokio::test]
    async fn hello_world() {
        let (mut client, mut server) = bootstrap().await;
        let mut buf = vec![0; 32];

        for i in 0..10 {
            let msg = format!("hello {} from client", i);
            client.send(msg.as_bytes()).await.unwrap();
            assert_eq!(server.recv(&mut buf).await.unwrap(), msg.as_bytes());

            // Every other test, also send a message from server -> client.
            if i % 2 == 0 {
                continue;
            }

            let msg = format!("hello {} from server", i);
            server.send(msg.as_bytes()).await.unwrap();
            assert_eq!(client.recv(&mut buf).await.unwrap(), msg.as_bytes());
        }
    }

    #[tokio::test]
    async fn reject_too_long_messages() {
        let (mut client, mut server) = bootstrap().await;

        // Sending a 5-byte message is fine...
        client.send(b"01235").await.unwrap();

        // ... but trying to recv into a 4-long buffer will fail.
        let mut buf = vec![0; 4];
        assert!(matches!(
            server.recv(&mut buf).await.unwrap_err(),
            SessionError::TooLong { max: 4 }
        ));
    }

    #[tokio::test]
    async fn reject_too_short_messages() {
        let (mut client, mut server) = bootstrap().await;
        let mut buf = vec![0; 1];

        // Sending 0-length messages through the normal process is fine...
        client.send(b"").await.unwrap();
        assert_eq!(server.recv(&mut buf).await.unwrap(), b"");

        // ... but sending a length prefix that's < TAG_SIZE should fail
        let length_prefix = TAG_SIZE - 1;
        client
            .channel
            .write_all(&length_prefix.to_be_bytes())
            .await
            .unwrap();
        client.channel.flush().await.unwrap();

        assert!(matches!(
            server.recv(&mut buf).await.unwrap_err(),
            SessionError::TooShortForAuthTag
        ));
    }

    #[tokio::test]
    async fn detect_remote_end_closing_connection() {
        let (mut client, server) = bootstrap().await;
        mem::drop(server);

        assert!(matches!(
            client.send(b"hi").await.unwrap_err(),
            SessionError::Write { .. }
        ));
        match client.recv(&mut []).await.unwrap_err() {
            SessionError::Read(err) => {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof)
            }
            other => panic!("unexpected error {}", other),
        }
    }
}
