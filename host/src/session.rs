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
use sprockets_session::MAX_HANDSHAKE_MSG_SIZE;
use std::error::Error;
use std::io;
use std::time::Duration;
use std::time::Instant;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

const TAG_SIZE: usize =
    <<ChaCha20Poly1305 as AeadCore>::TagSize as Unsigned>::USIZE;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("connection closed")]
    Closed,
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
    #[error("handshake error: received overlarge length prefix {0}")]
    OverlargeLengthPrefix(usize),
}

pub struct Session<Chan> {
    channel: Chan,
    remote_identity: Identity,
    session: RawSession,
    recv_buf: RecvBuf,
    send_buf: Vec<u8>,
    max_message_size: usize,
}

impl<Chan> Session<Chan>
where
    Chan: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn new_client<T: RotTransport>(
        mut channel: Chan,
        manufacturing_public_key: Ed25519PublicKey,
        rot: &RotManagerHandle<T>,
        rot_certs: Ed25519Certificates,
        rot_timeout: Duration,
        max_message_size: usize,
    ) -> Result<Self, SessionHandshakeError<T::Error>> {
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

        Ok(Self::new_common(
            channel,
            remote_identity,
            session,
            max_message_size,
        ))
    }

    pub async fn new_server<T: RotTransport>(
        mut channel: Chan,
        manufacturing_public_key: Ed25519PublicKey,
        rot: &RotManagerHandle<T>,
        rot_certs: Ed25519Certificates,
        rot_timeout: Duration,
        max_message_size: usize,
    ) -> Result<Self, SessionHandshakeError<T::Error>> {
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

        Ok(Self::new_common(
            channel,
            remote_identity,
            session,
            max_message_size,
        ))
    }

    fn new_common(
        channel: Chan,
        remote_identity: Identity,
        session: RawSession,
        max_message_size: usize,
    ) -> Self {
        // Allocate space in our send/recv buffers for the max message plus our
        // overhead (4-byte length prefix and auth tag).
        let max_msg_with_tag = max_message_size + TAG_SIZE;
        assert!(max_msg_with_tag < u32::MAX as usize);
        let buf_size = max_msg_with_tag + 4;

        Self {
            channel,
            remote_identity,
            session,
            recv_buf: RecvBuf::with_capacity(buf_size),
            send_buf: Vec::with_capacity(buf_size),
            max_message_size,
        }
    }

    /// Send a message to the server through our encrypted session.
    ///
    /// This method is NOT cancel-safe.
    pub async fn send(&mut self, message: &[u8]) -> Result<(), SessionError> {
        if message.len() > self.max_message_size {
            return Err(SessionError::TooLong {
                max: self.max_message_size,
            });
        }

        // Compute total message length. We know this fits in a u32 because of
        // the check against `max_message_size` and our assertion in
        // `new_common` that the max message size (plus overhead) fits in a u32.
        let len = u32::try_from(message.len() + TAG_SIZE).unwrap();

        // Pack `[length_prefix || message]` into our buffer.
        self.send_buf.clear();
        self.send_buf.extend_from_slice(&len.to_be_bytes());
        self.send_buf.extend_from_slice(message);

        // Encrypt message in place.
        let tag = self
            .session
            .encrypt_in_place_detached(&mut self.send_buf[4..])
            .map_err(SessionError::SprocketsError)?;

        // Append tag to our buffer.
        assert_eq!(tag.len(), TAG_SIZE);
        self.send_buf.extend_from_slice(&tag);

        self.channel
            .write_all(&self.send_buf)
            .await
            .map_err(SessionError::Write)
    }

    /// Receive a message from the server through our encrypted session.
    //
    // TODO document cancellation safety; I belive this method _is_ cancel safe,
    // because we only await on `.read()` which is cancel safe, and we keep our
    // own internal (resumable) state when it returns. Need to confirm.
    pub async fn recv(&mut self) -> Result<&[u8], SessionError> {
        let buf = self
            .recv_buf
            .recv_length_prefixed(
                &mut self.channel,
                self.max_message_size + TAG_SIZE,
            )
            .await?;

        // Reject too-short messages.
        if buf.len() < TAG_SIZE {
            return Err(SessionError::TooShortForAuthTag);
        }

        // Split into encrypted message and auth tag.
        let (buf, tag) = buf.split_at_mut(buf.len() - TAG_SIZE);
        let tag = Tag::from_slice(tag);

        self.session
            .decrypt_in_place_detached(buf, tag)
            .map_err(SessionError::SprocketsError)?;

        Ok(buf)
    }

    /// Get the client's remote identity.
    pub fn remote_identity(&self) -> Identity {
        self.remote_identity
    }
}

struct RecvBuf {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl RecvBuf {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: vec![0; capacity],
            start: 0,
            end: 0,
        }
    }

    async fn recv_length_prefixed<Chan>(
        &mut self,
        channel: &mut Chan,
        max_message_size: usize,
    ) -> Result<&mut [u8], SessionError>
    where
        Chan: AsyncRead + AsyncWrite + Unpin,
    {
        // Ensure we were allocated with enough space for `max_message_size` and
        // its length prefix.
        assert!(max_message_size <= self.buf.len() - 4);

        loop {
            // Do we have a 4-byte length prefix?
            if self.end - self.start >= 4 {
                // Extract length
                let len = u32::from_be_bytes(
                    self.buf[self.start..self.start + 4].try_into().unwrap(),
                ) as usize;

                // Reject too-long messages.
                if len > max_message_size {
                    return Err(SessionError::TooLong {
                        max: max_message_size,
                    });
                }

                // Do we have the full message?
                if self.end - self.start - 4 >= len {
                    let msg =
                        &mut self.buf[self.start + 4..self.start + 4 + len];

                    // Update `self.start` so we'll discard this message the
                    // next time `recv_encrypted()` is called.
                    self.start += 4 + len;

                    return Ok(msg);
                }
            }

            // Shift any old data out to minimize the number of times we read
            // from `channel`.
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                let new_end = self.end - self.start;
                self.start = 0;
                self.end = new_end;
            }

            let n = channel
                .read(&mut self.buf[self.end..])
                .await
                .map_err(SessionError::Read)?;
            if n == 0 {
                return Err(SessionError::Closed);
            }
            self.end += n;
        }
    }
}

#[derive(Debug, Default)]
struct SendBuf {
    buf: Vec<u8>,
}

impl SendBuf {
    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    // Append `msg` to our buffer, prepended by a length prefix.
    fn append_message(&mut self, msg: &[u8]) {
        let prefix =
            u32::try_from(msg.len()).expect("message length overflows u32");
        self.buf.extend_from_slice(&prefix.to_be_bytes());
        self.buf.extend_from_slice(msg);
    }

    // Write all the buffered data we contain to `channel`, then clear our
    // buffer.
    async fn write_all<Chan>(&mut self, channel: &mut Chan) -> io::Result<()>
    where
        Chan: AsyncWrite + Unpin,
    {
        channel.write_all(&self.buf).await?;
        self.buf.clear();
        Ok(())
    }
}

async fn client_handshake<Chan, T>(
    channel: &mut Chan,
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
    let mut send_buf = SendBuf::default();
    let mut recv_buf = RecvBuf::with_capacity(MAX_HANDSHAKE_MSG_SIZE + 4);

    // Send the ClientHello
    send_buf.append_message(&buf);
    send_buf
        .write_all(channel)
        .await
        .map_err(SessionError::Write)?;

    // Receive the ServerHello
    let msg = recv_buf
        .recv_length_prefixed(channel, MAX_HANDSHAKE_MSG_SIZE)
        .await?;
    buf.clear();
    buf.extend_from_slice(msg).unwrap();

    // Handle the ServerHello and retrieve the next action to take
    let mut action = handshake
        .handle(&mut buf, token)
        .map_err(SessionError::SprocketsError)?;

    // Keep executing handshake actions until complete
    loop {
        action = match action {
            UserAction::Recv(token) => {
                // If we have buffered data to send, send it before receiving.
                if !send_buf.is_empty() {
                    send_buf
                        .write_all(channel)
                        .await
                        .map_err(SessionError::Write)?;
                }
                let msg = recv_buf
                    .recv_length_prefixed(channel, MAX_HANDSHAKE_MSG_SIZE)
                    .await?;
                buf.clear();
                buf.extend_from_slice(msg).unwrap();
                handshake
                    .handle(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Send(token) => {
                let next_action = handshake
                    .create_next_msg(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?;
                send_buf.append_message(&buf);
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
                if !send_buf.is_empty() {
                    send_buf
                        .write_all(channel)
                        .await
                        .map_err(SessionError::Write)?;
                }
                return Ok((handshake, token));
            }
        }
    }
}

async fn server_handshake<Chan, T>(
    channel: &mut Chan,
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
    let mut send_buf = SendBuf::default();

    // Receive the ClientHello
    let mut buf = HandshakeMsgVec::new();
    let mut recv_buf = RecvBuf::with_capacity(MAX_HANDSHAKE_MSG_SIZE + 4);
    let msg = recv_buf
        .recv_length_prefixed(channel, MAX_HANDSHAKE_MSG_SIZE)
        .await?;
    buf.extend_from_slice(msg).unwrap();

    // Handle the ClientHello and retrieve the next action to take
    let mut action = handshake
        .handle(&mut buf, token)
        .map_err(SessionError::SprocketsError)?;

    // Keep executing handshake actions until complete
    loop {
        action = match action {
            UserAction::Recv(token) => {
                // If we have buffered data to send, send it before receiving.
                if !send_buf.is_empty() {
                    send_buf
                        .write_all(channel)
                        .await
                        .map_err(SessionError::Write)?;
                }
                let msg = recv_buf
                    .recv_length_prefixed(channel, MAX_HANDSHAKE_MSG_SIZE)
                    .await?;
                buf.clear();
                buf.extend_from_slice(msg).unwrap();
                handshake
                    .handle(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?
            }
            UserAction::Send(token) => {
                let next_action = handshake
                    .create_next_msg(&mut buf, token)
                    .map_err(SessionError::SprocketsError)?;
                send_buf.append_message(&buf);
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
                if !send_buf.is_empty() {
                    send_buf
                        .write_all(channel)
                        .await
                        .map_err(SessionError::Write)?;
                }
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

    async fn bootstrap(
        max_message_size: usize,
    ) -> (Session<DuplexStream>, Session<DuplexStream>) {
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

        let (client_stream, server_stream) =
            tokio::io::duplex(max_message_size + 4 + TAG_SIZE);

        let client_fut = Session::new_client(
            client_stream,
            manufacturing_public_key,
            &client_handle,
            client_certs,
            Duration::from_secs(10),
            max_message_size,
        );
        let server_fut = Session::new_server(
            server_stream,
            manufacturing_public_key,
            &server_handle,
            server_certs,
            Duration::from_secs(10),
            max_message_size,
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
        let (mut client, mut server) = bootstrap(32).await;

        for i in 0..10 {
            let msg = format!("hello {} from client", i);
            client.send(msg.as_bytes()).await.unwrap();
            assert_eq!(server.recv().await.unwrap(), msg.as_bytes());

            // Every other test, also send a message from server -> client.
            if i % 2 == 0 {
                continue;
            }

            let msg = format!("hello {} from server", i);
            server.send(msg.as_bytes()).await.unwrap();
            assert_eq!(client.recv().await.unwrap(), msg.as_bytes());
        }
    }

    #[tokio::test]
    async fn reject_too_long_messages() {
        let (mut client, mut server) = bootstrap(4).await;

        // Sending a 4-byte message is fine
        client.send(b"0123").await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"0123");

        // Trying to send a 5-byte message should fail
        assert!(matches!(
            client.send(b"01234").await.unwrap_err(),
            SessionError::TooLong { max: 4 }
        ));

        // Recv should reject messages as soon as it reads a length prefix
        // greater than 4 + TAG_SIZE bytes; confirm this by grabbing the raw
        // channel from the client, sending an overlong length prefix, and
        // confirming an error on the server recv.
        let length_prefix = (4 + TAG_SIZE + 1) as u32;
        client
            .channel
            .write_all(&length_prefix.to_be_bytes())
            .await
            .unwrap();

        assert!(matches!(
            server.recv().await.unwrap_err(),
            SessionError::TooLong { max: 20 }
        ));
    }

    #[tokio::test]
    async fn reject_too_short_messages() {
        let (mut client, mut server) = bootstrap(4).await;

        // Sending 0-length messages through the normal process is fine...
        client.send(b"").await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"");

        // ... but sending a length prefix that's < TAG_SIZE should fail
        let length_prefix = TAG_SIZE - 1;
        client
            .channel
            .write_all(&length_prefix.to_be_bytes())
            .await
            .unwrap();

        assert!(matches!(
            server.recv().await.unwrap_err(),
            SessionError::TooShortForAuthTag
        ));
    }

    #[tokio::test]
    async fn detect_remote_end_closing_connection() {
        let (mut client, server) = bootstrap(4).await;
        mem::drop(server);

        assert!(matches!(
            client.send(b"hi").await.unwrap_err(),
            SessionError::Write { .. }
        ));
        assert!(matches!(
            client.recv().await.unwrap_err(),
            SessionError::Closed,
        ));
    }
}
