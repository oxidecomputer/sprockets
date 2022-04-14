// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chacha20poly1305::aead::heapless::Vec;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{self, ChaCha20Poly1305, Key};
use derive_more::From;
use hkdf::Hkdf;
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::msgs::*;
use sprockets_common::certificates::Ed25519Certificates;
use sprockets_common::{Ed25519PublicKey, Nonce};

// The length of the nonce for ChaCha20Poly1305
const NONCE_LEN: usize = 12;

// The length of a digest or nonce as a big endian u16
const ENCODED_LEN: usize = 2;

// The length of a SHA3-256 digest
const DIGEST_LEN: usize = 32;

// The length of a ChaCha20Poly1305 Key
const KEY_LEN: usize = 32;

// The length of a label used to create an ApplicationSalt
const APP_SALT_LABEL_LEN: usize = 12;

pub enum State {
    Hello {
        secret: EphemeralSecret,
    },
    WaitForIdentity {
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
}

pub struct Client {
    certs: Ed25519Certificates,
    transcript: Sha3_256,
    // Must be an option to allow moving out of the type when switching between
    // states.
    state: Option<State>,
}

#[derive(Debug, PartialEq, Eq, From)]
pub enum Error {
    BadVersion,
    UnexpectedMsg,
    Hubpack(hubpack::error::Error),
    DecryptError,
}

impl Client {
    /// Initialize the Client and serialize the ClientHello message into `buf`.
    ///
    /// Return the Client and the size of the serialize message.
    ///
    /// `buf` must be at least `HandshakeMsgV1::MAX_SIZE` bytes;
    pub fn init(certs: Ed25519Certificates, buf: &mut [u8]) -> (Client, usize) {
        let secret = EphemeralSecret::new(OsRng);
        let public_key = PublicKey::from(&secret);

        let state = State::Hello { secret };

        let msg = HandshakeMsgV1::new(
            ClientHello {
                nonce: Nonce::new(),
                public_key: Ed25519PublicKey(public_key.to_bytes()),
            }
            .into(),
        );

        let mut transcript = Sha3_256::new();
        let size = serialize(buf, &msg).unwrap();
        transcript.update(&buf[..size]);

        let client = Client {
            certs,
            transcript,
            state: Some(state),
        };

        (client, size)
    }

    /// Handle a message from the server
    ///
    /// Intentionally return an opaque error.
    pub fn handle(&mut self, buf: &[u8]) -> Result<(), Error> {
        let state = self.state.take().unwrap();
        match state {
            State::Hello { secret } => self.handle_hello(secret, buf),
            State::WaitForIdentity {
                server_nonce,
                handshake_state,
            } => self.handle_identity(server_nonce, handshake_state, buf),
            _ => unimplemented!(),
        }
    }

    fn handle_hello(&mut self, secret: EphemeralSecret, buf: &[u8]) -> Result<(), Error> {
        let (msg, _) = deserialize::<HandshakeMsgV1>(&buf)?;
        Self::validate_version(&msg.version)?;
        if let HandshakeMsgDataV1::ServerHello(hello) = msg.data {
            self.transcript.update(buf);
            // We clone so we can use the intermediate hash value but maintain
            // the running hash computation.
            let transcript_hash = self.transcript.clone().finalize();
            let public_key = PublicKey::from(hello.public_key.0);
            let handshake_state =
                HandshakeState::new(secret, &public_key, transcript_hash.as_slice());
            self.state = Some(State::WaitForIdentity {
                server_nonce: hello.nonce,
                handshake_state,
            });
            Ok(())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    fn handle_identity(
        &mut self,
        server_nonce: Nonce,
        handshake_state: HandshakeState,
        buf: &[u8],
    ) -> Result<(), Error> {
        unimplemented!();
    }

    fn validate_version(version: &HandshakeVersion) -> Result<(), Error> {
        if version.version != 1 {
            return Err(Error::BadVersion);
        }
        Ok(())
    }
}

/// Keys, IVs, AEADs used for the handshake traffic
pub struct HandshakeState {
    client_aead: ChaCha20Poly1305,
    server_aead: ChaCha20Poly1305,
    application_salt: Zeroizing<[u8; DIGEST_LEN]>,
    nonce_counter: u64,
    server_iv: Zeroizing<[u8; NONCE_LEN]>,
    client_iv: Zeroizing<[u8; NONCE_LEN]>,
    server_finished_key: Zeroizing<[u8; DIGEST_LEN]>,
    client_finished_key: Zeroizing<[u8; DIGEST_LEN]>,
}

impl HandshakeState {
    /// Compute a shared secret via x25519 and derive HandshakeKeys using HKDF
    pub fn new(
        my_secret: EphemeralSecret,
        peer_public_key: &PublicKey,
        transcript: &[u8],
    ) -> HandshakeState {
        let initial_salt = [0u8; 32];
        let shared_secret = my_secret.diffie_hellman(peer_public_key);
        let handshake_secret = Hkdf::<Sha3_256>::new(Some(&initial_salt), shared_secret.as_bytes());

        let mut client_handshake_secret_buf = Zeroizing::new([0u8; KEY_LEN]);
        handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 c hs", transcript],
                client_handshake_secret_buf.as_mut(),
            )
            .unwrap();

        let mut server_handshake_secret_buf = Zeroizing::new([0u8; KEY_LEN]);
        handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 s hs", transcript],
                server_handshake_secret_buf.as_mut(),
            )
            .unwrap();

        // Setup handshake traffic secrets to be used to generate keys and IVs
        // via HKDF-Expand
        let client_handshake_secret =
            Hkdf::<Sha3_256>::from_prk(client_handshake_secret_buf.as_ref()).unwrap();
        let server_handshake_secret =
            Hkdf::<Sha3_256>::from_prk(server_handshake_secret_buf.as_ref()).unwrap();

        // Create traffic keys and IVs
        let mut client_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut server_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut client_iv = Zeroizing::new([0u8; NONCE_LEN]);
        let mut server_iv = Zeroizing::new([0u8; NONCE_LEN]);

        client_handshake_secret
            .expand_multi_info(&[&digest_len_buf()[..], b"spr1 key"], client_key.as_mut())
            .unwrap();

        server_handshake_secret
            .expand_multi_info(&[&digest_len_buf()[..], b"spr1 key"], server_key.as_mut())
            .unwrap();

        client_handshake_secret
            .expand_multi_info(&[&nonce_len_buf()[..], b"spr1 iv"], client_iv.as_mut())
            .unwrap();

        server_handshake_secret
            .expand_multi_info(&[&nonce_len_buf()[..], b"spr1 iv"], server_iv.as_mut())
            .unwrap();

        let client_aead = ChaCha20Poly1305::new(Key::from_slice(client_key.as_ref()));
        let server_aead = ChaCha20Poly1305::new(Key::from_slice(server_key.as_ref()));

        // Generate Finished keys
        let mut client_finished_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut server_finished_key = Zeroizing::new([0u8; KEY_LEN]);

        client_handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 finished"],
                client_finished_key.as_mut(),
            )
            .unwrap();

        server_handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 finished"],
                server_finished_key.as_mut(),
            )
            .unwrap();

        // Generate application salt
        let mut application_salt = Zeroizing::new([0u8; DIGEST_LEN]);
        handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 derived"],
                application_salt.as_mut(),
            )
            .unwrap();

        HandshakeState {
            client_aead,
            server_aead,
            application_salt,
            nonce_counter: 0,
            server_iv,
            client_iv,
            server_finished_key,
            client_finished_key,
        }
    }
}

// This uses the construction from section 5.3 or RFC 8446
//
// XOR the IV with the big-endian counter 0 padded to the left.
//
// The IV is 12 bytes (96 bits)
fn new_chach20poly1305nonce(iv: &[u8], counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
        .iter_mut()
        .zip(iv.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    nonce
}

// Return a 2-byte big endian encoded buf containing digest size
fn digest_len_buf() -> [u8; ENCODED_LEN] {
    let digest_len = u16::try_from(DIGEST_LEN).unwrap();
    digest_len.to_be_bytes()
}

// Return a 2 byte big endian encoded buf containing nonce size
//
// Note that nonce size = iv size
fn nonce_len_buf() -> [u8; ENCODED_LEN] {
    let nonce_len = u16::try_from(NONCE_LEN).unwrap();
    nonce_len.to_be_bytes()
}
