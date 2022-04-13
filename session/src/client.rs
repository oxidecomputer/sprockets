// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chacha20poly1305::aead::heapless::Vec;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::msgs::*;
use sprockets_common::{Ed25519PublicKey, Nonce};

pub struct CommonState {
    transcript: Sha3_256,
}

pub enum State {
    Hello {
        secret: EphemeralSecret,
        public_key: PublicKey,
    },
    WaitForIdentity {
        handshake_state: HandshakeState,
    },
}

pub struct Client {
    common: CommonState,
    state: State,
}

impl Client {
    pub fn init() -> (Client, HandshakeMsgV1) {
        let common = CommonState {
            transcript: Sha3_256::new(),
        };
        let secret = EphemeralSecret::new(OsRng);
        let public_key = PublicKey::from(&secret);

        let state = State::Hello { secret, public_key };
        let client = Client { common, state };

        let msg = HandshakeMsgV1::new(
            ClientHello {
                nonce: Nonce::new(),
                public_key: Ed25519PublicKey(public_key.to_bytes()),
            }
            .into(),
        );

        (client, msg)
    }
}

/// AEAD used for the handshake traffic
///
/// We include the application salt because once we calculate it we can throw
/// away the Handshake Secret.
pub struct HandshakeState {
    client_aead: XChaCha20Poly1305,
    server_aead: XChaCha20Poly1305,
    application_salt: Zeroizing<[u8; DIGEST_LEN as usize]>,
}

impl HandshakeState {
    /// Compute a shared secret via x25519 and derive HandshakeKeys using HKDF
    pub fn new(
        my_secret: EphemeralSecret,
        peer_public_key: PublicKey,
        transcript: &[u8],
    ) -> HandshakeState {
        let initial_salt = [0u8; 32];
        let shared_secret = my_secret.diffie_hellman(&peer_public_key);
        let handshake_secret = Hkdf::<Sha3_256>::new(Some(&initial_salt), shared_secret.as_bytes());

        let mut client_key_buf = Zeroizing::new([0u8; KEY_LEN]);
        let client_context = binconcat_secret(b"spr1 c hs", transcript);
        handshake_secret
            .expand(&client_context.0, client_key_buf.as_mut())
            .unwrap();

        let mut server_key_buf = Zeroizing::new([0u8; KEY_LEN]);
        let server_context = binconcat_secret(b"spr1 s hs", transcript);
        handshake_secret
            .expand(&server_context.0, server_key_buf.as_mut())
            .unwrap();

        let client_aead = XChaCha20Poly1305::new(Key::from_slice(client_key_buf.as_ref()));
        let server_aead = XChaCha20Poly1305::new(Key::from_slice(server_key_buf.as_ref()));

        let mut application_salt = Zeroizing::new([0u8; DIGEST_LEN as usize]);
        handshake_secret
            .expand(&AppSaltContext::new().0, application_salt.as_mut())
            .unwrap();

        HandshakeState {
            client_aead,
            server_aead,
            application_salt,
        }
    }
}

// The length of a digest as a big endian u16
const DIGEST_LEN_ENCODED_LEN: usize = 2;

// The length of a SHA3-256 digest
const DIGEST_LEN: usize = 32;

// The length of a XChaCha20Poly1305 Key
const KEY_LEN: usize = 32;

// The length of a label used to create an ApplicationSalt
const APP_SALT_LABEL_LEN: usize = 12;

// Create a context for HKDF-Expand for an application traffic salt
struct AppSaltContext([u8; DIGEST_LEN_ENCODED_LEN + APP_SALT_LABEL_LEN]);

impl AppSaltContext {
    fn new() -> AppSaltContext {
        let digest_len = u16::try_from(DIGEST_LEN).unwrap();
        let label = b"spr1 derived";
        let mut buf = [0u8; DIGEST_LEN_ENCODED_LEN + APP_SALT_LABEL_LEN];
        buf[0..DIGEST_LEN_ENCODED_LEN].copy_from_slice(&digest_len.to_be_bytes());
        buf[DIGEST_LEN_ENCODED_LEN..].copy_from_slice(label);
        AppSaltContext(buf)
    }
}

const SECRET_LABEL_LEN: usize = 9;
const SECRET_CONTEXT_LEN: usize = DIGEST_LEN_ENCODED_LEN + SECRET_LABEL_LEN + DIGEST_LEN as usize;

// Create a context for HKDF-Expand useful for creating secrets
fn binconcat_secret(label: &[u8], transcript_digest: &[u8]) -> SecretContext {
    let digest_len = u16::try_from(DIGEST_LEN).unwrap();
    let mut buf = [0u8; SECRET_CONTEXT_LEN];
    buf[0..DIGEST_LEN_ENCODED_LEN].copy_from_slice(&digest_len.to_be_bytes());
    buf[DIGEST_LEN_ENCODED_LEN..DIGEST_LEN_ENCODED_LEN + SECRET_LABEL_LEN].copy_from_slice(&label);
    buf[SECRET_CONTEXT_LEN - DIGEST_LEN..].copy_from_slice(transcript_digest);
    SecretContext(buf)
}

struct SecretContext([u8; SECRET_CONTEXT_LEN]);