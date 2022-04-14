// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The state needed for handshake encyption by both client and server

use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{self, ChaCha20Poly1305, Key};
use hkdf::Hkdf;
use hubpack::SerializedSize;
use sha3::Sha3_256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::msgs::HandshakeMsgV1;

// The length of the nonce for ChaCha20Poly1305
pub const NONCE_LEN: usize = 12;

// The length of a digest or nonce as a big endian u16
pub const ENCODED_LEN: usize = 2;

// The length of a SHA3-256 digest
pub const DIGEST_LEN: usize = 32;

// The length of a ChaCha20Poly1305 Key
pub const KEY_LEN: usize = 32;

// The length of a ChaCha20Poly1305 authentication tag
pub const TAG_LEN: usize = 16;

pub const MAX_HANDSHAKE_MSG_SIZE: usize = HandshakeMsgV1::MAX_SIZE + TAG_LEN;

/// Keys, IVs, AEADs used for the handshake traffic
pub struct HandshakeState {
    pub client_aead: ChaCha20Poly1305,
    pub server_aead: ChaCha20Poly1305,
    pub application_salt: Zeroizing<[u8; DIGEST_LEN]>,
    pub client_nonce_counter: u64,
    pub server_nonce_counter: u64,
    pub server_iv: Zeroizing<[u8; NONCE_LEN]>,
    pub client_iv: Zeroizing<[u8; NONCE_LEN]>,
    pub server_finished_key: Zeroizing<[u8; DIGEST_LEN]>,
    pub client_finished_key: Zeroizing<[u8; DIGEST_LEN]>,
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
            client_nonce_counter: 0,
            server_nonce_counter: 0,
            server_iv,
            client_iv,
            server_finished_key,
            client_finished_key,
        }
    }
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
