// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Secure Session type

use chacha20poly1305::aead::{AeadInPlace, Buffer, KeyInit};
use chacha20poly1305::{self, ChaCha20Poly1305, Key, Tag};
use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::handshake_state::HandshakeState;
use crate::{digest_len_buf, nonce_len_buf, Error, Role, KEY_LEN, NONCE_LEN};
use sprockets_common::Sha3_256Digest;

// A secure session created as a result of a successful handshake
pub struct Session {
    role: Role,
    client_aead: ChaCha20Poly1305,
    server_aead: ChaCha20Poly1305,
    client_nonce_counter: u64,
    server_nonce_counter: u64,
    server_iv: Zeroizing<[u8; NONCE_LEN]>,
    client_iv: Zeroizing<[u8; NONCE_LEN]>,
}

impl Session {
    // Create application level traffic keys, and return a secure session with
    // which to send encrypted application level messages.
    pub fn new(hs: HandshakeState, transcript_hash: Sha3_256Digest) -> Session {
        // This "0" ikm is correct, and follows the derivation given in tls 1.3!
        let ikm = [0u8; 32];
        let app_secret =
            Hkdf::<Sha3_256>::new(Some(hs.application_salt()), &ikm);

        // Generate client application traffic secret
        let mut client_app_secret = Zeroizing::new([0u8; KEY_LEN]);
        app_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 c app", &transcript_hash.0],
                client_app_secret.as_mut(),
            )
            .unwrap();
        let client_app_secret =
            Hkdf::<Sha3_256>::from_prk(client_app_secret.as_ref()).unwrap();

        // Generate server application traffic secret
        let mut server_app_secret = Zeroizing::new([0u8; KEY_LEN]);
        app_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 c app", &transcript_hash.0],
                server_app_secret.as_mut(),
            )
            .unwrap();
        let server_app_secret =
            Hkdf::<Sha3_256>::from_prk(server_app_secret.as_ref()).unwrap();

        // Create buffers to hold keys and IVs
        let mut client_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut server_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut client_iv = Zeroizing::new([0u8; NONCE_LEN]);
        let mut server_iv = Zeroizing::new([0u8; NONCE_LEN]);

        // Create client key
        client_app_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 key"],
                client_key.as_mut(),
            )
            .unwrap();

        // Create server key
        server_app_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 key"],
                server_key.as_mut(),
            )
            .unwrap();

        // Create client IV
        client_app_secret
            .expand_multi_info(
                &[&nonce_len_buf()[..], b"spr1 iv"],
                client_iv.as_mut(),
            )
            .unwrap();

        // Create server IV
        server_app_secret
            .expand_multi_info(
                &[&nonce_len_buf()[..], b"spr1 iv"],
                server_iv.as_mut(),
            )
            .unwrap();

        // Initialize AEAD algorithms for client and server
        let client_aead =
            ChaCha20Poly1305::new(Key::from_slice(client_key.as_ref()));
        let server_aead =
            ChaCha20Poly1305::new(Key::from_slice(server_key.as_ref()));

        Session {
            role: hs.role(),
            client_aead,
            server_aead,
            client_nonce_counter: 0,
            server_nonce_counter: 0,
            client_iv,
            server_iv,
        }
    }

    /// Encrypt an application level plaintext message in place. The buffer must
    /// be large enough to support an authentication tag of 16 bytes.
    pub fn encrypt(&mut self, buf: &mut dyn Buffer) -> Result<(), Error> {
        let nonce = self.chacha20poly1305nonce(self.role);
        let aead = match self.role {
            Role::Client => &mut self.client_aead,
            Role::Server => &mut self.server_aead,
        };
        aead.encrypt_in_place(&nonce, b"", buf)
            .map_err(|_| Error::EncryptError)
    }

    /// Encrypt an application level plaintext message in place, returning the
    /// 16-byte authentication tag.
    pub fn encrypt_in_place_detached(
        &mut self,
        buf: &mut [u8],
    ) -> Result<Tag, Error> {
        let nonce = self.chacha20poly1305nonce(self.role);
        let aead = match self.role {
            Role::Client => &mut self.client_aead,
            Role::Server => &mut self.server_aead,
        };
        aead.encrypt_in_place_detached(&nonce, b"", buf)
            .map_err(|_| Error::EncryptError)
    }

    /// Decrypt buf in place, returning the plaintext in buf
    pub fn decrypt(&mut self, buf: &mut dyn Buffer) -> Result<(), Error> {
        let nonce = self.chacha20poly1305nonce(self.role.peer());
        let aead = match self.role.peer() {
            Role::Client => &mut self.client_aead,
            Role::Server => &mut self.server_aead,
        };
        aead.decrypt_in_place(&nonce, b"", buf)
            .map_err(|_| Error::DecryptError)
    }

    /// Decrypt buf in place, returning an error if the provided authentication
    /// tag does not match the ciphertext.
    pub fn decrypt_in_place_detached(
        &mut self,
        buf: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        let nonce = self.chacha20poly1305nonce(self.role.peer());
        let aead = match self.role.peer() {
            Role::Client => &mut self.client_aead,
            Role::Server => &mut self.server_aead,
        };
        aead.decrypt_in_place_detached(&nonce, b"", buf, tag)
            .map_err(|_| Error::DecryptError)
    }

    // This uses the construction from section 5.3 or RFC 8446
    //
    // XOR the IV with the big-endian counter 0 padded to the left.
    //
    // The IV is 12 bytes (96 bits)
    fn chacha20poly1305nonce(
        &mut self,
        sender_role: Role,
    ) -> chacha20poly1305::Nonce {
        let (iv, counter) = match sender_role {
            Role::Client => (&self.client_iv, &mut self.client_nonce_counter),
            Role::Server => (&self.server_iv, &mut self.server_nonce_counter),
        };
        let mut nonce = [0u8; NONCE_LEN];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        nonce
            .iter_mut()
            .zip(iv.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);

        // Increment the counter in preparation for the next message
        *counter += 1;

        *chacha20poly1305::Nonce::from_slice(&nonce)
    }
}
