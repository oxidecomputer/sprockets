// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The state needed for handshake encyption by both client and server

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{self, ChaCha20Poly1305, Key};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hubpack::{deserialize, serialize};
use sha3::Sha3_256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::msgs::{HandshakeMsgDataV1, HandshakeMsgV1, HandshakeVersion};
use crate::{
    digest_len_buf, nonce_len_buf, Error, HandshakeMsgVec, Role, DIGEST_LEN,
    KEY_LEN, NONCE_LEN,
};
use sprockets_common::HmacSha3_256;

/// Keys, IVs, AEADs used for the handshake traffic
pub struct HandshakeState {
    role: Role,
    client_aead: ChaCha20Poly1305,
    server_aead: ChaCha20Poly1305,
    application_salt: Zeroizing<[u8; DIGEST_LEN]>,
    client_nonce_counter: u64,
    server_nonce_counter: u64,
    server_iv: Zeroizing<[u8; NONCE_LEN]>,
    client_iv: Zeroizing<[u8; NONCE_LEN]>,
    server_finished_key: Zeroizing<[u8; DIGEST_LEN]>,
    client_finished_key: Zeroizing<[u8; DIGEST_LEN]>,
}

impl HandshakeState {
    /// Compute a shared secret via x25519 and derive HandshakeKeys using HKDF
    pub(crate) fn new(
        role: Role,
        my_secret: EphemeralSecret,
        peer_public_key: &PublicKey,
        transcript: &[u8],
    ) -> HandshakeState {
        let initial_salt = [0u8; 32];
        let shared_secret = my_secret.diffie_hellman(peer_public_key);
        let handshake_secret = Hkdf::<Sha3_256>::new(
            Some(&initial_salt),
            shared_secret.as_bytes(),
        );

        // Generate client handshake secret PRK
        let mut client_handshake_secret_buf = Zeroizing::new([0u8; KEY_LEN]);
        handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 c hs", transcript],
                client_handshake_secret_buf.as_mut(),
            )
            .unwrap();

        // Generate server handshake secret PRK
        let mut server_handshake_secret_buf = Zeroizing::new([0u8; KEY_LEN]);
        handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 s hs", transcript],
                server_handshake_secret_buf.as_mut(),
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

        // Setup handshake traffic secrets to be used to generate keys and IVs
        // via HKDF-Expand
        let client_handshake_secret =
            Hkdf::<Sha3_256>::from_prk(client_handshake_secret_buf.as_ref())
                .unwrap();
        let server_handshake_secret =
            Hkdf::<Sha3_256>::from_prk(server_handshake_secret_buf.as_ref())
                .unwrap();

        // Create traffic keys and IVs
        let mut client_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut server_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut client_iv = Zeroizing::new([0u8; NONCE_LEN]);
        let mut server_iv = Zeroizing::new([0u8; NONCE_LEN]);

        // Create client key
        client_handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 key"],
                client_key.as_mut(),
            )
            .unwrap();

        // Create server key
        server_handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 key"],
                server_key.as_mut(),
            )
            .unwrap();

        // Create client IV
        client_handshake_secret
            .expand_multi_info(
                &[&nonce_len_buf()[..], b"spr1 iv"],
                client_iv.as_mut(),
            )
            .unwrap();

        // Create server IV
        server_handshake_secret
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

        let mut client_finished_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut server_finished_key = Zeroizing::new([0u8; KEY_LEN]);

        // Create client_finished_key
        client_handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 finished"],
                client_finished_key.as_mut(),
            )
            .unwrap();

        // Create server_finished_key
        server_handshake_secret
            .expand_multi_info(
                &[&digest_len_buf()[..], b"spr1 finished"],
                server_finished_key.as_mut(),
            )
            .unwrap();

        HandshakeState {
            role,
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

    pub fn serialize(
        msg: HandshakeMsgV1,
        buf: &mut HandshakeMsgVec,
    ) -> Result<(), Error> {
        let size = serialize(buf, &msg)?;
        buf.truncate(size);
        Ok(())
    }

    pub fn encrypt(&mut self, buf: &mut HandshakeMsgVec) -> Result<(), Error> {
        let nonce = self.chacha20poly1305nonce(self.role);
        let aead = match self.role {
            Role::Client => &mut self.client_aead,
            Role::Server => &mut self.server_aead,
        };
        aead.encrypt_in_place(&nonce, b"", buf)
            .map_err(|_| Error::EncryptError)
    }

    // 1. Decrypt buf in place returning the plaintext in buf
    // 2. Deserialize the message
    // 3. Validate that the message version is correct
    pub fn decrypt_and_deserialize(
        &mut self,
        buf: &mut HandshakeMsgVec,
    ) -> Result<HandshakeMsgDataV1, Error> {
        let nonce = self.chacha20poly1305nonce(self.role.peer());
        let aead = match self.role.peer() {
            Role::Client => &mut self.client_aead,
            Role::Server => &mut self.server_aead,
        };
        aead.decrypt_in_place(&nonce, b"", buf)
            .map_err(|_| Error::DecryptError)?;

        let (msg, _) = deserialize::<HandshakeMsgV1>(buf)?;
        validate_version(&msg.version)?;
        Ok(msg.data)
    }

    // Verify a MAC over the current transcript hash
    pub fn verify_finished_mac(
        &self,
        finished_mac: &[u8],
        transcript_hash: &[u8],
    ) -> Result<(), Error> {
        // The peer signed the message
        let finished_key = match self.role {
            Role::Client => self.server_finished_key.as_ref(),
            Role::Server => self.client_finished_key.as_ref(),
        };
        let mut mac =
            <Hmac<Sha3_256> as Mac>::new_from_slice(finished_key).unwrap();
        mac.update(transcript_hash);
        mac.verify_slice(finished_mac).map_err(|_| Error::BadMac)
    }

    /// Create a MAC over the current transcript hash
    pub fn create_finished_mac(&self, transcript_hash: &[u8]) -> HmacSha3_256 {
        // We signed the message
        let finished_key = match self.role {
            Role::Client => self.client_finished_key.as_ref(),
            Role::Server => self.server_finished_key.as_ref(),
        };
        let mut mac =
            <Hmac<Sha3_256> as Mac>::new_from_slice(finished_key).unwrap();
        mac.update(transcript_hash);
        HmacSha3_256(mac.finalize().into_bytes().into())
    }

    // This uses the construction from section 5.3 of RFC 8446
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

    pub fn application_salt(&self) -> &[u8] {
        self.application_salt.as_ref()
    }

    pub(crate) fn role(&self) -> Role {
        self.role
    }
}

pub fn validate_version(version: &HandshakeVersion) -> Result<(), Error> {
    if version.version != 1 {
        return Err(Error::BadVersion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::IdentityVerify;
    use rand_core::OsRng;
    use sprockets_common::Ed25519Signature;

    impl core::fmt::Debug for HandshakeState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HandshakeState")
                .field("application_salt", &self.application_salt)
                .field("client_nonce_counter", &self.client_nonce_counter)
                .field("server_nonce_counter", &self.server_nonce_counter)
                .field("server_iv", &self.server_iv)
                .field("client_iv", &self.client_iv)
                .field("server_finished_key", &self.server_finished_key)
                .field("client_finished_key", &self.client_finished_key)
                .finish()
        }
    }

    // We must skip the AEAD impls
    impl PartialEq for HandshakeState {
        fn eq(&self, other: &Self) -> bool {
            self.application_salt == other.application_salt
                && self.client_nonce_counter == other.client_nonce_counter
                && self.server_nonce_counter == other.server_nonce_counter
                && self.server_iv == other.server_iv
                && self.client_iv == other.client_iv
                && self.server_finished_key == other.server_finished_key
                && self.client_finished_key == other.client_finished_key
        }
    }

    impl Eq for HandshakeState {}

    impl HandshakeState {
        pub fn serialize_and_encrypt(
            &mut self,
            msg: HandshakeMsgV1,
            buf: &mut HandshakeMsgVec,
        ) -> Result<(), Error> {
            Self::serialize(msg, buf)?;
            self.encrypt(buf)
        }
    }

    // Return a HandshakeState for a client and server
    fn handshake_states() -> (HandshakeState, HandshakeState) {
        let client_secret = EphemeralSecret::new(OsRng);
        let client_public_key = PublicKey::from(&client_secret);
        let server_secret = EphemeralSecret::new(OsRng);
        let server_public_key = PublicKey::from(&server_secret);
        let transcript = [0u8; 32];

        let hs1 = HandshakeState::new(
            Role::Client,
            client_secret,
            &server_public_key,
            &transcript,
        );
        let hs2 = HandshakeState::new(
            Role::Server,
            server_secret,
            &client_public_key,
            &transcript,
        );

        (hs1, hs2)
    }

    #[test]
    fn sanity_check() {
        let (hs1, hs2) = handshake_states();
        // We are just testing keys here, not whether the state is for a client
        // or server. See PartialEq impl above.
        assert_eq!(hs1, hs2);

        // Ensure all keys are different
        assert_ne!(hs1.application_salt, hs1.server_finished_key);
        assert_ne!(hs1.application_salt, hs1.client_finished_key);
        assert_ne!(hs1.server_finished_key, hs1.client_finished_key);

        // Ensure IVs are different
        assert_ne!(hs1.server_iv, hs1.client_iv);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (mut hs1, mut hs2) = handshake_states();
        let mut buf = HandshakeMsgVec::new();
        buf.resize_default(buf.capacity()).unwrap();
        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::IdentityVerify(IdentityVerify {
                transcript_signature: Ed25519Signature([9u8; 64]),
            }),
        };

        // To align the keys and nonces, hs1 must encrypt, and hs2 must decrypt
        // or vice versa.
        hs1.serialize_and_encrypt(msg, &mut buf).unwrap();
        let data = hs2.decrypt_and_deserialize(&mut buf).unwrap();

        buf.resize_default(buf.capacity()).unwrap();
        hs2.serialize_and_encrypt(msg, &mut buf).unwrap();
        let data2 = hs1.decrypt_and_deserialize(&mut buf).unwrap();

        assert_eq!(data, data2);
    }

    #[test]
    fn double_encrypt_same_message_gives_diff_ciphertexts() {
        let (mut hs1, mut hs2) = handshake_states();
        let mut buf1 = HandshakeMsgVec::new();
        buf1.resize_default(buf1.capacity()).unwrap();
        let mut buf2 = HandshakeMsgVec::new();
        buf2.resize_default(buf2.capacity()).unwrap();
        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::IdentityVerify(IdentityVerify {
                transcript_signature: Ed25519Signature([9u8; 64]),
            }),
        };

        hs1.serialize_and_encrypt(msg, &mut buf1).unwrap();
        hs1.serialize_and_encrypt(msg, &mut buf2).unwrap();
        assert_ne!(buf1, buf2);

        hs2.serialize_and_encrypt(msg, &mut buf1).unwrap();
        hs2.serialize_and_encrypt(msg, &mut buf2).unwrap();
        assert_ne!(buf1, buf2);

        // Sanity check that encryption is different on both sides
        hs1.serialize_and_encrypt(msg, &mut buf1).unwrap();
        hs2.serialize_and_encrypt(msg, &mut buf2).unwrap();
        assert_ne!(buf1, buf2);
    }

    #[test]
    // The nonce gets bumped so any replayed message will not decrypt
    fn ensure_replay_decryption_fails() {
        let (mut hs1, mut hs2) = handshake_states();

        let mut buf = HandshakeMsgVec::new();
        buf.resize_default(buf.capacity()).unwrap();
        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::IdentityVerify(IdentityVerify {
                transcript_signature: Ed25519Signature([9u8; 64]),
            }),
        };

        hs1.serialize_and_encrypt(msg, &mut buf).unwrap();
        let data = hs2.decrypt_and_deserialize(&mut buf).unwrap();
        assert_eq!(msg.data, data);

        // We can't decrypt the same message twice, as we already changed the
        // expected nonce.
        assert_eq!(
            Err(Error::DecryptError),
            hs2.decrypt_and_deserialize(&mut buf)
        );
    }
}
