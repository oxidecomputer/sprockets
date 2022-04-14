// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chacha20poly1305;
use chacha20poly1305::aead::{heapless, AeadInPlace};
use derive_more::From;
use ed25519;
use ed25519_dalek;
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::handshake_state::{HandshakeState, MAX_HANDSHAKE_MSG_SIZE, NONCE_LEN};
use crate::msgs::*;
use sprockets_common::certificates::{
    Ed25519Certificates, Ed25519CertificatesError, Ed25519Signature, Ed25519Verifier,
};
use sprockets_common::{Ed25519PublicKey, Nonce};

type Vec = heapless::Vec<u8, MAX_HANDSHAKE_MSG_SIZE>;

// The current state of the handshake state machine
//
// Each state has different data associated with it.
pub enum State {
    Hello {
        client_nonce: Nonce,
        secret: EphemeralSecret,
    },
    WaitForIdentity {
        client_nonce: Nonce,
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
    WaitForIdentityVerify {
        server_identity: Identity,
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
}

pub struct Client {
    manufacturing_public_key: Ed25519PublicKey,
    client_certs: Ed25519Certificates,
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
    Certificates(Ed25519CertificatesError),
    BadMeasurementsSig,
    BadTranscriptSig,
}

impl Client {
    /// Initialize the Client and serialize the ClientHello message into `buf`.
    ///
    /// Return the Client and the size of the serialize message.
    ///
    /// `buf` must be at least `HandshakeMsgV1::MAX_SIZE` bytes;
    pub fn init(
        manufacturing_public_key: Ed25519PublicKey,
        client_certs: Ed25519Certificates,
        buf: &mut [u8],
    ) -> (Client, usize) {
        let secret = EphemeralSecret::new(OsRng);
        let public_key = PublicKey::from(&secret);

        let client_nonce = Nonce::new();

        let state = State::Hello {
            secret,
            client_nonce,
        };

        let msg = HandshakeMsgV1::new(
            ClientHello {
                nonce: client_nonce.clone(),
                public_key: Ed25519PublicKey(public_key.to_bytes()),
            }
            .into(),
        );

        let mut transcript = Sha3_256::new();
        let size = serialize(buf, &msg).unwrap();
        transcript.update(&buf[..size]);

        let client = Client {
            manufacturing_public_key,
            client_certs,
            transcript,
            state: Some(state),
        };

        (client, size)
    }

    /// Handle a message from the server
    ///
    /// We take a mutable buffer, because we decrypt in place to prevent the
    // need to allocate.
    pub fn handle(&mut self, buf: &mut Vec) -> Result<(), Error> {
        let state = self.state.take().unwrap();
        match state {
            State::Hello {
                client_nonce,
                secret,
            } => self.handle_hello(client_nonce, secret, buf),
            State::WaitForIdentity {
                client_nonce,
                server_nonce,
                handshake_state,
            } => self.handle_identity(client_nonce, server_nonce, handshake_state, buf),
            State::WaitForIdentityVerify {
                server_identity,
                server_nonce,
                handshake_state,
            } => self.handle_identity_verify(server_identity, server_nonce, handshake_state, buf),

            _ => unimplemented!(),
        }
    }

    fn handle_hello(
        &mut self,
        client_nonce: Nonce,
        secret: EphemeralSecret,
        buf: &mut Vec,
    ) -> Result<(), Error> {
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
                client_nonce,
                server_nonce: hello.nonce,
                handshake_state,
            });
            Ok(())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    // TODO: Add a Corpus to the Client state and validate measurements
    fn handle_identity(
        &mut self,
        client_nonce: Nonce,
        server_nonce: Nonce,
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<(), Error> {
        let msg_data = Self::decrypt_and_deserialize(hs, buf)?;
        if let HandshakeMsgDataV1::Identity(identity) = msg_data {
            self.transcript.update(buf);

            // Validate the certificate chains
            identity
                .certs
                .validate(&self.manufacturing_public_key, &DalekVerifier)?;

            // Ensure measurements concatenated with the client nonce are
            // properly signed.
            let (buf, size) = identity.measurements.serialize_with_nonce(&client_nonce);
            DalekVerifier
                .verify(
                    &identity.certs.measurement.subject_public_key,
                    &buf[..size],
                    &identity.measurements_sig,
                )
                .map_err(|_| Error::BadMeasurementsSig)?;

            // Transition to the next state
            self.state = Some(State::WaitForIdentityVerify {
                server_identity: identity,
                server_nonce,
                handshake_state: hs,
            });

            Ok(())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    fn handle_identity_verify(
        &mut self,
        server_identity: Identity,
        server_nonce: Nonce,
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<(), Error> {
        let msg_data = Self::decrypt_and_deserialize(hs, buf)?;
        if let HandshakeMsgDataV1::IdentityVerify(identity_verify) = msg_data {
            // We clone so we can use the intermediate hash value but maintain
            // the running hash computation.
            //
            // The current transcript hash is:
            //   H(ClientHello || ServerHello || Identity)
            //
            let transcript_hash = self.transcript.clone().finalize();
            self.transcript.update(buf);

            // Verify the transcript hash signature
            DalekVerifier
                .verify(
                    &server_identity.certs.dhe.subject_public_key,
                    &transcript_hash,
                    &identity_verify.transcript_signature,
                )
                .map_err(|_| Error::BadTranscriptSig)?;

            // Transition to the next state
            self.state = Some(State::WaitForFinished {});

            Ok(())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    // 1. Decrypt buf in place returning the plaintext in buf
    // 2. Deserialize the message
    // 3. Validate that the message version is correct
    fn decrypt_and_deserialize(
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<HandshakeMsgDataV1, Error> {
        let nonce = chach20poly1305nonce(hs.server_iv.as_ref(), hs.server_nonce_counter);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce);
        hs.server_aead
            .decrypt_in_place(nonce, b"", buf)
            .map_err(|_| Error::DecryptError)?;

        // Increment the server nonce counter in anticipation of the next message.
        hs.server_nonce_counter += 1;
        let (msg, _) = deserialize::<HandshakeMsgV1>(buf)?;
        Self::validate_version(&msg.version)?;
        Ok(msg.data)
    }

    fn validate_version(version: &HandshakeVersion) -> Result<(), Error> {
        if version.version != 1 {
            return Err(Error::BadVersion);
        }
        Ok(())
    }
}

// This uses the construction from section 5.3 or RFC 8446
//
// XOR the IV with the big-endian counter 0 padded to the left.
//
// The IV is 12 bytes (96 bits)
fn chach20poly1305nonce(iv: &[u8], counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
        .iter_mut()
        .zip(iv.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    nonce
}

pub struct DalekVerifier;

impl Ed25519Verifier for DalekVerifier {
    fn verify(
        &self,
        signer_public_key: &Ed25519PublicKey,
        msg: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), ()> {
        let public_key = ed25519_dalek::PublicKey::from_bytes(&signer_public_key.0).unwrap();
        let signature = ed25519::Signature::from_bytes(&signature.0).unwrap();
        public_key.verify_strict(msg, &signature).map_err(|_| ())?;
        Ok(())
    }
}
