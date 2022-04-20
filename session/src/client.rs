// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use derive_more::From;
use ed25519;
use ed25519_dalek;
use hmac::{Hmac, Mac};
use hubpack::{deserialize, serialize};
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::handshake_state::{validate_version, HandshakeState, Role};
use crate::msgs::{ClientHello, HandshakeMsgDataV1, HandshakeMsgV1, HandshakeVersion, Identity};
use crate::{Error, Vec};
use sprockets_common::certificates::{Ed25519Certificates, Ed25519Signature, Ed25519Verifier};
use sprockets_common::msgs::{RotOp, RotResult};
use sprockets_common::{Ed25519PublicKey, Measurements, Nonce};

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
    WaitForFinished {
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
    WaitForSignedMeasurementsFromRoT {
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
    SendIdentity {
        measurements: Measurements,
        signature: Ed25519Signature,
        handshake_state: HandshakeState,
    },
    WaitForSignedTranscriptFromRoT {
        handshake_state: HandshakeState,
    },
    SendIdentityVerify {
        handshake_state: HandshakeState,
    },
    SendFinished {
        handshake_state: HandshakeState,
    },
    Complete {
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

/// A token that allows calling the `handle` method of a `ClientHandshake`
#[derive(Debug)]
pub struct RecvToken(usize);

impl RecvToken {
    fn new() -> RecvToken {
        RecvToken(0)
    }
}

/// A token that allows calling the `next_msg` method of a `ClientHandshake`
#[derive(Debug)]
pub struct SendToken(usize);

impl SendToken {
    fn new() -> SendToken {
        SendToken(0)
    }
}

/// A token that allows calling the `new_session` method of a `ClientHandshake`
#[derive(Debug)]
pub struct CompletionToken(usize);

impl CompletionToken {
    fn new() -> CompletionToken {
        CompletionToken(0)
    }
}

/// This is the return value from a Client operation. It instructs the user what
/// to do next.
#[derive(Debug, From)]
pub enum UserAction {
    /// The user should receive a message over the transport and then call
    /// `handle`.
    Recv(RecvToken),

    /// The user should call the `next_msg` method to provide a message to be
    /// sent over the transport.
    Send(SendToken),

    /// The user should send the included `RotRequest` to the RoT and then call
    /// `handle_rot_result` with the reply received from the RoT.
    SendToRot(RotOp),

    /// The handshake is complete and the user should call the `new_session`
    /// method to get back a `Session` object that can be used to encrypt
    /// application messages to send and decrypt received application messages.
    Complete(CompletionToken),
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
    ) -> (Client, usize, RecvToken) {
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

        (client, size, RecvToken::new())
    }

    /// Handle a message from the server
    ///
    /// We take a mutable buffer, because we decrypt in place to prevent the
    // need to allocate.
    pub fn handle(&mut self, buf: &mut Vec, _token: RecvToken) -> Result<UserAction, Error> {
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
            State::WaitForFinished {
                server_nonce,
                handshake_state,
            } => self.handle_finished(server_nonce, handshake_state, buf),
            _ => unreachable!(),
        }
    }

    /// Handle the result message from an RoT
    ///
    /// Note that these are not encrypted nor serialized.
    /// Serialization/Deserialization is performed by the user, because the
    /// user also puts the `RotOp` into the `RotRequest`, and removes the
    /// `RotResult` from the `RotResponse`. This is useful as it allows the user
    /// to keep track of request ids for RotRequests across multiple sessions.
    /// The session code does not have to worry about this as a result.
    pub fn handle_rot_reply(&mut self, result: RotResult) -> Result<UserAction, Error> {
        let state = self.state.take().unwrap();
        match state {
            State::WaitForSignedMeasurementsFromRoT {
                server_nonce,
                handshake_state,
            } => self.handle_signed_measurements(server_nonce, handshake_state, result),
            _ => unimplemented!(),
        }
    }

    // Get the next message to send over the session transport
    //
    // This requires a SendToken to ensure that it will only be called when the
    // next state in the protocol handshake requires sending a message.
    pub fn next_msg(&mut self, buf: &mut Vec, _token: SendToken) -> Result<UserAction, Error> {
        let state = self.state.take().unwrap();
        match state {
            State::SendIdentity {
                measurements,
                signature,
                handshake_state,
            } => self.create_identity_msg(measurements, signature, handshake_state, buf),
            _ => unimplemented!(),
        }
    }

    fn handle_signed_measurements(
        &mut self,
        server_nonce: Nonce,
        hs: HandshakeState,
        result: RotResult,
    ) -> Result<UserAction, Error> {
        if let RotResult::Measurements(measurements, nonce, signature) = result {
            if nonce != server_nonce {
                return Err(Error::BadNonce);
            }
            // Transition to the next state
            self.state = Some(State::SendIdentity {
                measurements,
                signature,
                handshake_state: hs,
            });
            Ok(SendToken::new().into())
        } else {
            Err(Error::UnexpecteRotMsg)
        }
    }

    fn create_identity_msg(
        &mut self,
        measurements: Measurements,
        measurements_sig: Ed25519Signature,
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<UserAction, Error> {
        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::Identity(Identity {
                certs: self.client_certs.clone(),
                measurements,
                measurements_sig,
            }),
        };
        hs.serialize_and_encrypt(msg, buf)?;
        Ok(SendToken::new().into())
    }

    fn handle_hello(
        &mut self,
        client_nonce: Nonce,
        secret: EphemeralSecret,
        buf: &mut Vec,
    ) -> Result<UserAction, Error> {
        let (msg, _) = deserialize::<HandshakeMsgV1>(&buf)?;
        validate_version(&msg.version)?;
        if let HandshakeMsgDataV1::ServerHello(hello) = msg.data {
            self.transcript.update(buf);
            // We clone so we can use the intermediate hash value but maintain
            // the running hash computation.
            let transcript_hash = self.transcript.clone().finalize();
            let public_key = PublicKey::from(hello.public_key.0);
            let handshake_state = HandshakeState::new(
                Role::Client,
                secret,
                &public_key,
                transcript_hash.as_slice(),
            );

            // Transition to the next state
            self.state = Some(State::WaitForIdentity {
                client_nonce,
                server_nonce: hello.nonce,
                handshake_state,
            });
            Ok(RecvToken::new().into())
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
    ) -> Result<UserAction, Error> {
        let msg_data = hs.decrypt_and_deserialize(buf)?;
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

            Ok(RecvToken::new().into())
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
    ) -> Result<UserAction, Error> {
        let msg_data = hs.decrypt_and_deserialize(buf)?;
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
            self.state = Some(State::WaitForFinished {
                server_nonce,
                handshake_state: hs,
            });

            Ok(RecvToken::new().into())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    fn handle_finished(
        &mut self,
        server_nonce: Nonce,
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<UserAction, Error> {
        let msg_data = hs.decrypt_and_deserialize(buf)?;
        if let HandshakeMsgDataV1::Finished(finished) = msg_data {
            // We clone so we can use the intermediate hash value but maintain
            // the running hash computation.
            //
            // The current transcript hash is:
            //   H(ClientHello || ServerHello || Identity || IdentityVerify)
            //
            let transcript_hash = self.transcript.clone().finalize();
            self.transcript.update(buf);

            // Verify the MAC over the transcript hash
            let mut mac =
                Hmac::<Sha3_256>::new_from_slice(hs.server_finished_key.as_ref()).unwrap();
            mac.update(&transcript_hash);
            mac.verify_slice(&finished.mac.0)
                .map_err(|_| Error::BadMac)?;

            // Transition to the next state
            self.state = Some(State::WaitForSignedMeasurementsFromRoT {
                server_nonce: server_nonce.clone(),
                handshake_state: hs,
            });

            Ok(RotOp::GetMeasurements(server_nonce).into())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }
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
