// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
use derive_more::From;
use ed25519;
use ed25519_dalek;
use hubpack::{deserialize, serialize};
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::handshake_state::{validate_version, HandshakeState};
use crate::msgs::{
    ClientHello, Finished, HandshakeMsgDataV1, HandshakeMsgV1, HandshakeVersion, Identity,
    IdentityVerify, ServerHello,
};
use crate::{CompletionToken, Error, RecvToken, Role, SendToken, Session, UserAction, Vec};
use sprockets_common::certificates::{Ed25519Certificates, Ed25519Signature, Ed25519Verifier};
use sprockets_common::msgs::{RotOp, RotResult};
use sprockets_common::{Ed25519PublicKey, Measurements, Nonce, Sha3_256Digest};

// The current state of the handshake state machine
//
// Each state has different data associated with it.
//
// The states are transitioned in the order listed. No state is ever skipped.
enum State {
    WaitForHello,
    SendHello {
        client_hello: ClientHello,
    },
    WaitForSignedMeasurementsFromRoT {
        client_nonce: Nonce,
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
    SendIdentity {
        server_nonce: Nonce,
        measurements: Measurements,
        signature: Ed25519Signature,
        handshake_state: HandshakeState,
    },
    WaitForSignedTranscriptFromRoT {
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
    SendIdentityVerify {
        server_nonce: Nonce,
        signature: Ed25519Signature,
        handshake_state: HandshakeState,
    },
    SendFinished {
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
    WaitForIdentity {
        server_nonce: Nonce,
        handshake_state: HandshakeState,
    },
    WaitForIdentityVerify {
        server_identity: Identity,
        handshake_state: HandshakeState,
    },
    WaitForFinished {
        handshake_state: HandshakeState,
    },
    Complete {
        handshake_state: HandshakeState,
    },
}

/// The server side of a secure session handshake
pub struct ServerHandshake {
    manufacturing_public_key: Ed25519PublicKey,
    server_certs: Ed25519Certificates,
    transcript: Sha3_256,
    // Must be an option to allow moving out of the type when switching between
    // states.
    state: Option<State>,
}

impl ServerHandshake {
    // Initialize the server handshake
    //
    // The server will be waiting for a ClientHello message, so we return a
    // `RecvToken` to allow calling the `handle` method.
    pub fn init(
        manufacturing_public_key: Ed25519PublicKey,
        server_certs: Ed25519Certificates,
    ) -> ServerHandshake {
        let state = Some(State::WaitForHello);
        let transcript = Sha3_256::new();
        ServerHandshake {
            manufacturing_public_key,
            server_certs,
            transcript,
            state,
        }
    }

    /// Handle a message from the client
    ///
    /// We take a mutable buffer because we decrypt in place to prevent the need
    /// to allocate.
    pub fn handle(&mut self, buf: &mut Vec, _token: RecvToken) -> Result<UserAction, Error> {
        let state = self.state.take().unwrap();
        match state {
            State::WaitForHello => self.handle_hello(buf),
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
            State::SendHello { client_hello } => self.create_hello_msg(client_hello, buf),
            State::SendIdentity {
                server_nonce,
                measurements,
                signature,
                handshake_state,
            } => self.create_identity_msg(
                server_nonce,
                measurements,
                signature,
                handshake_state,
                buf,
            ),
            State::SendIdentityVerify {
                server_nonce,
                signature,
                handshake_state,
            } => self.create_identity_verify_msg(server_nonce, signature, handshake_state, buf),
            _ => unimplemented!(),
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
                client_nonce,
                server_nonce,
                handshake_state,
            } => {
                self.handle_signed_measurements(client_nonce, server_nonce, handshake_state, result)
            }
            State::WaitForSignedTranscriptFromRoT {
                server_nonce,
                handshake_state,
            } => self.handle_signed_transcript(server_nonce, handshake_state, result),
            _ => unreachable!(),
        }
    }

    fn handle_hello(&mut self, buf: &mut Vec) -> Result<UserAction, Error> {
        let (msg, _) = deserialize::<HandshakeMsgV1>(&buf)?;
        validate_version(&msg.version)?;
        if let HandshakeMsgDataV1::ClientHello(client_hello) = msg.data {
            // Add the serialized ClientHello to the transcript
            self.transcript.update(buf);

            // Transition to the next state
            self.state = Some(State::SendHello { client_hello });
            Ok(SendToken::new().into())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    fn create_hello_msg(
        &mut self,
        client_hello: ClientHello,
        buf: &mut Vec,
    ) -> Result<UserAction, Error> {
        let secret = EphemeralSecret::new(OsRng);
        let public_key = PublicKey::from(&secret);
        let server_nonce = Nonce::new();

        let msg = HandshakeMsgV1::new(
            ServerHello {
                nonce: server_nonce.clone(),
                public_key: Ed25519PublicKey(public_key.to_bytes()),
            }
            .into(),
        );

        let size = serialize(buf.as_mut(), &msg)?;
        buf.truncate(size);
        self.transcript.update(buf);

        // We clone so we can use the intermediate hash value but maintain
        // the running hash computation.
        let transcript_hash = self.transcript.clone().finalize();
        let handshake_state = HandshakeState::new(
            Role::Server,
            secret,
            &PublicKey::from(client_hello.public_key.0),
            transcript_hash.as_slice(),
        );

        let client_nonce = client_hello.nonce;

        // Transition to the next state
        self.state = Some(State::WaitForSignedMeasurementsFromRoT {
            client_nonce: client_nonce.clone(),
            server_nonce,
            handshake_state,
        });

        Ok(RotOp::GetMeasurements(client_nonce).into())
    }

    fn handle_signed_measurements(
        &mut self,
        client_nonce: Nonce,
        server_nonce: Nonce,
        hs: HandshakeState,
        result: RotResult,
    ) -> Result<UserAction, Error> {
        if let RotResult::Measurements(measurements, nonce, signature) = result {
            if nonce != client_nonce {
                return Err(Error::BadNonce);
            }
            // Transition to the next state
            self.state = Some(State::SendIdentity {
                server_nonce,
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
        server_nonce: Nonce,
        measurements: Measurements,
        measurements_sig: Ed25519Signature,
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<UserAction, Error> {
        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::Identity(Identity {
                certs: self.server_certs.clone(),
                measurements,
                measurements_sig,
            }),
        };
        HandshakeState::serialize(msg, buf)?;
        self.transcript.update(&buf);
        hs.encrypt(buf)?;

        // Transition to the next state
        self.state = Some(State::WaitForSignedTranscriptFromRoT {
            server_nonce,
            handshake_state: hs,
        });

        // We clone so we can use the intermediate hash value but maintain
        // the running hash computation.
        //
        // The current transcript hash is:
        //   H(ClientHello || ServerHello || Identity(S))
        //
        let hash = Sha3_256Digest(self.transcript.clone().finalize().into());
        Ok(RotOp::SignTranscript(hash).into())
    }

    fn handle_signed_transcript(
        &mut self,
        server_nonce: Nonce,
        hs: HandshakeState,
        result: RotResult,
    ) -> Result<UserAction, Error> {
        if let RotResult::SignedTranscript(signature) = result {
            // Transition to the next state
            self.state = Some(State::SendIdentityVerify {
                server_nonce,
                signature,
                handshake_state: hs,
            });
            Ok(SendToken::new().into())
        } else {
            Err(Error::UnexpecteRotMsg)
        }
    }

    fn create_identity_verify_msg(
        &mut self,
        server_nonce: Nonce,
        transcript_signature: Ed25519Signature,
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<UserAction, Error> {
        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::IdentityVerify(IdentityVerify {
                transcript_signature,
            }),
        };
        HandshakeState::serialize(msg, buf)?;
        self.transcript.update(&buf);
        hs.encrypt(buf)?;

        // Transition to the next state
        self.state = Some(State::SendFinished {
            server_nonce,
            handshake_state: hs,
        });

        Ok(SendToken::new().into())
    }
}
