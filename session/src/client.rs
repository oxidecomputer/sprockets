// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hubpack::deserialize;
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::handshake_state::{validate_version, HandshakeState};
use crate::msgs::{
    ClientHello, Finished, HandshakeMsgDataV1, HandshakeMsgV1, HandshakeVersion, Identity,
    IdentityVerify,
};
use crate::{
    CompletionToken, DalekVerifier, Error, RecvToken, Role, SendToken, Session, UserAction, Vec,
};
use sprockets_common::certificates::{Ed25519Certificates, Ed25519Signature, Ed25519Verifier};
use sprockets_common::msgs::{RotOp, RotResult};
use sprockets_common::{Ed25519PublicKey, Measurements, Nonce, Sha3_256Digest};

// The current state of the handshake state machine
//
// Each state has different data associated with it.
//
// The states are transitioned in the order listed. No state is ever skipped.
enum State {
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
        signature: Ed25519Signature,
        handshake_state: HandshakeState,
    },
    SendFinished {
        handshake_state: HandshakeState,
    },
    Complete {
        handshake_state: HandshakeState,
    },
}

/// The client side of a secure session handshake
pub struct ClientHandshake {
    manufacturing_public_key: Ed25519PublicKey,
    client_certs: Ed25519Certificates,
    transcript: Sha3_256,
    // Must be an option to allow moving out of the type when switching between
    // states.
    state: Option<State>,
}

impl ClientHandshake {
    /// Initialize the ClientHandshake and serialize the ClientHello message
    /// into `buf`.
    ///
    /// Return the ClientHandshake along with a RecvToken.
    pub fn init(
        manufacturing_public_key: Ed25519PublicKey,
        client_certs: Ed25519Certificates,
        buf: &mut Vec,
    ) -> (ClientHandshake, RecvToken) {
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
        HandshakeState::serialize(msg, buf).unwrap();
        transcript.update(&buf);

        let client = ClientHandshake {
            manufacturing_public_key,
            client_certs,
            transcript,
            state: Some(state),
        };

        (client, RecvToken::new())
    }

    /// Handle a message from the server
    ///
    /// We take a mutable buffer because we decrypt in place to prevent the
    /// need to allocate.
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
            State::WaitForSignedTranscriptFromRoT { handshake_state } => {
                self.handle_signed_transcript(handshake_state, result)
            }
            _ => unreachable!(),
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
            State::SendIdentityVerify {
                signature,
                handshake_state,
            } => self.create_identity_verify_msg(signature, handshake_state, buf),
            State::SendFinished { handshake_state } => {
                self.create_finished_msg(handshake_state, buf)
            }
            _ => unreachable!(),
        }
    }

    // Return a `Session` that can be used to send and receive application
    // level messages over an encrypted channel.
    //
    // The CompletionToken ensures that the session can only be called after the
    // handshake completes.
    pub fn new_session(self, _: CompletionToken) -> Session {
        let hs = match self.state.unwrap() {
            State::Complete { handshake_state } => handshake_state,
            _ => unreachable!(),
        };
        Session::new(hs, Sha3_256Digest(self.transcript.finalize().into()))
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

    fn handle_signed_transcript(
        &mut self,
        hs: HandshakeState,
        result: RotResult,
    ) -> Result<UserAction, Error> {
        if let RotResult::SignedTranscript(signature) = result {
            // Transition to the next state
            self.state = Some(State::SendIdentityVerify {
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
        HandshakeState::serialize(msg, buf)?;
        self.transcript.update(&buf);
        hs.encrypt(buf)?;

        // Transition to the next state
        self.state = Some(State::WaitForSignedTranscriptFromRoT {
            handshake_state: hs,
        });

        // We clone so we can use the intermediate hash value but maintain
        // the running hash computation.
        //
        // The current transcript hash is:
        //   H(ClientHello || ServerHello || Identity(S) || IdentityVerify(S)
        //      || Finished(S) || Identity(C))
        //
        let hash = Sha3_256Digest(self.transcript.clone().finalize().into());
        Ok(RotOp::SignTranscript(hash).into())
    }

    fn create_identity_verify_msg(
        &mut self,
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
            handshake_state: hs,
        });

        Ok(SendToken::new().into())
    }

    fn create_finished_msg(
        &mut self,
        mut hs: HandshakeState,
        buf: &mut Vec,
    ) -> Result<UserAction, Error> {
        // We clone so we can use the intermediate hash value but maintain
        // the running hash computation.
        //
        // The current transcript hash is:
        //   H(ClientHello || ServerHello || Identity(S) || IdentityVerify(S)
        //      || Finished(S) || Identity(C) ||  IdentityVerify(C))
        //
        let transcript_hash = self.transcript.clone().finalize();

        // Create a MAC over the transcript hash
        let mac = hs.create_finished_mac(&transcript_hash);

        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::Finished(Finished { mac }),
        };
        HandshakeState::serialize(msg, buf)?;
        self.transcript.update(&buf);
        hs.encrypt(buf)?;

        // Transition to the next state
        self.state = Some(State::Complete {
            handshake_state: hs,
        });

        Ok(CompletionToken::new().into())
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
            hs.verify_finished_mac(&finished.mac.0, &transcript_hash)?;

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
