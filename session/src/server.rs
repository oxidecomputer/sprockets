// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
use hubpack::{deserialize, serialize, SerializedSize};
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::handshake_state::{validate_version, HandshakeState};
use crate::msgs::{
    ClientHello, Finished, HandshakeMsgDataV1, HandshakeMsgV1,
    HandshakeVersion, Identity, IdentityVerify, ServerHello,
};
use crate::{
    CompletionToken, DalekVerifier, Error, HandshakeMsgVec, RecvToken, Role,
    SendToken, Session, UserAction,
};
use sprockets_common::certificates::{
    Ed25519Certificates, Ed25519Signature, Ed25519Verifier,
};
use sprockets_common::msgs::{RotOpV1, RotResultV1};
use sprockets_common::{Ed25519PublicKey, Measurements, Nonce, Sha3_256Digest};

// The current state of the server handshake state machine
//
// Each state has different data associated with it.
//
// The states are transitioned in the order listed. No state is ever skipped.
#[allow(clippy::large_enum_variant)] // clippy suggests `Box`; we're no_std
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
        client_identity: Identity,
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
    server_certs: Ed25519Certificates,
    transcript: Sha3_256,
    // We don't know the client identity when we're created, but once we get it
    // we have to hold it until we return it in the `CompletionToken`.
    client_identity: Option<Identity>,
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
        server_certs: Ed25519Certificates,
    ) -> (ServerHandshake, RecvToken) {
        let state = Some(State::WaitForHello);
        let transcript = Sha3_256::new();
        (
            ServerHandshake {
                server_certs,
                transcript,
                client_identity: None,
                state,
            },
            RecvToken::new(),
        )
    }

    /// Handle a message from the client
    ///
    /// We take a mutable buffer because we decrypt in place to prevent the need
    /// to allocate.
    pub fn handle(
        &mut self,
        buf: &mut HandshakeMsgVec,
        _token: RecvToken,
    ) -> Result<UserAction, Error> {
        let state = self.state.take().unwrap();
        match state {
            State::WaitForHello => self.handle_hello(buf),
            State::WaitForIdentity {
                server_nonce,
                handshake_state,
            } => self.handle_identity(server_nonce, handshake_state, buf),
            State::WaitForIdentityVerify {
                client_identity,
                handshake_state,
            } => self.handle_identity_verify(
                client_identity,
                handshake_state,
                buf,
            ),
            State::WaitForFinished { handshake_state } => {
                self.handle_finished(handshake_state, buf)
            }
            _ => unreachable!(),
        }
    }

    // Get the next message to send over the session transport
    //
    // This requires a SendToken to ensure that it will only be called when the
    // next state in the protocol handshake requires sending a message.
    pub fn create_next_msg(
        &mut self,
        buf: &mut HandshakeMsgVec,
        _token: SendToken,
    ) -> Result<UserAction, Error> {
        let state = self.state.take().unwrap();
        buf.resize_default(buf.capacity()).unwrap();
        match state {
            State::SendHello { client_hello } => {
                self.create_hello_msg(client_hello, buf)
            }
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
            } => self.create_identity_verify_msg(
                server_nonce,
                signature,
                handshake_state,
                buf,
            ),
            State::SendFinished {
                server_nonce,
                handshake_state,
            } => self.create_finished_msg(server_nonce, handshake_state, buf),
            _ => unreachable!(),
        }
    }

    /// Handle the result message from an RoT
    ///
    /// Note that these are not encrypted nor serialized.
    /// Serialization/Deserialization is performed by the user, because the
    /// user also puts the `RotOpV1` into the `RotRequest`, and removes the
    /// `RotResultV1` from the `RotResponse`. This is useful as it allows the user
    /// to keep track of request ids for RotRequests across multiple sessions.
    /// The session code does not have to worry about this as a result.
    pub fn handle_rot_reply(
        &mut self,
        result: RotResultV1,
    ) -> Result<UserAction, Error> {
        let state = self.state.take().unwrap();
        match state {
            State::WaitForSignedMeasurementsFromRoT {
                client_nonce,
                server_nonce,
                handshake_state,
            } => self.handle_signed_measurements(
                client_nonce,
                server_nonce,
                handshake_state,
                result,
            ),
            State::WaitForSignedTranscriptFromRoT {
                server_nonce,
                handshake_state,
            } => self.handle_signed_transcript(
                server_nonce,
                handshake_state,
                result,
            ),
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

    fn handle_hello(
        &mut self,
        buf: &mut HandshakeMsgVec,
    ) -> Result<UserAction, Error> {
        let (msg, _) = deserialize::<HandshakeMsgV1>(buf)?;
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
        buf: &mut HandshakeMsgVec,
    ) -> Result<UserAction, Error> {
        let secret = EphemeralSecret::new(OsRng);
        let public_key = PublicKey::from(&secret);
        let server_nonce = Nonce::new();

        let msg = HandshakeMsgV1::new(
            ServerHello {
                nonce: server_nonce,
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
            client_nonce,
            server_nonce,
            handshake_state,
        });

        Ok(RotOpV1::GetMeasurements(client_nonce).into())
    }

    fn handle_signed_measurements(
        &mut self,
        client_nonce: Nonce,
        server_nonce: Nonce,
        hs: HandshakeState,
        result: RotResultV1,
    ) -> Result<UserAction, Error> {
        if let RotResultV1::Measurements(measurements, nonce, signature) =
            result
        {
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
            Err(Error::UnexpectedRotMsg)
        }
    }

    fn create_identity_msg(
        &mut self,
        server_nonce: Nonce,
        measurements: Measurements,
        measurements_sig: Ed25519Signature,
        mut hs: HandshakeState,
        buf: &mut HandshakeMsgVec,
    ) -> Result<UserAction, Error> {
        let msg = HandshakeMsgV1 {
            version: HandshakeVersion { version: 1 },
            data: HandshakeMsgDataV1::Identity(Identity {
                certs: self.server_certs,
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
        Ok(RotOpV1::SignTranscript(hash).into())
    }

    fn handle_signed_transcript(
        &mut self,
        server_nonce: Nonce,
        hs: HandshakeState,
        result: RotResultV1,
    ) -> Result<UserAction, Error> {
        if let RotResultV1::SignedTranscript(signature) = result {
            // Transition to the next state
            self.state = Some(State::SendIdentityVerify {
                server_nonce,
                signature,
                handshake_state: hs,
            });
            Ok(SendToken::new().into())
        } else {
            Err(Error::UnexpectedRotMsg)
        }
    }

    fn create_identity_verify_msg(
        &mut self,
        server_nonce: Nonce,
        transcript_signature: Ed25519Signature,
        mut hs: HandshakeState,
        buf: &mut HandshakeMsgVec,
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

    fn create_finished_msg(
        &mut self,
        server_nonce: Nonce,
        mut hs: HandshakeState,
        buf: &mut HandshakeMsgVec,
    ) -> Result<UserAction, Error> {
        // We clone so we can use the intermediate hash value but maintain
        // the running hash computation.
        //
        // The current transcript hash is:
        //   H(ClientHello || ServerHello || Identity(S) || IdentityVerify(S))
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
        self.state = Some(State::WaitForIdentity {
            server_nonce,
            handshake_state: hs,
        });

        Ok(RecvToken::new().into())
    }

    // TODO: Add a Corpus to the state and validate measurements
    fn handle_identity(
        &mut self,
        server_nonce: Nonce,
        mut hs: HandshakeState,
        buf: &mut HandshakeMsgVec,
    ) -> Result<UserAction, Error> {
        let msg_data = hs.decrypt_and_deserialize(buf)?;
        if let HandshakeMsgDataV1::Identity(identity) = msg_data {
            self.transcript.update(buf);

            // Validate the certificate chains
            identity.certs.validate(
                &self.server_certs.manufacturing_public_key,
                &DalekVerifier,
            )?;

            // Ensure measurements concatenated with the client nonce are
            // properly signed.
            let mut signed_buf =
                [0u8; Measurements::MAX_SIZE + Nonce::MAX_SIZE];
            let size = identity
                .measurements
                .serialize_with_nonce(&server_nonce, &mut signed_buf)?;
            DalekVerifier
                .verify(
                    &identity.certs.measurement.subject_public_key,
                    &signed_buf[..size],
                    &identity.measurements_sig,
                )
                .map_err(|_| Error::BadMeasurementsSig)?;

            // Transition to the next state
            self.state = Some(State::WaitForIdentityVerify {
                client_identity: identity,
                handshake_state: hs,
            });

            Ok(RecvToken::new().into())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    fn handle_identity_verify(
        &mut self,
        client_identity: Identity,
        mut hs: HandshakeState,
        buf: &mut HandshakeMsgVec,
    ) -> Result<UserAction, Error> {
        let msg_data = hs.decrypt_and_deserialize(buf)?;
        if let HandshakeMsgDataV1::IdentityVerify(identity_verify) = msg_data {
            // We clone so we can use the intermediate hash value but maintain
            // the running hash computation.
            //
            // The current transcript hash is:
            //   H(ClientHello || ServerHello || Identity(S) || IdentityVerify(S)
            //      || Finished(S) || Identity(C))
            //
            let transcript_hash = self.transcript.clone().finalize();
            self.transcript.update(buf);

            // Verify the transcript hash signature
            DalekVerifier
                .verify(
                    &client_identity.certs.dhe.subject_public_key,
                    &transcript_hash,
                    &identity_verify.transcript_signature,
                )
                .map_err(|_| Error::BadTranscriptSig)?;

            // Transition to the next state
            self.state = Some(State::WaitForFinished {
                handshake_state: hs,
            });

            // Save the client identity for constructing a `CompletionToken`
            self.client_identity = Some(client_identity);

            Ok(RecvToken::new().into())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }

    fn handle_finished(
        &mut self,
        mut hs: HandshakeState,
        buf: &mut HandshakeMsgVec,
    ) -> Result<UserAction, Error> {
        let msg_data = hs.decrypt_and_deserialize(buf)?;
        if let HandshakeMsgDataV1::Finished(finished) = msg_data {
            // We clone so we can use the intermediate hash value but maintain
            // the running hash computation.
            //
            // The current transcript hash is:
            //   H(ClientHello || ServerHello || Identity(S) || IdentityVerify(S)
            //      || Finished(S) || Identity(C) ||  IdentityVerify(C))
            let transcript_hash = self.transcript.clone().finalize();
            self.transcript.update(buf);

            // Verify the MAC over the transcript hash
            hs.verify_finished_mac(&finished.mac.0, &transcript_hash)?;

            // Transition to the next state
            self.state = Some(State::Complete {
                handshake_state: hs,
            });

            // We received and verified the server identity in
            // `handle_identity_verify()`, at which point we stashed it in
            // `self.client_identity`, making it safe to unwrap here.
            let client_identity = self.client_identity.take().unwrap();
            Ok(CompletionToken::new(client_identity).into())
        } else {
            Err(Error::UnexpectedMsg)
        }
    }
}
