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
}
