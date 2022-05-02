// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use salty;

use sprockets_common::msgs::{RotRequest, RotResponse};
use sprockets_common::{random_buf, Ed25519PublicKey};
use sprockets_rot::{RotConfig, RotSprocket};
use sprockets_session::{
    ClientHandshake, HandshakeMsgVec, RecvToken, ServerHandshake, UserAction,
};

// Initialize the necessary components for testing
fn bootstrap() -> (
    ChannelClient,
    HandshakeMsgVec,
    RecvToken,
    ChannelServer,
    RecvToken,
) {
    // All certs should trace back to the same manufacturing key
    let manufacturing_keypair = salty::Keypair::from(&random_buf());
    let manufacturing_public_key =
        Ed25519PublicKey(manufacturing_keypair.public.to_bytes());
    let client_rot = RotSprocket::new(RotConfig::bootstrap_for_testing(
        &manufacturing_keypair,
    ));
    let server_rot = RotSprocket::new(RotConfig::bootstrap_for_testing(
        &manufacturing_keypair,
    ));
    let (client_tx, server_rx) = mpsc::channel();
    let (server_tx, client_rx) = mpsc::channel();

    let mut client_hello_buf = HandshakeMsgVec::new();
    client_hello_buf
        .resize_default(client_hello_buf.capacity())
        .unwrap();
    let (client_hs, client_recv_token) = ClientHandshake::init(
        manufacturing_public_key.clone(),
        client_rot.get_certificates(),
        &mut client_hello_buf,
    );
    let client = ChannelClient {
        rot: client_rot,
        tx: client_tx,
        rx: client_rx,
        hs: Some(client_hs),
    };

    let (server_hs, server_recv_token) = ServerHandshake::init(
        manufacturing_public_key,
        server_rot.get_certificates(),
    );
    let server = ChannelServer {
        rot: server_rot,
        tx: server_tx,
        rx: server_rx,
        hs: Some(server_hs),
    };

    (
        client,
        client_hello_buf,
        client_recv_token,
        server,
        server_recv_token,
    )
}

// A client using 2 channels for transport
struct ChannelClient {
    rot: RotSprocket,
    tx: Sender<HandshakeMsgVec>,
    rx: Receiver<HandshakeMsgVec>,

    // We start with a handshake, and then transition to a session upon
    // handshake completion
    hs: Option<ClientHandshake>,
}

impl ChannelClient {
    // Run the client so that it completes the handshake then sends an encrypted
    // msg, "oxide", that gets echoed back from the server.
    pub fn run(&mut self, hello: HandshakeMsgVec, recv_token: RecvToken) {
        // Send the ClientHello
        self.tx.send(hello).unwrap();

        // Receive the ServerHello
        let mut server_hello = self.rx.recv().unwrap();

        // Handle the ServerHello and retrieve the next action to take
        let mut hs = self.hs.take().unwrap();
        let mut action = hs.handle(&mut server_hello, recv_token).unwrap();

        // A msg id counter to use for RotRequests
        let mut req_id = 0;

        // Keep executing handshake actions until complete.
        let completion_token = loop {
            action = match action {
                UserAction::Recv(token) => {
                    let mut msg = self.rx.recv().unwrap();
                    hs.handle(&mut msg, token).unwrap()
                }
                UserAction::Send(token) => {
                    // Create a buffer to hold the message
                    let mut msg = HandshakeMsgVec::new();
                    msg.resize_default(msg.capacity()).unwrap();

                    // Fill in the msg to send and get the next action to take
                    let next_action =
                        hs.create_next_msg(&mut msg, token).unwrap();

                    self.tx.send(msg).unwrap();
                    next_action
                }
                UserAction::SendToRot(op) => {
                    let req = RotRequest::V1 { id: req_id, op };
                    // This is a test, don't bother with serialization
                    let RotResponse::V1 { id, result } =
                        self.rot.handle_deserialized(req).unwrap();
                    assert_eq!(id, req_id);
                    req_id += 1;
                    hs.handle_rot_reply(result).unwrap()
                }
                UserAction::Complete(token) => {
                    break token;
                }
            };
        };

        println!("Client handshake complete");

        // Handshake is complete. Transition to a session object so we can send
        // and receive application level messages.
        let mut session = hs.new_session(completion_token);

        // A handshake HandshakeMsgVec is large enough for this test message. In practice, a
        // different type would be used. We only use the same type to require
        // only two channels.
        let mut msg = HandshakeMsgVec::new();
        msg.extend_from_slice(b"oxide").unwrap();

        // Encrypt and send the message
        session.encrypt(&mut msg).unwrap();
        self.tx.send(msg).unwrap();

        // Receive the echoed response and decrypt it
        let mut msg = self.rx.recv().unwrap();
        session.decrypt(&mut msg).unwrap();

        // Assert that the received msg was what we sent.
        assert_eq!(msg.as_slice(), b"oxide");
    }
}

// A server using 2 channels for transport
struct ChannelServer {
    rot: RotSprocket,
    tx: Sender<HandshakeMsgVec>,
    rx: Receiver<HandshakeMsgVec>,

    // We start with a handshake, and then transition to a session upon
    // handshake completion
    hs: Option<ServerHandshake>,
}

impl ChannelServer {
    // Run the server so that it completes the handshake then receives an encrypted
    // msg, "oxide", and echoes it back to the client.
    pub fn run(&mut self, recv_token: RecvToken) {
        // Receive the ClientHello
        let mut client_hello = self.rx.recv().unwrap();

        // Handle the ClientHello and retrieve the next action to take
        let mut hs = self.hs.take().unwrap();
        let mut action = hs.handle(&mut client_hello, recv_token).unwrap();

        // A msg id counter to use for RotRequests
        let mut req_id = 0;

        // This loop is identical to the client loop, except for handshake
        // type. We can probably abstract it.
        let completion_token = loop {
            action = match action {
                UserAction::Recv(token) => {
                    let mut msg = self.rx.recv().unwrap();
                    hs.handle(&mut msg, token).unwrap()
                }
                UserAction::Send(token) => {
                    // Create a buffer to hold the message
                    let mut msg = HandshakeMsgVec::new();
                    msg.resize_default(msg.capacity()).unwrap();

                    // Fill in the msg to send and get the next action to take
                    let next_action =
                        hs.create_next_msg(&mut msg, token).unwrap();

                    self.tx.send(msg).unwrap();
                    next_action
                }
                UserAction::SendToRot(op) => {
                    let req = RotRequest::V1 { id: req_id, op };
                    // This is a test, don't bother with serialization
                    let RotResponse::V1 { id, result } =
                        self.rot.handle_deserialized(req).unwrap();
                    assert_eq!(id, req_id);
                    req_id += 1;
                    hs.handle_rot_reply(result).unwrap()
                }
                UserAction::Complete(token) => {
                    break token;
                }
            };
        };

        println!("Server handshake complete");

        let mut session = hs.new_session(completion_token);

        // Receive the application level message, decrypt it, re-encrypt it, and echo it back.
        let mut msg = self.rx.recv().unwrap();
        session.decrypt(&mut msg).unwrap();
        assert_eq!(msg.as_slice(), b"oxide");
        session.encrypt(&mut msg).unwrap();
        self.tx.send(msg).unwrap();
    }
}

// Setup an encrypted session between a client and server using channels as
// transport. Then echo back a message from the client over the encrypted
// session.
#[test]
fn encrypted_session_over_channels() {
    let (
        mut client,
        client_hello_buf,
        client_recv_token,
        mut server,
        server_recv_token,
    ) = bootstrap();
    let server_thread = thread::spawn(move || {
        server.run(server_recv_token);
    });

    client.run(client_hello_buf, client_recv_token);

    server_thread.join().unwrap();
}
