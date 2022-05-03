// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::{Duration, Instant};

use sprockets_common::msgs::{
    RotError, RotOpV1, RotRequestV1, RotResponseV1, RotResultV1,
};
use tokio::sync::{mpsc, oneshot};

// One slot for each sled in a rack
const CHANNEL_CAPACITY: usize = 32;

// The mechanism for sending requests to the RoT from the host, and waiting for
// replies.
pub trait RotTransport {
    type Error: std::error::Error;
    fn send(&mut self, req: RotRequestV1) -> Result<(), Self::Error>;
    fn recv(&mut self) -> Result<RotResponseV1, Self::Error>;
    fn set_timeout(&mut self, timeout: Duration) -> Result<(), Self::Error>;
}

/// A message handled by the RotManager
#[derive(Debug)]
pub enum RotManagerMsg {
    // A request to be transmitted to the RotSprocket
    RotRequest {
        timeout: Duration,
        op: RotOpV1,
        reply_tx: oneshot::Sender<RotResultV1>,
    },

    // Shutdown the recv loop
    Shutdown,
}

/// All RoT requests go over the uart serially. The RotManager cues up requests
/// from multiple session handshakes in order to send them one at a time.
pub struct RotManager<T: RotTransport> {
    // A monotonic counter across all RotRequests
    request_id: u64,

    // Receive a message from a tokio task with an RotRequestV1 and a tokio
    // oneshot sender for replying.
    rx: mpsc::Receiver<RotManagerMsg>,

    // The RotManager sends requests and receives responses over this transport
    // one at a time.
    rot_transport: T,
}

impl<T: RotTransport> RotManager<T> {
    pub fn new(
        rot_transport: T,
    ) -> (RotManager<T>, mpsc::Sender<RotManagerMsg>) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        (
            RotManager {
                request_id: 0,
                rx,
                rot_transport,
            },
            tx,
        )
    }

    /// Loop receiving messages until all senders close or a Shutdown message is
    /// received.
    pub fn run(&mut self) {
        while let Some(msg) = self.rx.blocking_recv() {
            match msg {
                RotManagerMsg::RotRequest {
                    timeout,
                    op,
                    reply_tx,
                } => {
                    let result = self.send_to_rot(op, timeout);
                    let _ = reply_tx.send(result);
                }
                RotManagerMsg::Shutdown => break,
            }
        }
    }

    fn send_to_rot(&mut self, op: RotOpV1, timeout: Duration) -> RotResultV1 {
        let start = Instant::now();
        self.request_id += 1;
        let request = RotRequestV1 {
            version: 1,
            id: self.request_id,
            op,
        };
        if let Err(e) = self.rot_transport.set_timeout(timeout) {
            // TODO: Log real error
            return RotResultV1::Err(RotError::TransportError);
        }
        if let Err(err) = self.rot_transport.send(request) {
            // TODO: Log real error
            return RotResultV1::Err(RotError::SendError);
        }
        self.recv_from_rot(start, timeout)
    }

    fn recv_from_rot(
        &mut self,
        start: Instant,
        timeout: Duration,
    ) -> RotResultV1 {
        loop {
            match self.rot_transport.recv() {
                Ok(response) => {
                    if response.id != self.request_id {
                        // TODO: Log skip?
                        // This is a stale id. Skip it, and wait some more.
                        let remaining = timeout.saturating_sub(start.elapsed());
                        if remaining == Duration::ZERO {
                            return RotResultV1::Err(RotError::Timeout);
                        }
                        if let Err(e) =
                            // TODO: Log real error
                            self.rot_transport.set_timeout(remaining)
                        {
                            return RotResultV1::Err(RotError::TransportError);
                        }
                    }
                    return response.result;
                }
                Err(e) => {
                    // TODO: Log real error
                    return RotResultV1::Err(RotError::RecvError);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sprockets_common::{random_buf, Ed25519PublicKey};
    use sprockets_rot::{RotConfig, RotSprocket};
    use std::collections::VecDeque;
    use thiserror::Error;

    fn new_rot() -> RotSprocket {
        let manufacturing_keypair = salty::Keypair::from(&random_buf());
        RotSprocket::new(RotConfig::bootstrap_for_testing(
            &manufacturing_keypair,
        ))
    }

    #[derive(Error, Debug)]
    enum TestTransportError {
        #[error("Send")]
        Send,
        #[error("Recv")]
        Recv,
        #[error("Timeout")]
        Timeout,
    }

    struct TestTransport {
        rot: RotSprocket,
        req: Option<RotRequestV1>,
        errors: VecDeque<TestTransportError>,
    }

    impl TestTransport {
        fn new() -> TestTransport {
            TestTransport {
                rot: new_rot(),
                req: None,
                errors: VecDeque::new(),
            }
        }

        // Force the transport to create an error scenario.
        //
        // We use TestTransportError for the convenience of not having to create
        // another enum for this purpose.
        //
        // Each message received will be affected by the errors in order.
        fn inject_errors(&mut self, errors: VecDeque<TestTransportError>) {
            self.errors = errors;
        }
    }

    impl RotTransport for TestTransport {
        type Error = TestTransportError;

        fn send(&mut self, req: RotRequestV1) -> Result<(), Self::Error> {
            if let Some(TestTransportError::Send) = self.errors.front() {
                let _ = self.errors.pop_front();
                return Err(TestTransportError::Send);
            }
            self.req = Some(req);
            Ok(())
        }

        fn recv(&mut self) -> Result<RotResponseV1, Self::Error> {
            match self.errors.pop_front() {
                Some(TestTransportError::Recv) => {
                    return Err(TestTransportError::Recv)
                }
                Some(TestTransportError::Timeout) => {
                    // Return a "stale" message with a bogus request id.
                    // This emulates a prior transport timeout, followed by the
                    // RoT finally returning the old result that is no longer
                    // valid.
                    let mut msg = self
                        .rot
                        .handle_deserialized(self.req.take().unwrap())
                        .unwrap();
                    msg.id -= 1;
                    return Ok(msg);
                }
                Some(e) => self.errors.push_front(e),
                None => (),
            }
            Ok(self
                .rot
                .handle_deserialized(self.req.take().unwrap())
                .unwrap())
        }

        // We arent' going to bother actually tracking time inside this fake
        // transport. We can assume everything happens instantaneously, and
        // force timeouts via error injection.
        fn set_timeout(
            &mut self,
            _timeout: Duration,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn successful_op() {
        let (mut mgr, tx) = RotManager::new(TestTransport::new());
        let mgr_thread = std::thread::spawn(move || mgr.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RotManagerMsg::RotRequest {
            timeout: Duration::from_millis(100),
            op: RotOpV1::GetCertificates,
            reply_tx,
        };

        tx.send(msg).await.unwrap();
        let result = reply_rx.await.unwrap();
        assert!(matches!(result, RotResultV1::Certificates(..)));

        tx.send(RotManagerMsg::Shutdown).await.unwrap();
        mgr_thread.join().unwrap();
    }

    // A timeout is returned as a result of a stale message taking a long time
    // to process.
    //
    // We use a zero timeout for each message, and therefore when an old
    // message is received, the timeout is noticed before the manager tries to
    // receive from the transport again.
    #[tokio::test]
    async fn injected_errors() {
        let mut transport = TestTransport::new();
        transport.inject_errors(VecDeque::from([
            TestTransportError::Send,
            TestTransportError::Recv,
            TestTransportError::Timeout,
        ]));

        let (mut mgr, tx) = RotManager::new(transport);
        let mgr_thread = std::thread::spawn(move || mgr.run());

        for i in 0..3 {
            let (reply_tx, reply_rx) = oneshot::channel();
            let msg = RotManagerMsg::RotRequest {
                timeout: Duration::ZERO,
                op: RotOpV1::GetCertificates,
                reply_tx,
            };

            tx.send(msg).await.unwrap();
            let result = reply_rx.await.unwrap();
            match i {
                0 => assert_eq!(result, RotResultV1::Err(RotError::SendError)),
                1 => assert_eq!(result, RotResultV1::Err(RotError::RecvError)),
                2 => assert_eq!(result, RotResultV1::Err(RotError::Timeout)),
                _ => (),
            }
        }
        tx.send(RotManagerMsg::Shutdown).await.unwrap();
        mgr_thread.join().unwrap();
    }
}
