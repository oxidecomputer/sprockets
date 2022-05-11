// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use slog::{error, o, warn, Logger};
use sprockets_common::msgs::{
    RotOpV1, RotRequestV1, RotResponseV1, RotResultV1,
};
use std::fmt::Debug;
use std::fmt::Display;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// The mechanism for interacting with the RoT from the host.
pub trait RotTransport {
    type Error: Display;

    /// Send a request to the RoT, returning an error if the deadline is
    /// exceeded in addition to any other possible errors from the transport.
    fn send(
        &mut self,
        req: RotRequestV1,
        deadline: Instant,
    ) -> Result<(), Self::Error>;

    /// Receive a message from an RoT, returning an error if the deadline is
    /// exceeded, in addition to any other possible errors from the transport.
    fn recv(&mut self, deadline: Instant)
        -> Result<RotResponseV1, Self::Error>;
}

// An error resulting from communcation with the RotManager
#[derive(Error, Debug, PartialEq)]
pub enum RotManagerError<T: Display> {
    #[error("send to RotManager failed. Is the RotManager running?")]
    SendFailed(RotOpV1),
    #[error("recv from RotManager failed. Is the RotManager running?")]
    RecvFailed,
    #[error("shutdown failed. Is the RotManager running?")]
    ShutdownFailed,
    #[error("RoT transport error: {0}")]
    TransportError(T),
}

/// An API wrapper to send messages to and receive replies from an RotManager
/// running in a seperate thread.
pub struct RotManagerHandle<T: RotTransport> {
    tx: mpsc::Sender<RotManagerMsg<T>>,
}

impl<T: RotTransport> RotManagerHandle<T> {
    pub async fn call(
        &self,
        op: RotOpV1,
        deadline: Instant,
    ) -> Result<RotResultV1, RotManagerError<T::Error>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RotManagerMsg::RotRequest {
            deadline,
            op,
            reply_tx,
        };
        self.tx.send(msg).await.map_err(|e| {
            if let RotManagerMsg::RotRequest { op, .. } = e.0 {
                RotManagerError::SendFailed(op)
            } else {
                unreachable!();
            }
        })?;
        reply_rx.await.map_err(|_| RotManagerError::RecvFailed)?
    }

    pub async fn shutdown(&self) {
        let msg = RotManagerMsg::Shutdown;
        let _ = self.tx.send(msg).await;
    }
}

/// A message handled by the RotManager
#[derive(Debug)]
enum RotManagerMsg<T: RotTransport> {
    // A request to be transmitted to the RotSprocket
    RotRequest {
        deadline: Instant,
        op: RotOpV1,
        reply_tx:
            oneshot::Sender<Result<RotResultV1, RotManagerError<T::Error>>>,
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
    rx: mpsc::Receiver<RotManagerMsg<T>>,

    // The RotManager sends requests and receives responses over this transport
    // one at a time.
    rot_transport: T,

    // A slog logger
    logger: Logger,
}

impl<T: RotTransport> RotManager<T> {
    /// Create a new RotTransport.
    ///
    /// `channel_capacity` should reflect the number of RoTs being communicated
    ///  with simultaneously. For trust quorum purposes, this is the number of
    /// sleds in a rack.
    pub fn new(
        channel_capacity: usize,
        rot_transport: T,
        logger: Logger,
    ) -> (RotManager<T>, RotManagerHandle<T>) {
        let logger = logger.new(o!("component" => "RotManager"));
        let (tx, rx) = mpsc::channel(channel_capacity);
        (
            RotManager {
                request_id: 0,
                rx,
                rot_transport,
                logger,
            },
            RotManagerHandle { tx },
        )
    }

    /// Loop receiving messages until all senders close or a Shutdown message is
    /// received.
    pub fn run(mut self) {
        while let Some(msg) = self.rx.blocking_recv() {
            match msg {
                RotManagerMsg::RotRequest {
                    deadline,
                    op,
                    reply_tx,
                } => {
                    let result = self.send_to_rot(op, deadline);
                    let _ = reply_tx.send(result);
                }
                RotManagerMsg::Shutdown => break,
            }
        }
    }

    fn send_to_rot(
        &mut self,
        op: RotOpV1,
        deadline: Instant,
    ) -> Result<RotResultV1, RotManagerError<T::Error>> {
        self.request_id += 1;
        let request = RotRequestV1 {
            version: 1,
            id: self.request_id,
            op,
        };

        self.rot_transport
            .send(request, deadline)
            .map_err(|e| RotManagerError::TransportError(e))?;
        self.recv_from_rot(deadline)
    }

    // Receive `RotResponseV1` messages from the RoT.
    //
    // If there is a prior transport timeout, the RoT may return a "stale"
    // message with an old request id. In this case we need to call
    // `self.rot_transport.recv()` again to try to recv the actual response we
    // are waiting for.
    fn recv_from_rot(
        &mut self,
        deadline: Instant,
    ) -> Result<RotResultV1, RotManagerError<T::Error>> {
        loop {
            let response = self
                .rot_transport
                .recv(deadline)
                .map_err(|e| RotManagerError::TransportError(e))?;

            if response.id == self.request_id {
                return Ok(response.result);
            }

            // This is a stale id. Skip it, and wait some more.
            warn!(
              self.logger,
              "Received stale response over rot_transport: ";
                "request_id" => self.request_id,
                "response_id" => response.id
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use slog::Drain;
    use slog_term;
    use sprockets_common::certificates::SerialNumber;
    use sprockets_common::{random_buf, Sha3_256Digest};
    use sprockets_rot::{RotConfig, RotSprocket};
    use std::collections::VecDeque;
    use std::time::Duration;

    pub(crate) fn test_logger() -> Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(drain, o!("ctx" => "test"))
    }

    fn new_rot(manufacturing_keypair: &salty::Keypair) -> RotSprocket {
        RotSprocket::new(RotConfig::bootstrap_for_testing(
            &manufacturing_keypair,
            salty::Keypair::from(&random_buf()),
            SerialNumber(random_buf()),
        ))
    }

    #[derive(Error, Debug, PartialEq)]
    pub(crate) enum TestTransportError {
        #[error("Send")]
        Send,
        #[error("Recv")]
        Recv,
        #[error("Timeout")]
        Timeout,
    }

    pub(crate) struct TestTransport {
        pub(crate) rot: RotSprocket,
        req: Option<RotRequestV1>,
        errors: VecDeque<TestTransportError>,
        timed_out_responses: VecDeque<RotResponseV1>,
    }

    impl TestTransport {
        pub(crate) fn from_manufacturing_keypair(
            manufacturing_keypair: &salty::Keypair,
        ) -> Self {
            TestTransport {
                rot: new_rot(manufacturing_keypair),
                req: None,
                errors: VecDeque::new(),
                timed_out_responses: VecDeque::new(),
            }
        }

        fn new() -> TestTransport {
            let manufacturing_keypair = salty::Keypair::from(&random_buf());
            Self::from_manufacturing_keypair(&manufacturing_keypair)
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

        fn send(
            &mut self,
            req: RotRequestV1,
            _: Instant,
        ) -> Result<(), Self::Error> {
            if let Some(TestTransportError::Send) = self.errors.front() {
                let _ = self.errors.pop_front();
                return Err(TestTransportError::Send);
            }
            self.req = Some(req);
            Ok(())
        }

        fn recv(&mut self, _: Instant) -> Result<RotResponseV1, Self::Error> {
            match self.errors.pop_front() {
                Some(TestTransportError::Recv) => {
                    return Err(TestTransportError::Recv)
                }
                Some(TestTransportError::Timeout) => {
                    // Save this message to return later, emulating a slow RoT.
                    let msg = self
                        .rot
                        .handle_deserialized(self.req.take().unwrap())
                        .unwrap();
                    self.timed_out_responses.push_back(msg);
                    return Err(TestTransportError::Timeout);
                }
                Some(e) => self.errors.push_front(e),
                None => (),
            }
            if let Some(old_msg) = self.timed_out_responses.pop_front() {
                Ok(old_msg)
            } else {
                Ok(self
                    .rot
                    .handle_deserialized(self.req.take().unwrap())
                    .unwrap())
            }
        }
    }

    #[tokio::test]
    async fn successful_op() {
        let (mgr, handle) =
            RotManager::new(32, TestTransport::new(), test_logger());
        let mgr_thread = std::thread::spawn(move || mgr.run());

        let result = handle
            .call(
                RotOpV1::GetCertificates,
                Instant::now() + Duration::from_millis(100),
            )
            .await
            .unwrap();

        assert!(matches!(result, RotResultV1::Certificates(..)));

        handle.shutdown().await;
        mgr_thread.join().unwrap();
    }

    // A timeout is returned as a result of a message taking a long time
    // to process.
    //
    // On the next call the stale message gets skipped successfully.
    #[tokio::test]
    async fn injected_errors() {
        let mut transport = TestTransport::new();
        transport.inject_errors(VecDeque::from([
            TestTransportError::Send,
            TestTransportError::Recv,
            TestTransportError::Timeout,
        ]));

        let (mgr, handle) = RotManager::new(32, transport, test_logger());
        let mgr_thread = std::thread::spawn(move || mgr.run());

        for i in 0..3 {
            let err = handle
                .call(RotOpV1::GetCertificates, Instant::now())
                .await
                .unwrap_err();

            match i {
                0 => assert_eq!(
                    err,
                    RotManagerError::TransportError(TestTransportError::Send)
                ),
                1 => assert_eq!(
                    err,
                    RotManagerError::TransportError(TestTransportError::Recv)
                ),
                2 => assert_eq!(
                    err,
                    RotManagerError::TransportError(
                        TestTransportError::Timeout
                    )
                ),
                _ => (),
            }
        }

        // We can still succeed after a timeout
        let result = handle
            .call(
                RotOpV1::SignTranscript(Sha3_256Digest([0; 32])),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();

        assert!(matches!(result, RotResultV1::SignedTranscript(..)));

        handle.shutdown().await;
        mgr_thread.join().unwrap();
    }
}
