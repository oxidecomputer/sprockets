// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runs the QUIC example pair (`server_quic` / `client_quic`) against each
//! other end to end, as separate processes over loopback — the examples are
//! themselves part of the crate's contract, and this pins them working.
//!
//! Cargo builds examples as part of `cargo test`, but provides no
//! `CARGO_BIN_EXE_<name>` for them (that exists only for `[[bin]]` targets),
//! so the binaries are located relative to the test executable:
//! `target/<profile>/examples/`. The test PKI comes from `OUT_DIR`, where
//! `build.rs` generates it (the `unittest` feature is always enabled for test
//! builds via the crate's self-dev-dependency).

#![cfg(feature = "quic")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddrV6;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Bound on every wait in this test, so a wedged process fails the test
/// instead of hanging the suite.
const TIMEOUT: Duration = Duration::from_secs(60);

fn example_bin(name: &str) -> PathBuf {
    // The test executable lives in target/<profile>/deps/; examples are
    // siblings of deps/ in target/<profile>/examples/.
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("examples");
    path.push(name);
    assert!(
        path.exists(),
        "example binary {path:?} not found; \
         it is built by `cargo test --features quic`"
    );
    path
}

fn pki(file: &str) -> PathBuf {
    PathBuf::from(env!("OUT_DIR")).join(file)
}

/// The five positional paths of the examples' `local` subcommand, for test
/// identity `n`.
fn identity_args(n: usize) -> Vec<PathBuf> {
    vec![
        pki(&format!("test-sprockets-auth-{n}.key.pem")),
        pki(&format!("test-sprockets-auth-{n}.certlist.pem")),
        pki(&format!("test-alias-{n}.key.pem")),
        pki(&format!("test-alias-{n}.certlist.pem")),
        pki("log.bin"),
    ]
}

fn base_cmd(bin: &Path) -> Command {
    let mut cmd = Command::new(bin);
    cmd.arg("--roots")
        .arg(pki("test-root-a.cert.pem"))
        .arg("--corpus")
        .arg(pki("corim-rot.cbor"))
        .arg("--corpus")
        .arg(pki("corim-sp.cbor"))
        .arg("--enforce");
    cmd
}

/// Kills the wrapped child on scope exit, so a failing assertion never leaks
/// a listening server process.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_bounded(child: &mut Child, what: &str) -> ExitStatus {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "{what} did not exit within {TIMEOUT:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Runs `client_quic` against `addr`, feeding `msg` on stdin, and returns
/// what the client wrote to stdout (the echo; the client logs to stderr).
fn run_client(bin: &Path, addr: &str, msg: &str) -> String {
    let mut child = base_cmd(bin)
        .arg("--addr")
        .arg(addr)
        .arg("local")
        .args(identity_args(2))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Write the message, then drop the handle: the resulting stdin EOF is
    // what moves the client to shutdown-and-drain.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(msg.as_bytes())
        .unwrap();

    let status = wait_bounded(&mut child, "client_quic");
    assert!(status.success(), "client_quic exited with {status}");

    // The echo is far smaller than the pipe buffer, so reading after exit
    // cannot have blocked the child.
    let mut echoed = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut echoed)
        .unwrap();
    echoed
}

/// The example pair round-trips messages over an attested QUIC connection:
/// the server started on port 0 announces its real address, each client's
/// stdin comes back complete on its stdout, and the server survives clients
/// departing (it used to panic when a finished client closed its
/// connection).
#[test]
fn example_pair_round_trips() {
    let mut server = KillOnDrop(
        base_cmd(&example_bin("server_quic"))
            .arg("--addr")
            .arg("[::1]:0")
            .arg("local")
            .args(identity_args(1))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    // The server's first stdout line announces the OS-assigned address. Read
    // it via a thread + channel so a silent server trips TIMEOUT rather than
    // blocking the test forever; the thread then keeps draining stdout so
    // the server can never block on a full pipe.
    let stdout = server.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        if let Some(Ok(line)) = lines.next() {
            let _ = tx.send(line);
        }
        for _ in lines {}
    });
    let line = rx
        .recv_timeout(TIMEOUT)
        .expect("server_quic announced its listen address");
    let addr = line
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected announce line: {line:?}"));
    let addr: SocketAddrV6 = addr.parse().unwrap();
    let addr = addr.to_string();

    let client_bin = example_bin("client_quic");

    const FIRST: &str = "hello over quic\n";
    assert_eq!(run_client(&client_bin, &addr, FIRST), FIRST);

    const SECOND: &str = "second client\n";
    assert_eq!(run_client(&client_bin, &addr, SECOND), SECOND);

    assert!(
        server.0.try_wait().unwrap().is_none(),
        "server_quic must outlive its clients"
    );
}
