// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use std::env;
use std::process::{Command as StdCommand, Stdio};

#[derive(Parser)]
struct Xtask {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser)]
enum Command {
    /// Alias to run the example server with generated test keys locally
    Server { addr: String },
    /// Alias to run the example client with generated test keys locally
    Client { addr: String },
}

const ROOT_A: &str = "test-root-a.cert.pem";

const CLIENT_TQ_PRIV_KEY: &str = "test-sprockets-auth-2.key.pem";
const CLIENT_TQ_CERT_CHAIN: &str = "test-sprockets-auth-2.certlist.pem";
const CLIENT_ATTEST_PRIV_KEY: &str = "test-alias-2.key.pem";
const CLIENT_ATTEST_CHAIN: &str = "test-alias-2.certlist.pem";

const SERVER_TQ_PRIV_KEY: &str = "test-sprockets-auth-1.key.pem";
const SERVER_TQ_CERT_CHAIN: &str = "test-sprockets-auth-1.certlist.pem";
const SERVER_ATTEST_PRIV_KEY: &str = "test-alias-1.key.pem";
const SERVER_ATTEST_CHAIN: &str = "test-alias-1.certlist.pem";

const MEASUREMENT_LOG: &str = "log.bin";

const CORPUS_ROT: &str = "corim-rot.cbor";
const CORPUS_SP: &str = "corim-sp.cbor";

fn main() -> Result<()> {
    let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pki_keydir.pop();
    pki_keydir.push("tls");
    pki_keydir.push("test-keys");

    let xtask = Xtask::parse();
    match xtask.cmd {
        Command::Server { addr } => {
            let cargo =
                std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut command = StdCommand::new(cargo);
            command.arg("run");
            command.arg("--example");
            command.arg("server");
            command.arg("--");
            command.arg("--addr");
            command.arg(addr);
            command.arg("--roots");
            command.arg(pki_keydir.join(ROOT_A));
            command.arg("--corpus");
            command.arg(pki_keydir.join(CORPUS_ROT));
            command.arg("--corpus");
            command.arg(pki_keydir.join(CORPUS_SP));
            command.arg("local");
            command.arg(pki_keydir.join(SERVER_TQ_PRIV_KEY));
            command.arg(pki_keydir.join(SERVER_TQ_CERT_CHAIN));
            command.arg(pki_keydir.join(SERVER_ATTEST_PRIV_KEY));
            command.arg(pki_keydir.join(SERVER_ATTEST_CHAIN));
            command.arg(pki_keydir.join(MEASUREMENT_LOG));

            let mut child = command
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()?;

            let status = child.wait();
            println!("ran with status {:?}", status);
        }
        Command::Client { addr } => {
            let cargo =
                std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut command = StdCommand::new(cargo);
            command.arg("run");
            command.arg("--example");
            command.arg("client");
            command.arg("--");
            command.arg("--addr");
            command.arg(addr);
            command.arg("--roots");
            command.arg(pki_keydir.join(ROOT_A));
            command.arg("--corpus");
            command.arg(pki_keydir.join(CORPUS_ROT));
            command.arg("--corpus");
            command.arg(pki_keydir.join(CORPUS_SP));
            command.arg("local");
            command.arg(pki_keydir.join(CLIENT_TQ_PRIV_KEY));
            command.arg(pki_keydir.join(CLIENT_TQ_CERT_CHAIN));
            command.arg(pki_keydir.join(CLIENT_ATTEST_PRIV_KEY));
            command.arg(pki_keydir.join(CLIENT_ATTEST_CHAIN));
            command.arg(pki_keydir.join(MEASUREMENT_LOG));

            let mut child = command
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()?;

            let status = child.wait();
            println!("ran with status {:?}", status);
        }
    }
    Ok(())
}
