// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(feature = "uart"), allow(dead_code, unused_imports))]

use clap::Parser;
use sprockets_common::msgs::{RotOpV1, RotRequestV1};
use sprockets_common::Nonce;

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "115200")]
    baud_rate: u32,

    /// Path to the UART
    #[clap(short, long)]
    path: String,

    #[clap(subcommand)]
    op: Op,
}

#[derive(Debug, clap::Subcommand)]
enum Op {
    GetCertificates,
    GetMeasurements,
}

#[cfg(not(feature = "uart"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("sprockets-cli requires `uart` feature")
}

#[cfg(feature = "uart")]
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut uart =
        sprockets_host::uart::Uart::attach(&args.path, args.baud_rate)?;

    let op = match args.op {
        Op::GetCertificates => RotOpV1::GetCertificates,
        Op::GetMeasurements => RotOpV1::GetMeasurements(Nonce::new()),
    };
    let req = RotRequestV1 {
        version: 1,
        id: 1,
        op,
    };

    uart.send(req)?;
    let rsp = uart.recv()?;

    println!("{:x?}", rsp);

    Ok(())
}
