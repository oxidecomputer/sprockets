// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use sprockets_common::msgs::{RotOp, RotRequest};
use sprockets_common::Nonce;
use sprockets_host::Uart;

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

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut uart = Uart::attach(&args.path, args.baud_rate)?;

    let op = match args.op {
        Op::GetCertificates => RotOp::GetCertificates,
        Op::GetMeasurements => RotOp::GetMeasurements(Nonce::new()),
    };
    let req = RotRequest::V1 { id: 1, op };

    uart.send(req)?;
    let rsp = uart.recv()?;

    println!("{:?}", rsp);

    Ok(())
}
