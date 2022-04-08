use anyhow::bail;
use clap::Parser;
use corncobs;
use hubpack::{deserialize, serialize, SerializedSize};
use sprockets_common::msgs::{RotOp, RotRequest, RotResponse};
use sprockets_common::Nonce;
use sprockets_host::Uart;
use std::io::{self, Read, Write};

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

    uart.port().clear(serialport::ClearBuffer::All);

    let mut req_buf = [0u8; RotRequest::MAX_SIZE];
    let op = match args.op {
        Op::GetCertificates => RotOp::GetCertificates,
        Op::GetMeasurements => RotOp::GetMeasurements(Nonce::new()),
    };
    let req = RotRequest::V1 { id: 1, op };
    let size = serialize(&mut req_buf, &req).unwrap();

    println!("Serialized size = {}", size);

    let mut encoded_buf = [0xFFu8; corncobs::max_encoded_len(RotRequest::MAX_SIZE)];
    let size = corncobs::encode_buf(&req_buf[..size], &mut encoded_buf);

    //    let size = uart.port().write_all(&encoded_buf[..size]).unwrap();

    println!("Sent {:?}", &encoded_buf[..size]);
    let mut pos = 0;
    loop {
        let sent_size = uart.port().write(&encoded_buf[pos..size]).unwrap();
        println!("sent size = {}", sent_size);
        pos += sent_size;
        if pos == size {
            break;
        }
    }

    // Read cobs encoded response back
    // TODO: Move this into the uart code

    let mut encoded_rsp_buf = [0xFFu8; corncobs::max_encoded_len(RotResponse::MAX_SIZE)];
    let mut pos = 0;
    loop {
        let bytes_read = uart.port().read(&mut encoded_rsp_buf[pos..])?;
        // The last byte should always be a 0
        pos += bytes_read;
        if encoded_rsp_buf[pos - 1] == 0 {
            break;
        } else {
            if pos == encoded_rsp_buf.len() {
                bail!("Invalid Response message");
            }
        }
    }

    let mut rsp_buf = [0u8; RotResponse::MAX_SIZE];
    let size = corncobs::decode_buf(&encoded_rsp_buf[..pos], &mut rsp_buf).unwrap();

    let (response, _) = deserialize::<RotResponse>(&rsp_buf[..size])?;

    println!("{:?}", response);

    Ok(())
}
