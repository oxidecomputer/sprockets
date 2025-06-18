// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
#[cfg(feature = "unittest")]
use anyhow::{anyhow, Context};

/// This path is where Oxide specific libraries live on helios systems.
/// This is needed for linking with libipcc
#[cfg(target_os = "illumos")]
static OXIDE_PLATFORM: &str = "/usr/platform/oxide/lib/amd64/";

/// Execute one of the `pki-playground` commands to generate part of the PKI
/// used for testing.
#[cfg(feature = "unittest")]
fn pki_gen_cmd(command: &str) -> Result<()> {
    let mut cmd = std::process::Command::new("pki-playground");
    cmd.arg(command);
    let output = cmd
        .output()
        .context("executing command \"pki-playground\"")?;

    if !output.status.success() {
        let stdout = String::from_utf8(output.stdout)
            .context("String from pki-playground stdout")?;
        println!("stdout: {stdout}");
        let stderr = String::from_utf8(output.stderr)
            .context("String from pki-playground stderr")?;
        println!("stderr: {stderr}");

        return Err(anyhow!("cmd failed: {cmd:?}"));
    }

    Ok(())
}

fn main() -> Result<()> {
    #[cfg(target_os = "illumos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-R{}", OXIDE_PLATFORM);
        println!("cargo:rustc-link-search={}", OXIDE_PLATFORM);
    }

    #[cfg(feature = "unittest")]
    {
        let start_dir = std::env::current_dir().context("get current dir")?;
        std::env::set_current_dir("test-keys/")
            .context("chdir to test keys")?;

        // generate keys, certs, and cert chains / lists used by `cargo test`
        pki_gen_cmd("generate-key-pairs")?;
        pki_gen_cmd("generate-certificates")?;
        pki_gen_cmd("generate-certificate-lists")?;

        std::env::set_current_dir(start_dir)
            .context("restore current dir to original")?;
    }

    Ok(())
}
