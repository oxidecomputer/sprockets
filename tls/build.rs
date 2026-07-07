// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
#[cfg(feature = "unittest")]
use anyhow::{anyhow, Context};
#[cfg(feature = "unittest")]
use camino::Utf8PathBuf;
#[cfg(feature = "unittest")]
use pki_playground::{config, OutputFileExistsBehavior};

/// This path is where Oxide specific libraries live on helios systems.
/// This is needed for linking with libipcc
#[cfg(target_os = "illumos")]
static OXIDE_PLATFORM: &str = "/usr/platform/oxide/lib/amd64/";

/// Execute one of the `attest-mock` commands to generate attestation
/// artifacts used in testing.
#[cfg(feature = "unittest")]
fn attest_gen_cmd(command: &str, input: &str, output: &str) -> Result<()> {
    // attest-mock "input" "cmd" > "output"
    let mut cmd = std::process::Command::new("attest-mock");
    cmd.arg(input).arg(command);
    let cmd_output =
        cmd.output().context("executing command \"attest-mock\"")?;

    if cmd_output.status.success() {
        std::fs::write(output, cmd_output.stdout).context("write {output}")
    } else {
        let stderr = String::from_utf8(cmd_output.stderr)
            .context("String from attest-mock stderr")?;
        println!("stderr: {stderr}");

        Err(anyhow!("cmd failed: {cmd:?}"))
    }
}

fn main() -> Result<()> {
    #[cfg(target_os = "illumos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-R{}", OXIDE_PLATFORM);
        println!("cargo:rustc-link-search={}", OXIDE_PLATFORM);
    }

    #[cfg(feature = "unittest")]
    {
        // output directory where we put data generated test inputs
        let out = Utf8PathBuf::from(
            std::env::var("OUT_DIR")
                .context("Get OUT_DIR from the environment")?,
        );

        let config_path = "test-keys/config.kdl";
        let doc =
            config::load_and_validate(config_path.as_ref()).map_err(|e| {
                anyhow!("Loading config from \"{}\" failed: {e:?}", config_path)
            })?;

        doc.write_key_pairs(out.clone(), OutputFileExistsBehavior::Skip)
            .map_err(|e| anyhow!("writing key pairs failed: {e:?}"))?;
        doc.write_certificates(out.clone(), OutputFileExistsBehavior::Skip)
            .map_err(|e| anyhow!("writing certificates failed: {e:?}"))?;
        doc.write_certificate_lists(out, OutputFileExistsBehavior::Skip)
            .map_err(|e| anyhow!("writing cert chains failed: {e:?}"))?;

        let start_dir = std::env::current_dir().context("get current dir")?;
        std::env::set_current_dir("test-keys/")
            .context("chdir to test keys")?;

        // generate measurement log used by `cargo test`
        attest_gen_cmd("log", "log.kdl", "log.bin")?;

        // generate the corpus of reference measurements used by `cargo test`
        attest_gen_cmd("corim", "corim-rot.kdl", "corim-rot.cbor")?;
        attest_gen_cmd("corim", "corim-sp.kdl", "corim-sp.cbor")?;

        std::env::set_current_dir(start_dir)
            .context("restore current dir to original")?;
    }

    Ok(())
}
