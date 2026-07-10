// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
#[cfg(feature = "unittest")]
use anyhow::{anyhow, Context};
#[cfg(feature = "unittest")]
use attest_mock::MockData;
#[cfg(feature = "unittest")]
use camino::Utf8PathBuf;
#[cfg(feature = "unittest")]
use pki_playground::{config, OutputFileExistsBehavior};

/// This path is where Oxide specific libraries live on helios systems.
/// This is needed for linking with libipcc
#[cfg(target_os = "illumos")]
static OXIDE_PLATFORM: &str = "/usr/platform/oxide/lib/amd64/";

#[cfg(feature = "unittest")]
fn mock_data<R: MockData>(input: &str, output: &str) -> Result<()>
where
    <R as MockData>::Error: std::error::Error + Send + Sync + 'static,
{
    let mock = R::load(input)?;
    let log = mock.to_bytes()?;
    Ok(std::fs::write(output, &log).with_context(|| {
        format!("write mock measurement log to file: {}", output)
    })?)
}

/// Execute one of the `attest-mock` commands to generate attestation
/// artifacts used in testing.
fn main() -> Result<()> {
    #[cfg(target_os = "illumos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-R{}", OXIDE_PLATFORM);
        println!("cargo:rustc-link-search={}", OXIDE_PLATFORM);
    }

    #[cfg(feature = "unittest")]
    {
        use attest_mock::{MockCorim, MockLog};

        // output directory where we put data generated test inputs
        let outdir = Utf8PathBuf::from(
            std::env::var("OUT_DIR")
                .context("Get OUT_DIR from the environment")?,
        );

        let config_path = "test-keys/config.kdl";
        let doc =
            config::load_and_validate(config_path.as_ref()).map_err(|e| {
                anyhow!("Loading config from \"{}\" failed: {e:?}", config_path)
            })?;

        doc.write_key_pairs(outdir.clone(), OutputFileExistsBehavior::Skip)
            .map_err(|e| anyhow!("writing key pairs failed: {e:?}"))?;
        doc.write_certificates(outdir.clone(), OutputFileExistsBehavior::Skip)
            .map_err(|e| anyhow!("writing certificates failed: {e:?}"))?;
        doc.write_certificate_lists(
            outdir.clone(),
            OutputFileExistsBehavior::Skip,
        )
        .map_err(|e| anyhow!("writing cert chains failed: {e:?}"))?;

        // generate the mock measurement log used by `cargo test`
        let out = outdir.join("log.bin");
        mock_data::<MockLog>("test-keys/log.kdl", out.as_ref())?;

        // generate the mock corpus of reference measurements for the RoT
        let out = outdir.join("corim-rot.cbor");
        mock_data::<MockCorim>("test-keys/corim-rot.kdl", out.as_ref())?;

        // generate the mock corpus of reference measurements for the SP
        let out = outdir.join("corim-sp.cbor");
        mock_data::<MockCorim>("test-keys/corim-sp.kdl", out.as_ref())?;
    }

    Ok(())
}
