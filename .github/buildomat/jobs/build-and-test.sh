#!/bin/bash
#: name = "cargo test (helios)"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = []

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

# dependencies used by `build.rs` to build test PKI, measurement log, & corpus
cargo install --locked \
    --git https://github.com/oxidecomputer/pki-playground \
    --rev 0c121f9c1e84868e2331173107c2b7ed6f59b13a

cargo install --locked \
    --git https://github.com/oxidecomputer/dice-util \
    --rev 4b408edc1d00f108ddf635415d783e6f12fe9641 \
    attest-mock

cargo test
