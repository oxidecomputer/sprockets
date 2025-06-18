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

# dependencies used by `build.rs` to build test PKI
cargo install --locked --git https://github.com/oxidecomputer/pki-playground

cargo test
