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

cargo test
