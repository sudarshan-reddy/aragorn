#!/usr/bin/env bash
set -euo pipefail
cargo fmt -- --check
cargo clippy -- -D warnings
cargo clippy --tests -- -D warnings
cargo test
