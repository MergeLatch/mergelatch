#!/usr/bin/env bash
# Builds the MergeLatch scanner from the Action's own source directory.
#
# MLA_ACTION_ROOT is the directory the Action was loaded into. When consumers
# pin the Action to a full commit SHA, that is a checkout of MergeLatch at that
# SHA, separate from the repository being scanned. The scanned repository is
# never read, built, or consulted here.
set -euo pipefail

: "${MLA_ACTION_ROOT:?MLA_ACTION_ROOT is required}"
: "${MLA_STATE_DIR:?MLA_STATE_DIR is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

# Configuration that could redirect the build or the toolchain must come from
# the Action checkout, not from the surrounding environment.
unset RUSTUP_TOOLCHAIN RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS \
  CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC \
  CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_TARGET CARGO_BUILD_TARGET_DIR \
  CARGO_TARGET_DIR RUSTDOCFLAGS

target_dir="${RUNNER_TEMP}/mergelatch-cargo-target"

# Run from the Action directory so that rustup reads its rust-toolchain.toml
# and cargo reads its configuration, and nothing from the scanned workspace.
cd -- "${MLA_ACTION_ROOT}"

rustup toolchain install --no-self-update
CARGO_TARGET_DIR="${target_dir}" cargo build --locked --release -p mergelatch-cli

rustc --version > "${MLA_STATE_DIR}/rustc-version.txt"
printf '%s\n' "${target_dir}/release/mergelatch" > "${MLA_STATE_DIR}/binary-path.txt"
