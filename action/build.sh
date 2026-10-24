#!/usr/bin/env bash
# Builds the MergeLatch scanner from the Action's own source directory.
#
# Do not run this directly. It is started by `mergelatch_action.py build`, which
# gives it an environment assembled from fixed values (see trusted_environment
# in that file). That, and not a list of variables to unset, is what keeps
# BASH_ENV, CARGO_HOME, linker and compiler overrides, and rustup settings out
# of the build.
#
# MLA_ACTION_ROOT is the directory the Action was loaded into. When consumers
# pin the Action to a full commit SHA, that is a checkout of MergeLatch at that
# SHA, separate from the repository being scanned. The scanned repository is
# never read, built, or consulted here.
set -euo pipefail

if [[ "${MLA_CONTROLLED_ENV:-}" != "1" ]]; then
  echo "::error title=MergeLatch advisory scan::build.sh must be started by the Action helper, which provides a controlled environment" >&2
  exit 1
fi

: "${MLA_ACTION_ROOT:?MLA_ACTION_ROOT is required}"
: "${MLA_STATE_DIR:?MLA_STATE_DIR is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${CARGO_HOME:?CARGO_HOME is required}"

# The tools must come from the trusted Rust installation.
for tool in rustup cargo; do
  found="$(command -v "${tool}" || true)"
  if [[ "${found}" != "${CARGO_HOME}/bin/${tool}" ]]; then
    echo "::error title=MergeLatch advisory scan::${tool} was not found in the trusted Rust installation" >&2
    exit 1
  fi
done

target_dir="${RUNNER_TEMP}/mergelatch-cargo-target"

# Run from the Action directory so that rustup reads its rust-toolchain.toml
# and cargo reads its configuration, and nothing from the scanned workspace.
cd -- "${MLA_ACTION_ROOT}"

rustup toolchain install --no-self-update
CARGO_TARGET_DIR="${target_dir}" cargo build --locked --release -p mergelatch-cli

rustc --version > "${MLA_STATE_DIR}/rustc-version.txt"
printf '%s\n' "${target_dir}/release/mergelatch" > "${MLA_STATE_DIR}/binary-path.txt"
