#!/bin/sh
# Inert fixture: would be run as a compiler wrapper if RUSTC_WRAPPER were honored.
touch "$(dirname "$0")/HOSTILE_RUSTC_WRAPPER_RAN"
exec "$@"
