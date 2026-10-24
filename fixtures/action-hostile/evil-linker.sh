#!/bin/sh
# Inert fixture: would be run as a linker if CARGO_TARGET_*_LINKER were honored.
touch "$(dirname "$0")/HOSTILE_LINKER_RAN"
exec cc "$@"
