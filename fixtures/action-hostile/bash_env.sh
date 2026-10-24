# Inert fixture. Sourced only if a shell honors BASH_ENV; leaves a visible marker.
touch "$(dirname "${BASH_SOURCE[0]}")/HOSTILE_BASH_ENV_RAN"
