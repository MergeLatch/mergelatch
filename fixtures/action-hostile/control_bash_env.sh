# Positive control used by the smoke test: proves BASH_ENV is honored by a normal bash step.
touch "$(dirname "${BASH_SOURCE[0]}")/CONTROL_BASH_ENV_RAN"
