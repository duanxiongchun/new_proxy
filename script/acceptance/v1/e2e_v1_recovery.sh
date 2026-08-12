#!/usr/bin/env bash
set -euo pipefail

SCENARIO=recovery
source "$(dirname "$0")/lib.sh"

setup_runtime standard
exercise_matrix "$SOURCE_NS" before-reconnect
assert_runtime_state 6
force_reconnect
exercise_matrix "$SOURCE_NS" after-reconnect
assert_target_snat
assert_runtime_state 6
