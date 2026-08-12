#!/usr/bin/env bash
set -euo pipefail

SCENARIO=client_to_target
source "$(dirname "$0")/lib.sh"

setup_runtime standard
exercise_matrix "$SOURCE_NS" client-to-target
assert_target_snat
assert_runtime_state 6
