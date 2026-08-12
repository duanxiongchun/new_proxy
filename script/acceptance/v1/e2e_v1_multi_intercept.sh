#!/usr/bin/env bash
set -euo pipefail

SCENARIO=multi_intercept
source "$(dirname "$0")/lib.sh"

setup_runtime multi
exercise_matrix "$SOURCE_NS" intercept-one
exercise_matrix "$SOURCE2_NS" intercept-two
assert_target_snat
assert_runtime_state 12
assert_multiple_intercepts
