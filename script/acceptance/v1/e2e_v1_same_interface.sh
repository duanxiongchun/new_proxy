#!/usr/bin/env bash
set -euo pipefail

SCENARIO=same_interface
source "$(dirname "$0")/lib.sh"

setup_runtime same
exercise_matrix "$SOURCE_NS" same-interface
assert_target_snat
assert_runtime_state 6
assert_same_interface_owner
