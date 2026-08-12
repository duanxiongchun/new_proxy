#!/usr/bin/env bash
set -euo pipefail

SCENARIO=server_return
source "$(dirname "$0")/lib.sh"

setup_runtime standard
exercise_matrix "$SOURCE_NS" server-return
assert_target_snat
wait_for_json "$SERVER_STATS" 'value["io_owners"][1]["rx_frames"] > 0 or value["io_owners"][0]["rx_frames"] > 0'
assert_runtime_state 6
