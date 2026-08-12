#!/usr/bin/env bash
set -euo pipefail

SCENARIO=client_return
source "$(dirname "$0")/lib.sh"

setup_runtime standard
exercise_matrix "$SOURCE_NS" client-return
wait_for_json "$CLIENT_STATS" 'value["io_owners"][0]["tx_frames"] > 0 or value["io_owners"][1]["tx_frames"] > 0'
assert_runtime_state 6
