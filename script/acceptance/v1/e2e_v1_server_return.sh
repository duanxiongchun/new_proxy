#!/usr/bin/env bash
set -euo pipefail

SCENARIO=server_return
source "$(dirname "$0")/lib.sh"

setup_runtime standard
server_return_rx_before="$(read_owner_metric "$SERVER_STATS" intercept rx_frames)"
exercise_matrix "$SOURCE_NS" server-return
assert_target_snat
wait_for_owner_metric_gt "$SERVER_STATS" intercept rx_frames "$server_return_rx_before"
assert_runtime_state 6
