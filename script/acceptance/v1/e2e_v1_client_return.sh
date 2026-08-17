#!/usr/bin/env bash
set -euo pipefail

SCENARIO=client_return
source "$(dirname "$0")/lib.sh"

setup_runtime standard
client_return_tx_before="$(read_owner_metric "$CLIENT_STATS" intercept tx_frames)"
exercise_matrix "$SOURCE_NS" client-return
wait_for_owner_metric_gt "$CLIENT_STATS" intercept tx_frames "$client_return_tx_before"
assert_runtime_state 6
