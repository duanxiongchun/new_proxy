#!/usr/bin/env bash
set -euo pipefail

SCENARIO=reliability
V1_FLOW_WORKER_COUNT=2
source "$(dirname "$0")/lib.sh"

setup_runtime standard
exercise_large_packets "$SOURCE_NS"
exercise_idle_connections "$SOURCE_NS"
exercise_matrix "$SOURCE_NS" before-crash
assert_runtime_state 8

kill_daemon_and_wait "$CLIENT_PID" "$ARTIFACT_DIR/client.conf"
wait "$CLIENT_PID" 2>/dev/null || true
rm -f "$CLIENT_STATS"
CLIENT_PID="$(start_in_namespace "$CLIENT_NS" "$ARTIFACT_DIR/client.conf" "$ARTIFACT_DIR/client-restart.log")"
sleep 0.5
assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client-restart.log"
wait_for_json "$CLIENT_STATS" \
  'len(value["flow_workers"]) == 2 and all(worker["authenticated"] for worker in value["flow_workers"])' || {
  cat "$ARTIFACT_DIR/client-restart.log" "$ARTIFACT_DIR/server.log" >&2
  exit 1
}

exercise_matrix "$SOURCE_NS" after-crash
assert_target_snat
assert_runtime_state 6

python3 - "$CLIENT_STATS" "$SERVER_STATS" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    value = json.load(open(path, encoding="utf-8"))
    if len(value["flow_workers"]) != 2:
        raise SystemExit(f"{path}: expected two flow workers")
    if not all(worker["authenticated"] for worker in value["flow_workers"]):
        raise SystemExit(f"{path}: not all flow workers authenticated")
PY
