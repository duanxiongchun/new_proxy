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

old_client_instance="$(read_stats_metric "$CLIENT_STATS" 'value["instance_id"]')"
old_client_pid="$(read_stats_metric "$CLIENT_STATS" 'value["pid"]')"
kill_daemon_and_wait "$CLIENT_PID" "$ARTIFACT_DIR/client.conf"
wait "$CLIENT_PID" 2>/dev/null || true
cp "$CLIENT_STATS" "$ARTIFACT_DIR/client-killed-stats.json"
sleep 0.3
python3 - "$CLIENT_STATS" "$ARTIFACT_DIR/client-killed-stats.json" "$old_client_instance" "$old_client_pid" <<'PY'
import json
import os
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
killed = json.load(open(sys.argv[2], encoding="utf-8"))
if killed["instance_id"] != sys.argv[3]:
    raise SystemExit("SIGKILL snapshot identity changed before restart")
if killed["pid"] != int(sys.argv[4]):
    raise SystemExit("SIGKILL snapshot PID changed before restart")
if value["instance_id"] != killed["instance_id"]:
    raise SystemExit("SIGKILL snapshot identity changed after process death")
if value["sequence"] != killed["sequence"]:
    raise SystemExit("SIGKILL snapshot sequence advanced after process death")
if value["pid"] != killed["pid"]:
    raise SystemExit("SIGKILL snapshot PID changed after process death")
if os.path.exists(f"/proc/{value['pid']}"):
    raise SystemExit("stale stats PID still exists after SIGKILL")
PY
CLIENT_PID="$(start_in_namespace "$CLIENT_NS" "$ARTIFACT_DIR/client.conf" "$ARTIFACT_DIR/client-restart.log")"
sleep 0.5
assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client-restart.log"
wait_for_json "$CLIENT_STATS" \
  "\"$old_client_instance\" != value[\"instance_id\"] and value[\"pid\"] != $old_client_pid and value[\"sequence\"] > 0 and len(value[\"flow_workers\"]) == 2 and all(worker[\"authenticated\"] for worker in value[\"flow_workers\"])" || {
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

stop_daemon_and_wait "$CLIENT_PID" "$ARTIFACT_DIR/client.conf"
wait "$CLIENT_PID" 2>/dev/null || true
attach_foreign_xdp "$CLIENT_NS" ci0
foreign_program_id="$(xdp_program_id "$CLIENT_NS" ci0)"

expect_startup_failure \
  "$CLIENT_NS" \
  "$ARTIFACT_DIR/client.conf" \
  "$ARTIFACT_DIR/client-foreign.log"
if [[ "$(xdp_program_id "$CLIENT_NS" ci0)" != "$foreign_program_id" ]]; then
  echo "foreign XDP program changed after rejected client startup" >&2
  cat "$ARTIFACT_DIR/client-foreign.log" >&2
  exit 1
fi
grep -Fq 'unowned XDP program' "$ARTIFACT_DIR/client-foreign.log" ||
  grep -Fq 'attachment no longer matches owned program' "$ARTIFACT_DIR/client-foreign.log"
