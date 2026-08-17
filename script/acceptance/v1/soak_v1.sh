#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUN_V1_SOAK:-0}" != "1" ]]; then
  echo "Set RUN_V1_SOAK=1 to run the bounded v1 soak." >&2
  exit 2
fi

SCENARIO=soak
V1_TARGET_LOG_EVERY="${V1_TARGET_LOG_EVERY:-100}"
source "$(dirname "$0")/lib.sh"

SOAK_CYCLES="${V1_SOAK_CYCLES:-10}"
RSS_GROWTH_KB="${V1_SOAK_RSS_GROWTH_KB:-32768}"
RSS_PEAK_GROWTH_KB="${V1_SOAK_RSS_PEAK_GROWTH_KB:-65536}"
SOAK_LOAD_SECONDS="${V1_SOAK_LOAD_SECONDS:-5}"
SOAK_LOAD_CONCURRENCY="${V1_SOAK_LOAD_CONCURRENCY:-8}"

process_rss_kb() {
  awk '/^VmRSS:/ { print $2 }' "/proc/$1/status"
}

process_fd_count() {
  find "/proc/$1/fd" -mindepth 1 -maxdepth 1 -printf . | wc -c
}

sample_process_peaks() {
  local current
  current="$(process_rss_kb "$CLIENT_PID")"
  if (( current > client_rss_peak )); then
    client_rss_peak="$current"
  fi
  current="$(process_rss_kb "$SERVER_PID")"
  if (( current > server_rss_peak )); then
    server_rss_peak="$current"
  fi
  current="$(process_fd_count "$CLIENT_PID")"
  if (( current > client_fds_peak )); then
    client_fds_peak="$current"
  fi
  current="$(process_fd_count "$SERVER_PID")"
  if (( current > server_fds_peak )); then
    server_fds_peak="$current"
  fi
}

assert_rebound_state() {
  local path="$1"
  wait_for_json "$path" \
    "len(value[\"flow_workers\"]) == $FLOW_WORKER_COUNT and all(worker[\"authenticated\"] and all(session[\"quic_flow_id\"] == worker[\"quic_flow_id\"] for session in worker[\"sessions\"]) for worker in value[\"flow_workers\"]) and value[\"reverse_nat_count\"] == sum(worker[\"reverse_nat_count\"] for worker in value[\"flow_workers\"]) and value[\"active_dcid_count\"] >= len(value[\"flow_workers\"])"
}

setup_runtime standard

client_rss_start="$(process_rss_kb "$CLIENT_PID")"
server_rss_start="$(process_rss_kb "$SERVER_PID")"
client_fds_start="$(process_fd_count "$CLIENT_PID")"
server_fds_start="$(process_fd_count "$SERVER_PID")"
client_rss_peak="$client_rss_start"
server_rss_peak="$server_rss_start"
client_fds_peak="$client_fds_start"
server_fds_peak="$server_fds_start"
client_owners="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["io_owners"]))' "$CLIENT_STATS")"
server_owners="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["io_owners"]))' "$SERVER_STATS")"

for cycle in $(seq 1 "$SOAK_CYCLES"); do
  capture_success_baseline
  ip netns exec "$SOURCE_NS" timeout "$((SOAK_LOAD_SECONDS + 10))s" \
    python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" load-client \
    --duration "$SOAK_LOAD_SECONDS" \
    --concurrency "$SOAK_LOAD_CONCURRENCY" \
    --payload-size 1200 >"$ARTIFACT_DIR/load-$cycle.json" &
  load_pid=$!
  while kill -0 "$load_pid" 2>/dev/null; do
    sample_process_peaks
    sleep 0.2
  done
  wait "$load_pid"
  sample_process_peaks
  assert_success_counters_unchanged
  exercise_matrix "$SOURCE_NS" "soak-$cycle"
  assert_runtime_state 6
  force_reconnect
  assert_rebound_state "$CLIENT_STATS"
  assert_rebound_state "$SERVER_STATS"
done

client_rss_end="$(process_rss_kb "$CLIENT_PID")"
server_rss_end="$(process_rss_kb "$SERVER_PID")"
client_fds_end="$(process_fd_count "$CLIENT_PID")"
server_fds_end="$(process_fd_count "$SERVER_PID")"

if (( client_rss_end > client_rss_start + RSS_GROWTH_KB )); then
  echo "client RSS grew from ${client_rss_start} KiB to ${client_rss_end} KiB" >&2
  exit 1
fi
if (( server_rss_end > server_rss_start + RSS_GROWTH_KB )); then
  echo "server RSS grew from ${server_rss_start} KiB to ${server_rss_end} KiB" >&2
  exit 1
fi
if (( client_rss_peak > client_rss_start + RSS_PEAK_GROWTH_KB )); then
  echo "client peak RSS grew from ${client_rss_start} KiB to ${client_rss_peak} KiB" >&2
  exit 1
fi
if (( server_rss_peak > server_rss_start + RSS_PEAK_GROWTH_KB )); then
  echo "server peak RSS grew from ${server_rss_start} KiB to ${server_rss_peak} KiB" >&2
  exit 1
fi
if (( client_fds_end != client_fds_start || server_fds_end != server_fds_start )); then
  echo "file descriptor count drifted: client ${client_fds_start}->${client_fds_end}, server ${server_fds_start}->${server_fds_end}" >&2
  exit 1
fi
if (( client_fds_peak > client_fds_start + SOAK_LOAD_CONCURRENCY || server_fds_peak > server_fds_start + SOAK_LOAD_CONCURRENCY )); then
  echo "file descriptor peak exceeded load concurrency budget: client ${client_fds_start}->${client_fds_peak}, server ${server_fds_start}->${server_fds_peak}" >&2
  exit 1
fi

python3 - "$CLIENT_STATS" "$SERVER_STATS" "$client_owners" "$server_owners" <<'PY'
import json
import sys

client = json.load(open(sys.argv[1], encoding="utf-8"))
server = json.load(open(sys.argv[2], encoding="utf-8"))
if len(client["io_owners"]) != int(sys.argv[3]):
    raise SystemExit("client IO owner count drifted")
if len(server["io_owners"]) != int(sys.argv[4]):
    raise SystemExit("server IO owner count drifted")
PY

printf 'v1 soak passed: cycles=%s client_rss_kb=%s peak=%s end=%s server_rss_kb=%s peak=%s end=%s fd_peak=%s/%s fd_end=%s/%s\n' \
  "$SOAK_CYCLES" \
  "$client_rss_start" "$client_rss_peak" "$client_rss_end" \
  "$server_rss_start" "$server_rss_peak" "$server_rss_end" \
  "$client_fds_peak" "$server_fds_peak" \
  "$client_fds_end" "$server_fds_end"
