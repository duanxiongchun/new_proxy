#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUN_V1_SOAK:-0}" != "1" ]]; then
  echo "Set RUN_V1_SOAK=1 to run the bounded v1 soak." >&2
  exit 2
fi

SCENARIO=soak
source "$(dirname "$0")/lib.sh"

SOAK_CYCLES="${V1_SOAK_CYCLES:-10}"
RSS_GROWTH_KB="${V1_SOAK_RSS_GROWTH_KB:-32768}"

process_rss_kb() {
  awk '/^VmRSS:/ { print $2 }' "/proc/$1/status"
}

process_fd_count() {
  find "/proc/$1/fd" -mindepth 1 -maxdepth 1 -printf . | wc -c
}

assert_idle_state() {
  local path="$1"
  wait_for_json "$path" \
    'value["flow_workers"][0]["authenticated"] and value["flow_workers"][0]["session_count"] == 0 and value["flow_workers"][0]["nat_count"] == 0 and value["flow_workers"][0]["reverse_nat_count"] == 0 and value["reverse_nat_count"] == 0 and value["active_dcid_count"] > 0'
}

setup_runtime standard

client_rss_start="$(process_rss_kb "$CLIENT_PID")"
server_rss_start="$(process_rss_kb "$SERVER_PID")"
client_fds_start="$(process_fd_count "$CLIENT_PID")"
server_fds_start="$(process_fd_count "$SERVER_PID")"
client_owners="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["io_owners"]))' "$CLIENT_STATS")"
server_owners="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["io_owners"]))' "$SERVER_STATS")"

for cycle in $(seq 1 "$SOAK_CYCLES"); do
  exercise_matrix "$SOURCE_NS" "soak-$cycle"
  assert_runtime_state 6
  force_reconnect
  assert_idle_state "$CLIENT_STATS"
  assert_idle_state "$SERVER_STATS"
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
if (( client_fds_end != client_fds_start || server_fds_end != server_fds_start )); then
  echo "file descriptor count drifted: client ${client_fds_start}->${client_fds_end}, server ${server_fds_start}->${server_fds_end}" >&2
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

printf 'v1 soak passed: cycles=%s client_rss_kb=%s->%s server_rss_kb=%s->%s fds=%s/%s\n' \
  "$SOAK_CYCLES" \
  "$client_rss_start" "$client_rss_end" \
  "$server_rss_start" "$server_rss_end" \
  "$client_fds_end" "$server_fds_end"
