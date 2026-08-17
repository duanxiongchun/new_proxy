#!/usr/bin/env bash
set -euo pipefail

SCENARIO=nat_capacity
V1_CLIENT_NAT_PORT_START=40000
V1_CLIENT_NAT_PORT_END=40001
source "$(dirname "$0")/lib.sh"

setup_runtime standard

nat_exhausted_before="$(
  read_stats_metric \
    "$CLIENT_STATS" \
    'sum(worker["session_nat_exhausted"] for worker in value["flow_workers"])'
)"
ip netns exec "$SOURCE_NS" timeout 15s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" udp-capacity \
  --address 10.20.1.2 \
  --first-source-port 53001 \
  --second-source-port 53003

wait_for_json "$CLIENT_STATS" \
  "sum(worker[\"session_nat_exhausted\"] for worker in value[\"flow_workers\"]) > $nat_exhausted_before and sum(worker[\"session_count\"] for worker in value[\"flow_workers\"]) == 1 and sum(worker[\"nat_count\"] for worker in value[\"flow_workers\"]) == 1"
wait_for_json "$SERVER_STATS" \
  'sum(worker["session_count"] for worker in value["flow_workers"]) == 1 and sum(worker["nat_count"] for worker in value["flow_workers"]) == 1'
assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client.log"
assert_daemon_running "$SERVER_PID" "$ARTIFACT_DIR/server.log"
