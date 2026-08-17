#!/usr/bin/env bash
set -euo pipefail

SCENARIO=auth_rejection
source "$(dirname "$0")/lib.sh"

require_root
trap cleanup EXIT INT TERM
cleanup
set -e
setup_standard_topology
generate_certificate
write_configs
ip netns exec "$CLIENT_NS" sysctl -qw \
  net.ipv4.ip_local_reserved_ports="$CLIENT_NAT_PORT_START-$CLIENT_NAT_PORT_END"
ip netns exec "$SERVER_NS" sysctl -qw \
  net.ipv4.ip_local_reserved_ports="$SERVER_NAT_PORT_START-$SERVER_NAT_PORT_END"
: >"$ARTIFACT_DIR/target.log"
ip netns exec "$TARGET_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  server --log "$ARTIFACT_DIR/target.log" \
  >"$ARTIFACT_DIR/target-server.log" 2>&1 &
TARGET_PID=$!

sed 's/^SharedKey=.*/SharedKey=0909090909090909090909090909090909090909090909090909090909090909/' \
  "$ARTIFACT_DIR/client.conf" >"$ARTIFACT_DIR/client-bad-key.conf"

SERVER_PID="$(
  start_in_namespace \
    "$SERVER_NS" \
    "$ARTIFACT_DIR/server.conf" \
    "$ARTIFACT_DIR/server.log"
)"
CLIENT_PID="$(start_in_namespace \
  "$CLIENT_NS" \
  "$ARTIFACT_DIR/client-bad-key.conf" \
  "$ARTIFACT_DIR/client-bad-key.log")"
sleep 11
assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client-bad-key.log"
assert_daemon_running "$SERVER_PID" "$ARTIFACT_DIR/server.log"
wait_for_json "$CLIENT_STATS" \
  'all(not worker["authenticated"] for worker in value["flow_workers"]) and value["active_dcid_count"] == 0 and value["reverse_nat_count"] == 0 and sum(worker["session_count"] + worker["nat_count"] for worker in value["flow_workers"]) == 0'
wait_for_json "$SERVER_STATS" \
  'all(not worker["authenticated"] for worker in value["flow_workers"]) and value["active_dcid_count"] == 0 and value["reverse_nat_count"] == 0 and sum(worker["session_count"] + worker["nat_count"] for worker in value["flow_workers"]) == 0'

if ip netns exec "$SOURCE_NS" timeout 3s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" client --tag bad-key; then
  echo "traffic unexpectedly crossed an unauthenticated QUIC connection" >&2
  exit 1
fi
if [[ -s "$ARTIFACT_DIR/target.log" ]]; then
  echo "target unexpectedly observed business traffic for rejected identity" >&2
  cat "$ARTIFACT_DIR/target.log" >&2
  exit 1
fi

kill_daemon_and_wait "$CLIENT_PID" "$ARTIFACT_DIR/client-bad-key.conf"
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID="$(start_in_namespace \
  "$CLIENT_NS" \
  "$ARTIFACT_DIR/client.conf" \
  "$ARTIFACT_DIR/client-recovered.log")"
sleep 0.5
assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client-recovered.log"
wait_for_json "$CLIENT_STATS" \
  'all(worker["authenticated"] for worker in value["flow_workers"])'
wait_for_json "$SERVER_STATS" \
  'all(worker["authenticated"] for worker in value["flow_workers"])'

exercise_matrix "$SOURCE_NS" after-bad-key
assert_target_snat
