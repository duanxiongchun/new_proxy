#!/usr/bin/env bash
set -euo pipefail

SCENARIO=malformed_ingress
source "$(dirname "$0")/lib.sh"

mkdir -p "$ARTIFACT_DIR"
printf 'google.com\n' >"$ARTIFACT_DIR/remote-domains.txt"
CLIENT_DNS_SECTION=$'[DNS]\nListen=10.30.1.53:53\nLocalResolver=10.30.1.2:53\nRemoteResolver=10.20.1.2:53\nRemoteDomainsFile='"$ARTIFACT_DIR"$'/remote-domains.txt\nTransactionCapacity=128\nTimeoutSeconds=5'

require_root
trap cleanup EXIT INT TERM
cleanup
set -e
setup_standard_topology
ip -n "$CLIENT_NS" addr add 10.30.1.53/32 dev ci0
start_runtime

malformed_before="$(read_owner_metric "$CLIENT_STATS" intercept malformed_drops)"
ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  malformed-frame \
  --interface sw0 \
  --source-mac "$SOURCE_MAC" \
  --destination-mac "$CLIENT_INTERCEPT_MAC" \
  --source-ip 10.30.1.2 \
  --destination-ip 10.20.1.2
wait_for_owner_metric_gt \
  "$CLIENT_STATS" intercept malformed_drops "$malformed_before"

unknown_nat_before="$(
  read_owner_metric "$CLIENT_STATS" intercept unknown_nat_tuple_drops
)"
ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  udp-frame \
  --interface sw0 \
  --source-mac "$SOURCE_MAC" \
  --destination-mac "$CLIENT_INTERCEPT_MAC" \
  --source-ip 10.30.1.2 \
  --destination-ip "$CLIENT_NAT_V4" \
  --source-port 49153 \
  --destination-port 9
wait_for_owner_metric_gt \
  "$CLIENT_STATS" intercept unknown_nat_tuple_drops "$unknown_nat_before"

xdp_parser_before="$(
  read_stats_metric "$CLIENT_STATS" 'value["xdp_parser_drops"]'
)"
ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  xdp-parser-drop \
  --kind truncated-ipv4 \
  --interface sw0 \
  --source-mac "$SOURCE_MAC" \
  --destination-mac "$CLIENT_INTERCEPT_MAC" \
  --source-ip 10.30.1.2 \
  --destination-ip 10.20.1.2
ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  xdp-parser-drop \
  --kind ipv4-length \
  --interface sw0 \
  --source-mac "$SOURCE_MAC" \
  --destination-mac "$CLIENT_INTERCEPT_MAC" \
  --source-ip 10.30.1.2 \
  --destination-ip 10.20.1.2
ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  xdp-parser-drop \
  --kind ipv6-extension \
  --interface sw0 \
  --source-mac "$SOURCE_MAC" \
  --destination-mac "$CLIENT_INTERCEPT_MAC" \
  --source-ip 2001:db8:30::2 \
  --destination-ip 2001:db8:20::2
ip netns exec "$SERVER_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  xdp-parser-drop \
  --kind tunnel-udp-length \
  --interface st0 \
  --source-mac "$SERVER_TUNNEL_MAC" \
  --destination-mac "$CLIENT_TUNNEL_MAC" \
  --source-ip 10.10.0.2 \
  --destination-ip 10.10.0.1
wait_for_json "$CLIENT_STATS" \
  "value[\"xdp_parser_drops\"] >= $((xdp_parser_before + 4))"

xdp_dns_fragment_before="$(
  read_stats_metric "$CLIENT_STATS" 'value["xdp_dns_fragment_drops"]'
)"
ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  xdp-parser-drop \
  --kind dns-ipv4-non-initial-fragment \
  --interface sw0 \
  --source-mac "$SOURCE_MAC" \
  --destination-mac "$CLIENT_INTERCEPT_MAC" \
  --source-ip 10.30.1.2 \
  --destination-ip 10.30.1.53
wait_for_json "$CLIENT_STATS" \
  "value[\"xdp_dns_fragment_drops\"] > $xdp_dns_fragment_before"

invalid_quic_before="$(
  read_owner_metric "$CLIENT_STATS" tunnel invalid_quic_drops
)"
ip netns exec "$SERVER_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  xdp-parser-drop \
  --kind invalid-outer-quic \
  --interface st0 \
  --source-mac "$SERVER_TUNNEL_MAC" \
  --destination-mac "$CLIENT_TUNNEL_MAC" \
  --source-ip 10.10.0.2 \
  --destination-ip 10.10.0.1
wait_for_owner_metric_gt \
  "$CLIENT_STATS" tunnel invalid_quic_drops "$invalid_quic_before"

assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client.log"
assert_daemon_running "$SERVER_PID" "$ARTIFACT_DIR/server.log"

exercise_matrix "$SOURCE_NS" after-malformed-frame
assert_target_snat
assert_runtime_state 6
