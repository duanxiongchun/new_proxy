#!/usr/bin/env bash
set -euo pipefail

SCENARIO=ip_policy
source "$(dirname "$0")/lib.sh"

mkdir -p "$ARTIFACT_DIR"
cat >"$ARTIFACT_DIR/direct-cidrs.txt" <<'EOF'
8.8.8.2/32
2606:4700:4700::2/128
EOF
CLIENT_ALLOWED_IPS_PREFIXES="!file:$ARTIFACT_DIR/direct-cidrs.txt"

require_root
trap cleanup EXIT INT TERM
cleanup
set -e
setup_standard_topology

ip netns exec "$CLIENT_NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$CLIENT_NS" sysctl -qw net.ipv6.conf.all.forwarding=1

ip -n "$CLIENT_NS" addr add 2606:4700:10::1/64 dev ct0 nodad
ip -n "$SERVER_NS" addr add 2606:4700:10::2/64 dev st0 nodad
ip -n "$SERVER_NS" addr add 8.8.8.2/32 dev st0
ip -n "$SERVER_NS" addr add 2606:4700:4700::2/128 dev st0 nodad
ip -n "$TARGET_NS" addr add 9.9.9.2/32 dev tg0
ip -n "$TARGET_NS" addr add 2606:4700:4701::2/128 dev tg0 nodad

ip -n "$SOURCE_NS" route add 8.8.8.2/32 via 10.30.1.1 dev sw0
ip -n "$SOURCE_NS" route add 9.9.9.2/32 via 10.30.1.1 dev sw0
ip -n "$SOURCE_NS" -6 route add 2606:4700:4700::2/128 via 2001:db8:30::1 dev sw0
ip -n "$SOURCE_NS" -6 route add 2606:4700:4701::2/128 via 2001:db8:30::1 dev sw0

ip -n "$CLIENT_NS" route add 8.8.8.2/32 dev ct0
ip -n "$CLIENT_NS" -6 route add 2606:4700:4700::2/128 via 2606:4700:10::2 dev ct0
ip -n "$CLIENT_NS" neigh replace 8.8.8.2 lladdr "$SERVER_TUNNEL_MAC" dev ct0
ip -n "$CLIENT_NS" -6 neigh replace 2606:4700:10::2 lladdr "$SERVER_TUNNEL_MAC" dev ct0

ip -n "$SERVER_NS" route add 10.30.1.0/24 via 10.10.0.1 dev st0
ip -n "$SERVER_NS" -6 route add 2001:db8:30::/64 via 2606:4700:10::1 dev st0
ip -n "$SERVER_NS" neigh replace 10.10.0.1 lladdr "$CLIENT_TUNNEL_MAC" dev st0
ip -n "$SERVER_NS" -6 neigh replace 2606:4700:10::1 lladdr "$CLIENT_TUNNEL_MAC" dev st0

ip -n "$SERVER_NS" route add 9.9.9.2/32 dev si0
ip -n "$SERVER_NS" -6 route add 2606:4700:4701::2/128 dev si0
ip -n "$TARGET_NS" route add 10.20.1.1/32 dev tg0
ip -n "$TARGET_NS" -6 route add 2001:db8:20::1/128 dev tg0

start_runtime

ip netns exec "$SOURCE_NS" timeout 5s ping -c 1 8.8.8.2 >/dev/null
ip netns exec "$SOURCE_NS" timeout 5s ping -6 -c 1 2606:4700:4700::2 >/dev/null
wait_for_json "$CLIENT_STATS" \
  'value["reverse_nat_count"] == 0 and all(worker["session_count"] == 0 and worker["nat_count"] == 0 for worker in value["flow_workers"])'
wait_for_json "$SERVER_STATS" \
  'value["reverse_nat_count"] == 0 and all(worker["session_count"] == 0 and worker["nat_count"] == 0 for worker in value["flow_workers"])'

ip netns exec "$SOURCE_NS" timeout 5s ping -c 1 9.9.9.2 >/dev/null
ip netns exec "$SOURCE_NS" timeout 5s ping -6 -c 1 2606:4700:4701::2 >/dev/null
assert_runtime_state 2
