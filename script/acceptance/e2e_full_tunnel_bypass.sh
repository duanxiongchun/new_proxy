#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

ARTIFACT_DIR="${FULL_TUNNEL_ARTIFACT_DIR:-/tmp/new_proxy_full_tunnel_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$ARTIFACT_DIR"

SERVER_PID=""
CLIENT_PID=""
HTTP_PID=""

cleanup() {
  set +e
  for pid in "$CLIENT_PID" "$SERVER_PID" "$HTTP_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid in "$CLIENT_PID" "$SERVER_PID" "$HTTP_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  ip netns delete ft_server_ns 2>/dev/null || true
  ip netns delete ft_router_ns 2>/dev/null || true
  ip netns delete ft_client_ns 2>/dev/null || true
  ip netns delete ft_work_ns 2>/dev/null || true
}
trap cleanup EXIT

cleanup
set -e

mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then
  mknod /dev/net/tun c 10 200
fi
chmod 666 /dev/net/tun

cat > "$ARTIFACT_DIR/ft_server.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.30.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.20.2.2
ListenPorts = 40001, 40002

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.30.0.2/32, 10.20.4.0/24
EOF_CONF

cat > "$ARTIFACT_DIR/ft_client.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.30.0.2/24
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.20.2.2:51820
ProxyPort = 51821
AllowedIPs = 0.0.0.0/0
EOF_CONF

echo "=== [1/6] Creating namespaces ==="
ip netns add ft_server_ns
ip netns add ft_router_ns
ip netns add ft_client_ns
ip netns add ft_work_ns

ip link add vf-s type veth peer name vf-rs
ip link set vf-s netns ft_server_ns
ip link set vf-rs netns ft_router_ns

ip link add vf-c type veth peer name vf-rc
ip link set vf-c netns ft_client_ns
ip link set vf-rc netns ft_router_ns

ip link add vf-w type veth peer name vf-cw
ip link set vf-w netns ft_work_ns
ip link set vf-cw netns ft_client_ns

echo "=== [2/6] Configuring physical topology ==="
ip netns exec ft_server_ns ip addr add 10.20.2.2/24 dev vf-s
ip netns exec ft_server_ns ip addr add 10.30.0.1/32 dev lo
ip netns exec ft_server_ns ip link set vf-s up
ip netns exec ft_server_ns ip link set lo up
ip netns exec ft_server_ns ip route add default via 10.20.2.1
ip netns exec ft_server_ns ip route add 10.30.0.1/32 dev lo scope host

ip netns exec ft_client_ns ip addr add 10.20.1.2/24 dev vf-c
ip netns exec ft_client_ns ip addr add 10.20.4.1/24 dev vf-cw
ip netns exec ft_client_ns ip link set vf-c up
ip netns exec ft_client_ns ip link set vf-cw up
ip netns exec ft_client_ns ip link set lo up
ip netns exec ft_client_ns ip route add 10.20.2.2/32 via 10.20.1.1
ip netns exec ft_client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec ft_work_ns ip addr add 10.20.4.2/24 dev vf-w
ip netns exec ft_work_ns ip link set vf-w up
ip netns exec ft_work_ns ip link set lo up
ip netns exec ft_work_ns ip route add default via 10.20.4.1

ip netns exec ft_router_ns ip addr add 10.20.2.1/24 dev vf-rs
ip netns exec ft_router_ns ip addr add 10.20.1.1/24 dev vf-rc
ip netns exec ft_router_ns ip link set vf-rs up
ip netns exec ft_router_ns ip link set vf-rc up
ip netns exec ft_router_ns ip link set lo up
ip netns exec ft_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "=== [3/6] Starting server and client daemons ==="
ip netns exec ft_server_ns python3 -m http.server 8080 --bind 10.30.0.1 > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!
ip netns exec ft_server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/ft_server.conf" > "$ARTIFACT_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
ip netns exec ft_server_ns ip addr add 10.30.0.1/24 dev ft_server
ip netns exec ft_server_ns ip link set ft_server up
ip netns exec ft_server_ns ip route add 10.20.4.0/24 dev ft_server
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Server daemon exited early"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi
ip netns exec ft_client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/ft_client.conf" > "$ARTIFACT_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "Client daemon exited early"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi

echo "=== [4/6] Verifying SO_MARK endpoint bypass survives full-tunnel default ==="
full_tunnel_route="$(ip netns exec ft_client_ns ip route get 198.51.100.10)"
echo "$full_tunnel_route" > "$ARTIFACT_DIR/full_tunnel_route.txt"
echo "$full_tunnel_route"
if ! grep -q "dev ft_client" <<<"$full_tunnel_route"; then
  echo "Expected generic unmarked traffic to follow full-tunnel policy table: $full_tunnel_route"
  exit 1
fi

marked_endpoint_route="$(ip netns exec ft_client_ns ip route get 10.20.2.2 mark 0x6e70)"
echo "$marked_endpoint_route" > "$ARTIFACT_DIR/marked_endpoint_route.txt"
echo "$marked_endpoint_route"
if grep -q "dev ft_client" <<<"$marked_endpoint_route"; then
  echo "Marked endpoint route loops through TUN: $marked_endpoint_route"
  exit 1
fi
if ! grep -q "dev vf-c" <<<"$marked_endpoint_route"; then
  echo "Marked endpoint route does not use physical client link: $marked_endpoint_route"
  exit 1
fi

default_route="$(ip netns exec ft_client_ns ip route show table 28272 default)"
echo "$default_route" > "$ARTIFACT_DIR/default_route.txt"
if ! grep -q "dev ft_client" <<<"$default_route"; then
  echo "Expected full-tunnel policy-table default route via ft_client TUN, got: $default_route"
  exit 1
fi
policy_rule="$(ip netns exec ft_client_ns ip rule show | grep 'not from all fwmark 0x6e70 lookup 28272' || true)"
echo "$policy_rule" > "$ARTIFACT_DIR/policy_rule.txt"
if [ -z "$policy_rule" ]; then
  echo "Expected SO_MARK policy rule for unmarked full-tunnel traffic"
  exit 1
fi
main_suppress_rule="$(ip netns exec ft_client_ns ip rule show | grep 'lookup main suppress_prefixlength 0' || true)"
echo "$main_suppress_rule" > "$ARTIFACT_DIR/main_suppress_rule.txt"
if [ -z "$main_suppress_rule" ]; then
  echo "Expected main-table suppress rule so connected routes bypass full-tunnel default"
  exit 1
fi

echo "=== [5/6] Sending work namespace TCP through full-tunnel userspace QUIC ==="
for _ in $(seq 1 10); do
  ip netns exec ft_work_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.30.0.1:8080/ >/dev/null
done

echo "=== [5b/6] Replacing full-tunnel proxy peer dynamically ==="
replace_output="$(ip netns exec ft_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface ft_client add-peer \
  "${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}" \
  "0.0.0.0/0" \
  "10.20.2.2:51820" \
  "51821")"
echo "$replace_output"
if ! grep -q "Peer added successfully" <<<"$replace_output"; then
  echo "Expected dynamic full-tunnel peer replacement to succeed"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi
sleep 2
full_tunnel_route_after_replace="$(ip netns exec ft_client_ns ip route get 198.51.100.10)"
echo "$full_tunnel_route_after_replace" > "$ARTIFACT_DIR/full_tunnel_route_after_replace.txt"
echo "$full_tunnel_route_after_replace"
if ! grep -q "dev ft_client" <<<"$full_tunnel_route_after_replace"; then
  echo "Expected generic unmarked traffic to follow full-tunnel policy table after dynamic peer replacement: $full_tunnel_route_after_replace"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi
marked_endpoint_route_after_replace="$(ip netns exec ft_client_ns ip route get 10.20.2.2 mark 0x6e70)"
echo "$marked_endpoint_route_after_replace" > "$ARTIFACT_DIR/marked_endpoint_route_after_replace.txt"
echo "$marked_endpoint_route_after_replace"
if grep -q "dev ft_client" <<<"$marked_endpoint_route_after_replace"; then
  echo "Marked endpoint route loops through TUN after dynamic peer replacement: $marked_endpoint_route_after_replace"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi
if ! grep -q "dev vf-c" <<<"$marked_endpoint_route_after_replace"; then
  echo "Marked endpoint route does not use physical client link after dynamic peer replacement: $marked_endpoint_route_after_replace"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi
ip netns exec ft_work_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.30.0.1:8080/ >/dev/null

echo "=== [6/6] Verifying QUIC telemetry is active ==="
for _ in $(seq 1 10); do
  ip netns exec ft_server_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface ft_server show > "$ARTIFACT_DIR/server_show.txt"
  if grep -q "active streams: 0" "$ARTIFACT_DIR/server_show.txt"; then
    break
  fi
  sleep 1
done
cat "$ARTIFACT_DIR/server_show.txt"
if ! grep -q "quic: active" "$ARTIFACT_DIR/server_show.txt"; then
  echo "Expected active QUIC telemetry"
  exit 1
fi
if ! grep -q "active streams: 0" "$ARTIFACT_DIR/server_show.txt"; then
  echo "Expected active streams to drain to 0 after completed curl requests"
  exit 1
fi

echo "Artifact directory: $ARTIFACT_DIR"
echo "✓ [SUCCESS] Full-tunnel endpoint bypass E2E passed"
