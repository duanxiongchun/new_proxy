#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"
ARTIFACT_DIR="${DYNAMIC_PEER_ARTIFACT_DIR:-/tmp/new_proxy_dynamic_peer_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$ARTIFACT_DIR"

SERVER_PID=""
CLIENT_PID=""
HTTP_PID=""
WORK_HTTP_PID=""

cleanup() {
  set +e
  for pid in "$CLIENT_PID" "$SERVER_PID" "$HTTP_PID" "$WORK_HTTP_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid in "$CLIENT_PID" "$SERVER_PID" "$HTTP_PID" "$WORK_HTTP_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  ip netns delete dyn_server_ns 2>/dev/null || true
  ip netns delete dyn_router_ns 2>/dev/null || true
  ip netns delete dyn_client_ns 2>/dev/null || true
  ip netns delete dyn_work_ns 2>/dev/null || true
}
trap cleanup EXIT

cleanup

mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then
  mknod /dev/net/tun c 10 200
fi
chmod 666 /dev/net/tun

cat > "$ARTIFACT_DIR/server.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = 40001

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32
EOF_CONF

cat > "$ARTIFACT_DIR/client_dyn.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
AllowedIPs = 10.255.255.255/32
EOF_CONF

echo "=== [1/7] Creating namespaces ==="
ip netns add dyn_server_ns
ip netns add dyn_router_ns
ip netns add dyn_client_ns
ip netns add dyn_work_ns

ip link add vd-s type veth peer name vd-rs
ip link set vd-s netns dyn_server_ns
ip link set vd-rs netns dyn_router_ns

ip link add vd-c type veth peer name vd-rc
ip link set vd-c netns dyn_client_ns
ip link set vd-rc netns dyn_router_ns

ip link add vd-w type veth peer name vd-c-w
ip link set vd-w netns dyn_work_ns
ip link set vd-c-w netns dyn_client_ns

echo "=== [2/7] Configuring routes ==="
ip netns exec dyn_server_ns ip addr add 10.0.2.2/24 dev vd-s
ip netns exec dyn_server_ns ip addr add 10.0.0.1/32 dev lo
ip netns exec dyn_server_ns ip link set vd-s up
ip netns exec dyn_server_ns ip link set lo up
ip netns exec dyn_server_ns ip route add default via 10.0.2.1
ip netns exec dyn_server_ns ip route add 10.0.0.1/32 dev lo scope host
ip netns exec dyn_server_ns ip route add 10.0.0.2/32 via 10.0.2.1
ip netns exec dyn_server_ns ip route add 10.0.4.0/24 via 10.0.2.1

ip netns exec dyn_client_ns ip addr add 10.0.1.2/24 dev vd-c
ip netns exec dyn_client_ns ip addr add 10.0.4.1/24 dev vd-c-w
ip netns exec dyn_client_ns ip link set vd-c up
ip netns exec dyn_client_ns ip link set vd-c-w up
ip netns exec dyn_client_ns ip link set lo up
ip netns exec dyn_client_ns ip route add default via 10.0.1.1
ip netns exec dyn_client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec dyn_work_ns ip addr add 10.0.4.2/24 dev vd-w
ip netns exec dyn_work_ns ip link set vd-w up
ip netns exec dyn_work_ns ip link set lo up
ip netns exec dyn_work_ns ip route add default via 10.0.4.1

ip netns exec dyn_router_ns ip addr add 10.0.2.1/24 dev vd-rs
ip netns exec dyn_router_ns ip addr add 10.0.1.1/24 dev vd-rc
ip netns exec dyn_router_ns ip link set vd-rs up
ip netns exec dyn_router_ns ip link set vd-rc up
ip netns exec dyn_router_ns ip link set lo up
ip netns exec dyn_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec dyn_router_ns ip route add 10.0.0.1/32 via 10.0.1.2
ip netns exec dyn_router_ns ip route add 10.0.0.2/32 via 10.0.1.2
ip netns exec dyn_router_ns ip route add 10.0.4.0/24 via 10.0.1.2

echo "=== [3/7] Starting daemons ==="
ip netns exec dyn_server_ns python3 -m http.server 8080 --bind 10.0.0.1 > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!
ip netns exec dyn_work_ns python3 -m http.server 8082 --bind 10.0.4.2 > "$ARTIFACT_DIR/work_http.log" 2>&1 &
WORK_HTTP_PID=$!
ip netns exec dyn_server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/server.conf" > "$ARTIFACT_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Server daemon exited early"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi
ip netns exec dyn_client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/client_dyn.conf" > "$ARTIFACT_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 2
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "Client daemon exited early"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi

echo "=== [4/7] Verifying traffic is blocked before dynamic proxy add-peer ==="
if ip netns exec dyn_work_ns curl -fsS --connect-timeout 2 --max-time 4 http://10.0.0.1:8080/ >/dev/null 2>&1; then
  echo "Expected pre-add curl to fail because no QUIC pool exists"
  exit 1
fi

echo "=== [5/7] Dynamically adding proxy peer on client ==="
add_output="$(ip netns exec dyn_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_dyn add-peer \
  "${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}" \
  "10.0.0.1/32" \
  "10.0.2.2:51820" \
  "51821")"
echo "$add_output"
if ! grep -q "Peer added successfully" <<<"$add_output"; then
  echo "Dynamic add-peer failed"
  exit 1
fi
sleep 2
if ! ip netns exec dyn_work_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.0.0.1:8080/ >/dev/null; then
  echo "Expected post-add curl to succeed through dynamic QUIC peer"
  cat "$ARTIFACT_DIR/client.log"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi

echo "=== [6/7] Verifying unrelated physical server-to-work traffic still succeeds ==="
if ! ip netns exec dyn_server_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.0.4.2:8082/ >/dev/null; then
  echo "Expected physical server-to-work traffic to remain reachable"
  cat "$ARTIFACT_DIR/client.log"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi

echo "=== [7/7] Removing proxy peer and verifying interception stops ==="
ip netns exec dyn_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_dyn remove-peer \
  "${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}"
sleep 1
if ip netns exec dyn_work_ns curl -fsS --connect-timeout 2 --max-time 4 http://10.0.0.1:8080/ >/dev/null 2>&1; then
  echo "Expected post-remove curl to fail because QUIC pool was removed"
  exit 1
fi

echo "Artifact directory: $ARTIFACT_DIR"
echo "✓ [SUCCESS] Dynamic client peer E2E passed"
