#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

ARTIFACT_DIR="${USERSPACE_WG_FALLBACK_ARTIFACT_DIR:-/tmp/new_proxy_userspace_wg_fallback_$(date +%Y%m%d_%H%M%S)}"
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
  ip netns delete uwg_server_ns 2>/dev/null || true
  ip netns delete uwg_router_ns 2>/dev/null || true
  ip netns delete uwg_client_ns 2>/dev/null || true
  rm -f /run/new_proxy/uwg_server.sock /run/new_proxy/uwg_client.sock
}
trap cleanup EXIT

for cmd in ip iptables python3 curl ping; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd"
    exit 1
  fi
done

if [ ! -x "$ROOT_DIR/target/debug/new_proxy" ] || [ ! -x "$ROOT_DIR/target/debug/new-proxy-cli" ]; then
  echo "Missing target/debug binaries. Run: cargo build --bins"
  exit 1
fi

cleanup

mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then
  mknod /dev/net/tun c 10 200
fi
chmod 666 /dev/net/tun

SERVER_CONF="$ARTIFACT_DIR/uwg_server.conf"
CLIENT_CONF="$ARTIFACT_DIR/uwg_client.conf"

cat > "$SERVER_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.40.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = auto

[QUICPool]
PublicIPv4 = 10.41.2.2
ListenPorts = 40001, 40002

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.40.0.2/32
EOF_CONF

cat > "$CLIENT_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.40.0.2/24
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.41.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.40.0.1/32
EOF_CONF

echo "=== [1/6] Creating namespaces ==="
ip netns add uwg_server_ns
ip netns add uwg_router_ns
ip netns add uwg_client_ns

ip link add uwg-s type veth peer name uwg-rs
ip link set uwg-s netns uwg_server_ns
ip link set uwg-rs netns uwg_router_ns

ip link add uwg-c type veth peer name uwg-rc
ip link set uwg-c netns uwg_client_ns
ip link set uwg-rc netns uwg_router_ns

echo "=== [2/6] Configuring physical routes ==="
ip netns exec uwg_server_ns ip addr add 10.41.2.2/24 dev uwg-s
ip netns exec uwg_server_ns ip link set uwg-s up
ip netns exec uwg_server_ns ip link set lo up
ip netns exec uwg_server_ns ip route add default via 10.41.2.1

ip netns exec uwg_client_ns ip addr add 10.41.1.2/24 dev uwg-c
ip netns exec uwg_client_ns ip link set uwg-c up
ip netns exec uwg_client_ns ip link set lo up
ip netns exec uwg_client_ns ip route add default via 10.41.1.1

ip netns exec uwg_router_ns ip addr add 10.41.2.1/24 dev uwg-rs
ip netns exec uwg_router_ns ip link set uwg-rs up
ip netns exec uwg_router_ns ip addr add 10.41.1.1/24 dev uwg-rc
ip netns exec uwg_router_ns ip link set uwg-rc up
ip netns exec uwg_router_ns ip link set lo up
ip netns exec uwg_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec uwg_client_ns ping -c 2 10.41.2.2 >/dev/null

echo "=== [3/6] Starting server daemon with symmetric TUN routing ==="
ip netns exec uwg_server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER_CONF" > "$ARTIFACT_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Server daemon exited early"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi

for _ in $(seq 1 20); do
  if ip netns exec uwg_server_ns ip addr show uwg_server | grep -q "10.40.0.1/24"; then
    break
  fi
  sleep 0.25
done
if ! ip netns exec uwg_server_ns ip addr show uwg_server | grep -q "10.40.0.1/24"; then
  echo "Server TUN address was not configured"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi

ip netns exec uwg_server_ns python3 -m http.server 8080 --bind 10.40.0.1 > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 20); do
  if ip netns exec uwg_server_ns curl -fsS --connect-timeout 1 --max-time 2 http://10.40.0.1:8080/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if ! ip netns exec uwg_server_ns curl -fsS --connect-timeout 1 --max-time 2 http://10.40.0.1:8080/ >/dev/null; then
  echo "HTTP service on server TUN did not become ready"
  cat "$ARTIFACT_DIR/http.log"
  exit 1
fi

echo "=== [4/6] Starting client and verifying initial QUIC path ==="
ip netns exec uwg_client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$ARTIFACT_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "Client daemon exited early"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi
if ! ip netns exec uwg_client_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.40.0.1:8080/ > "$ARTIFACT_DIR/quic_http.txt"; then
  echo "Expected initial QUIC HTTP request to succeed"
  echo "--- client.log ---"
  cat "$ARTIFACT_DIR/client.log"
  echo "--- server.log ---"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi

echo "=== [5/6] Verifying new TCP succeeds through userspace WireGuard fallback ==="
ip netns exec uwg_server_ns iptables -A INPUT -p udp --match multiport --dports 40001,40002 -j DROP
sleep 45
for _ in $(seq 1 20); do
  if ip netns exec uwg_client_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.40.0.1:8080/ > "$ARTIFACT_DIR/fallback_http.txt"; then
    break
  fi
  sleep 1
done
if ! test -s "$ARTIFACT_DIR/fallback_http.txt"; then
  echo "Expected fallback HTTP request to succeed through userspace WireGuard"
  echo "--- client.log ---"
  cat "$ARTIFACT_DIR/client.log"
  echo "--- server.log ---"
  cat "$ARTIFACT_DIR/server.log"
  exit 1
fi

echo "=== [6/6] Verifying telemetry shows WireGuard traffic without QUIC traffic ==="
ip netns exec uwg_server_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface uwg_server show > "$ARTIFACT_DIR/server_show.txt"
cat "$ARTIFACT_DIR/server_show.txt"
if grep -q "wireguard: 0 B received, 0 B sent" "$ARTIFACT_DIR/server_show.txt"; then
  echo "Expected non-zero WireGuard telemetry"
  exit 1
fi
if ! grep -q "quic: inactive" "$ARTIFACT_DIR/server_show.txt"; then
  echo "Expected QUIC telemetry to remain inactive while data ports are blocked"
  exit 1
fi

echo "Artifact directory: $ARTIFACT_DIR"
echo "✓ [SUCCESS] Userspace WireGuard TCP fallback E2E passed"
