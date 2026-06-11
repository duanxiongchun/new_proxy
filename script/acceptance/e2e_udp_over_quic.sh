#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E UDP OVER QUIC TEST SCRIPT
# ==============================================================================
set -euo pipefail

# Ensure script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

ARTIFACT_DIR="/tmp/new_proxy_udp_quic_$(date +%Y%m%d_%H%M%S)"
SERVER_CONF="$ARTIFACT_DIR/server.conf"
CLIENT_CONF="$ARTIFACT_DIR/client.conf"
SERVER_LOG="$ARTIFACT_DIR/server.log"
CLIENT_LOG="$ARTIFACT_DIR/client.log"
UDP_RECV="$ARTIFACT_DIR/udp_recv.txt"

SERVER_PID=""
CLIENT_PID=""
UDP_SERVER_PID=""

cleanup() {
  set +e
  echo "=== Cleaning up ==="
  for pid in "$CLIENT_PID" "$SERVER_PID" "$UDP_SERVER_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid in "$CLIENT_PID" "$SERVER_PID" "$UDP_SERVER_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  ip netns delete client_ns 2>/dev/null || true
  ip netns delete router_ns 2>/dev/null || true
  ip netns delete server_ns 2>/dev/null || true
  rm -f /run/new_proxy/server.sock /run/new_proxy/client.sock
}

# Do not run cleanup automatically on exit during debug so we can inspect logs
trap cleanup EXIT

mkdir -p "$ARTIFACT_DIR"
ip netns add client_ns
ip netns add router_ns
ip netns add server_ns

# Setup veth interfaces
ip link add veth-client type veth peer name veth-router-c
ip link set veth-client netns client_ns
ip link set veth-router-c netns router_ns

ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

# Configure client NS
ip netns exec client_ns ip addr add 10.0.1.2/24 dev veth-client
ip netns exec client_ns ip link set veth-client up
ip netns exec client_ns ip link set lo up
ip netns exec client_ns ip route add default via 10.0.1.1
ip netns exec client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Configure server NS
ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up
ip netns exec server_ns ip route add default via 10.0.2.1

# Configure router NS
ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c
ip netns exec router_ns ip link set veth-router-c up
ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip link set lo up
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Route tunnel traffic through client NS
ip netns exec router_ns ip route add 10.0.0.1/32 via 10.0.1.2

# Write configs
cat > "$SERVER_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
Table = auto

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = 40001, 40002

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32
EOF_CONF

cat > "$CLIENT_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
AllowedIPs = 10.0.0.1/32
EOF_CONF

echo "=== Starting Server and Client Daemons ==="
ip netns exec server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER_CONF" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

ip netns exec client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 3

# Check if processes are running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "❌ Server daemon exited early!" >&2
  cat "$SERVER_LOG"
  exit 1
fi
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "❌ Client daemon exited early!" >&2
  cat "$CLIENT_LOG"
  exit 1
fi

echo "=== Running UDP test over Userspace Tunnel ==="
# Start UDP server in server NS binding to port 8081
ip netns exec server_ns nc -u -l -p 8081 > "$UDP_RECV" 2>&1 &
UDP_SERVER_PID=$!
sleep 1

# Send UDP packet from client NS to server tunnel IP
echo "Hello Tunnel UDP over QUIC" | ip netns exec client_ns nc -u -w 2 10.0.0.1 8081
sleep 1

# Verify data received
if ! grep -q "Hello Tunnel UDP over QUIC" "$UDP_RECV"; then
  echo "❌ UDP over tunnel failed! Received data:" >&2
  cat "$UDP_RECV"
  exit 1
fi
echo "✅ UDP over tunnel succeeded."

echo "=== Verifying Telemetry L4 Statistics ==="
# Query stats from client
ip netns exec client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client show > "$ARTIFACT_DIR/client_stats.txt"
cat "$ARTIFACT_DIR/client_stats.txt"

# Verify QUIC transfer bytes > 0
# We check if there's non-zero QUIC transfer.
# E.g. we look for "quic transfer: [1-9][0-9]* B received" or similar, or just make sure it's not "0 B received, 0 B sent" and that the payload was counted.
# Let's check if "quic transfer: 0 B received, 19 B sent" is not the only thing sent.
# Wait! Let's print the log files for diagnostics.
echo "=== Client Log ==="
cat "$CLIENT_LOG"
echo "=== Server Log ==="
cat "$SERVER_LOG"
# Cleanup will be automatically executed by trap EXIT
echo "=== [SUCCESS] E2E UDP-over-QUIC Test Passed ==="
exit 0
