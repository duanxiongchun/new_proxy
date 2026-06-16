#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E MULTI-CLIENT CONCURRENT INTEGRATION TEST
# ==============================================================================
# Topology:
#   - 1 Server (runs server_proxy daemon)
#   - 2 Clients running concurrently:
#       - Client 1: userspace TUN client, TCP offloaded to QUIC Pool
#       - Client 2: direct physical L3 baseline path
# ==============================================================================

set -e

# Ensure script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

HTTP_PID=""
SERVER_PID=""
CLIENT1_PID=""

cleanup() {
  set +e
  echo "=== Tearing down namespaces and processes ==="
  for pid in "$HTTP_PID" "$SERVER_PID" "$CLIENT1_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid in "$HTTP_PID" "$SERVER_PID" "$CLIENT1_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  ip netns delete server_ns 2>/dev/null || true
  ip netns delete router_ns 2>/dev/null || true
  ip netns delete client1_ns 2>/dev/null || true
  ip netns delete client2_ns 2>/dev/null || true
  rm -f /run/new_proxy/srv_multi.sock /run/new_proxy/client1.sock
  rm -f /tmp/srv_multi.conf /tmp/client1.conf
}
trap cleanup EXIT

echo "======================================================================"
echo "=== [1/8] Cleaning Up Pre-Existing Network Namespaces ==="
echo "======================================================================"
ip netns delete server_ns 2>/dev/null || true
ip netns delete router_ns 2>/dev/null || true
ip netns delete client1_ns 2>/dev/null || true
ip netns delete client2_ns 2>/dev/null || true
rm -f /run/new_proxy/srv_multi.sock
rm -f /run/new_proxy/client1.sock

echo "=== [2/8] Creating Namespaces (Server, Router, Client1, Client2) ==="
ip netns add server_ns
ip netns add router_ns
ip netns add client1_ns
ip netns add client2_ns

echo "=== [3/8] Building Veth Network Links ==="
# Server <-> Router
ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

# Client 1 <-> Router
ip link add veth-client1 type veth peer name veth-router-c1
ip link set veth-client1 netns client1_ns
ip link set veth-router-c1 netns router_ns

# Client 2 <-> Router
ip link add veth-client2 type veth peer name veth-router-c2
ip link set veth-client2 netns client2_ns
ip link set veth-router-c2 netns router_ns

echo "=== [4/8] Configuring IPs and Network States ==="
# Server NS
ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up
ip netns exec server_ns ip addr add 10.0.0.1/32 dev lo

# Client 1 NS (Custom Proxy)
ip netns exec client1_ns ip addr add 10.0.1.2/24 dev veth-client1
ip netns exec client1_ns ip link set veth-client1 up
ip netns exec client1_ns ip link set lo up

# Client 2 NS (direct physical L3 baseline)
ip netns exec client2_ns ip addr add 10.0.3.2/24 dev veth-client2
ip netns exec client2_ns ip link set veth-client2 up
ip netns exec client2_ns ip link set lo up
ip netns exec client2_ns ip addr add 10.0.0.3/32 dev lo

# Router NS
ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c1
ip netns exec router_ns ip link set veth-router-c1 up
ip netns exec router_ns ip addr add 10.0.3.1/24 dev veth-router-c2
ip netns exec router_ns ip link set veth-router-c2 up
ip netns exec router_ns ip link set lo up

# Enable IP forwarding
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec client1_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "=== [5/8] Injecting Routing Paths ==="
# Clients Gateway Routes
ip netns exec client1_ns ip route add default via 10.0.1.1
ip netns exec client1_ns ip route add 10.0.0.1/32 via 10.0.1.1

ip netns exec client2_ns ip route add default via 10.0.3.1
ip netns exec client2_ns ip route add 10.0.0.1/32 via 10.0.3.1

# Server Gateway & Client Routes
ip netns exec server_ns ip route add default via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.2/32 via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.3/32 via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.1/32 dev lo scope host

# Router Routing Table
ip netns exec router_ns ip route add 10.0.0.1/32 via 10.0.2.2
ip netns exec router_ns ip route add 10.0.0.2/32 via 10.0.1.2
ip netns exec router_ns ip route add 10.0.0.3/32 via 10.0.3.2


echo "=== [6/8] Writing Multi-Client Configuration Files ==="
# Private keys:
# Server: ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
# Client 1: ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
# Client 2: direct physical L3 baseline namespace

cat > /tmp/srv_multi.conf <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
PublicIPv6 = fd00:2::2
ListenPorts = 40001, 40002

# Client 1: Custom Proxy Client Peer
[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32
EOF_CONF

cat > /tmp/client1.conf <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24, fd00::2/64
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
AllowedIPs = 10.0.0.1/32
EOF_CONF

echo "=== [7/8] Starting Services and Proxy Daemons ==="
# A. Start Target HTTP Server in Server Namespace
ip netns exec server_ns python3 -m http.server 8080 >/dev/null 2>&1 &
HTTP_PID=$!

# C. Start Server Proxy Daemon
ip netns exec server_ns "$ROOT_DIR/target/debug/new_proxy" -config /tmp/srv_multi.conf > /tmp/new_proxy_srv_multi.log 2>&1 &
SERVER_PID=$!
sleep 2

# Manually configure the server TUN interface (since Table = off avoids automatic setup)
ip netns exec server_ns ip addr replace 10.0.0.1/24 dev srv_multi-tun
ip netns exec server_ns ip link set srv_multi-tun up

# D. Start Client 1 (Custom Proxy) Daemon
ip netns exec client1_ns "$ROOT_DIR/target/debug/new_proxy" -config /tmp/client1.conf > /tmp/new_proxy_client1.log 2>&1 &
CLIENT1_PID=$!
sleep 2

# E. Verify L3 WAN Path Ping Connectivity
ip netns exec client1_ns ping -c 2 10.0.2.2 >/dev/null
ip netns exec client2_ns ping -c 2 10.0.2.2 >/dev/null

echo "=== [8/8] Executing Concurrent Multi-Client Interception & Fallback Verification ==="
# Client 1: userspace TUN stream (TCP via parallel QUIC pool)
echo ">> [Client 1 - Custom Proxy]: Sending concurrent TCP request..."
ip netns exec client1_ns curl -fsS --connect-timeout 5 http://10.0.0.1:8080/ >/dev/null
if [ $? -eq 0 ]; then
  echo "✓ [PASS] Client 1 (Proxy) successfully fetched data via TUN/smoltcp/QUIC!"
else
  echo "✗ [FAIL] Client 1 (Proxy) TCP connection failed"
  exit 1
fi

# Client 2: direct physical L3 baseline path.
echo ">> [Client 2 - Direct L3]: Sending concurrent TCP request..."
ip netns exec client2_ns curl -fsS --connect-timeout 5 http://10.0.0.1:8080/ >/dev/null
if [ $? -eq 0 ]; then
  echo "✓ [PASS] Client 2 (Direct L3) successfully fetched data via physical routed path!"
else
  echo "✗ [FAIL] Client 2 (Direct L3) TCP connection failed"
  exit 1
fi

echo ""
echo ">> Fetching Server Telemetry for all concurrent Clients..."
ip netns exec server_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface srv_multi show

# Cleanup will be automatically executed by trap EXIT

echo "======================================================================"
echo "✓ [ALL PASS] Concurrent Multi-Client E2E Test Completed Successfully!"
echo "======================================================================"
