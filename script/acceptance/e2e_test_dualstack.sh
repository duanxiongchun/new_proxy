#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E DUALSTACK INTEGRATION TEST SCRIPT
# ==============================================================================

# Ensure script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

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
  ip netns delete client_ns 2>/dev/null || true
  ip netns delete router_ns 2>/dev/null || true
  ip netns delete server_ns 2>/dev/null || true
  rm -f /run/new_proxy/server_e2e.sock /run/new_proxy/client_e2e.sock
  rm -f /tmp/e2e_server.conf /tmp/e2e_client.conf /tmp/new_proxy_wg_dump_mock
}
trap cleanup EXIT

echo "=== [1/7] Cleaning up existing namespaces ==="
ip netns delete client_ns 2>/dev/null
ip netns delete router_ns 2>/dev/null
ip netns delete server_ns 2>/dev/null
rm -f /run/new_proxy/server_e2e.sock /run/new_proxy/client_e2e.sock
rm -f /tmp/e2e_server.conf /tmp/e2e_client.conf /tmp/new_proxy_wg_dump_mock

echo "=== [2/7] Creating Client, Router, and Server Namespaces ==="
ip netns add client_ns
ip netns add router_ns
ip netns add server_ns

echo "=== [3/7] Creating and Setting Up Virtual Ethernet (veth) Links ==="
# Client namespace <-> Router namespace
ip link add veth-client type veth peer name veth-router-c
ip link set veth-client netns client_ns
ip link set veth-router-c netns router_ns

# Server namespace <-> Router namespace
ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

echo "=== [4/7] Configuring IP Addresses and Interface States ==="
# 4.1 Client Namespace
ip netns exec client_ns ip addr add 10.0.1.2/24 dev veth-client
ip netns exec client_ns ip addr add fd00:1::2/64 dev veth-client
ip netns exec client_ns ip link set veth-client up
ip netns exec client_ns ip link set lo up

# 4.2 Server Namespace
ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip addr add fd00:2::2/64 dev veth-server
ip netns exec server_ns ip addr add fd00::1/128 dev lo
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up
ip netns exec server_ns ip route add fd00::1/128 dev lo scope host

# 4.3 Router Namespace
ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c
ip netns exec router_ns ip addr add fd00:1::1/64 dev veth-router-c
ip netns exec router_ns ip link set veth-router-c up

ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip addr add fd00:2::1/64 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip link set lo up

echo "=== [5/7] Establishing Routes and Enabling IP Forwarding ==="
# Client default gateway routing
ip netns exec client_ns ip route add default via 10.0.1.1
ip netns exec client_ns ip -6 route add default via fd00:1::1
ip netns exec client_ns ip -6 route add fd00::1/128 via fd00:1::1
ip netns exec client_ns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

# Server default gateway routing
ip netns exec server_ns ip route add default via 10.0.2.1
ip netns exec server_ns ip -6 route add default via fd00:2::1

# Enable routing on Router
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec router_ns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec router_ns ip -6 route add fd00::1/128 via fd00:1::2

echo "=== [6/7] Verifying WAN Network Connectivity (WAN Ping Tests) ==="
# Test physical connection (WAN path) between Client and Server namespaces
ip netns exec client_ns ping -c 2 10.0.2.2
if [ $? -ne 0 ]; then
  echo "✗ [FAIL] WAN IPv4 path connectivity check failed"
  exit 1
fi

ip netns exec client_ns ping6 -c 2 fd00:2::2
if [ $? -ne 0 ]; then
  echo "✗ [FAIL] WAN IPv6 path connectivity check failed"
  exit 1
fi
echo "✓ [SUCCESS] Dual-stack physical network WAN path verified successfully."

echo "=== [7/7] Starting Gateway Daemons and Verifying IPC CLI ==="
cat > /tmp/e2e_server.conf <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
PublicIPv6 = fd00:2::2
ListenPorts = 40001, 40002

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32, fd00::2/128
EOF_CONF

cat > /tmp/e2e_client.conf <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24, fd00::2/64
TProxyPort = 1080
MTU = 1400
Table = off

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32, fd00::1/128
EOF_CONF

now_ts="$(date +%s)"
cat > /tmp/new_proxy_wg_dump_mock <<EOF_MOCK_WG
${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}	(none)	10.0.1.2:50322	10.0.0.2/32,fd00::2/128	${now_ts}	3482	256	(none)
EOF_MOCK_WG

# 7.1 Start Server proxy daemon in server_ns
ip netns exec server_ns env NEW_PROXY_WG_MOCK_DUMP=/tmp/new_proxy_wg_dump_mock NEW_PROXY_WG_SKIP_KERNEL_SYNC=1 ./target/debug/new_proxy -config /tmp/e2e_server.conf > /tmp/new_proxy_server_daemon.log 2>&1 &
SERVER_PID=$!
sleep 2

# 7.2 Start Client proxy daemon in client_ns
ip netns exec client_ns env NEW_PROXY_WG_MOCK_DUMP=/tmp/new_proxy_wg_dump_mock NEW_PROXY_WG_SKIP_KERNEL_SYNC=1 ./target/debug/new_proxy -config /tmp/e2e_client.conf > /tmp/new_proxy_client_daemon.log 2>&1 &
CLIENT_PID=$!
sleep 2

# 7.3 Verify a real IPv6 TCP request is intercepted by client TPROXY and proxied
# through the authenticated QUIC pool to the server namespace.
ip netns exec client_ns ip -6 rule add fwmark 1 lookup 100
ip netns exec client_ns ip -6 route add local ::/0 dev lo table 100
ip netns exec client_ns ip6tables -t mangle -A PREROUTING \
  -p tcp -d fd00::1/128 \
  -j TPROXY --on-port 1080 --on-ip :: --tproxy-mark 0x1/0x1

ip netns exec server_ns python3 -m http.server 8080 --bind :: >/tmp/e2e_ipv6_http.log 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 20); do
  if ip netns exec server_ns curl -g -fsS --connect-timeout 1 --max-time 2 "http://[fd00::1]:8080/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if ! ip netns exec server_ns curl -g -fsS --connect-timeout 1 --max-time 2 "http://[fd00::1]:8080/" >/dev/null 2>&1; then
  echo "✗ [FAIL] IPv6 HTTP target server did not become ready"
  exit 1
fi

ip netns exec router_ns curl -g -fsS --connect-timeout 5 --max-time 10 "http://[fd00::1]:8080/" >/dev/null
if [ $? -ne 0 ]; then
  echo "✗ [FAIL] IPv6 HTTP over TPROXY/QUIC failed"
  exit 1
fi
echo "✓ [SUCCESS] IPv6 HTTP over TPROXY/QUIC verified successfully."

# 7.4 Use new-proxy-cli to fetch statistics from UDS inside the namespace
echo "=== Fetching Aggregated Gateway Telemetry via CLI ==="
ip netns exec server_ns ./target/debug/new-proxy-cli --interface e2e_server show
if [ $? -ne 0 ]; then
  echo "✗ [FAIL] CLI telemetry fetch failed"
  kill $SERVER_PID $CLIENT_PID 2>/dev/null
  exit 1
fi

# Clean up namespaces and processes
echo "=== Integration Test Complete, Tearing Down Namespaces ==="
echo "✓ [SUCCESS] E2E Integration tests passed cleanly!"
