#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E DUALSTACK INTEGRATION TEST SCRIPT
# ==============================================================================

# Ensure script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

echo "=== [1/7] Cleaning up existing namespaces ==="
ip netns delete client_ns 2>/dev/null
ip netns delete router_ns 2>/dev/null
ip netns delete server_ns 2>/dev/null
rm -f /run/new_proxy/server.sock

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
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up

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

# Server default gateway routing
ip netns exec server_ns ip route add default via 10.0.2.1
ip netns exec server_ns ip -6 route add default via fd00:2::1

# Enable routing on Router
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec router_ns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

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
# 7.1 Start Server proxy daemon in server_ns
ip netns exec server_ns ./target/debug/new_proxy -config conf/server.conf > /tmp/new_proxy_server_daemon.log 2>&1 &
SERVER_PID=$!
sleep 2

# 7.2 Start Client proxy daemon in client_ns
ip netns exec client_ns ./target/debug/new_proxy -config conf/client.conf > /tmp/new_proxy_client_daemon.log 2>&1 &
CLIENT_PID=$!
sleep 2

# 7.3 Use new-proxy-cli to fetch statistics from UDS inside the namespace
echo "=== Fetching Aggregated Gateway Telemetry via CLI ==="
ip netns exec server_ns ./target/debug/new-proxy-cli --interface server show
if [ $? -ne 0 ]; then
  echo "✗ [FAIL] CLI telemetry fetch failed"
  kill $SERVER_PID $CLIENT_PID 2>/dev/null
  exit 1
fi

# Clean up namespaces and processes
echo "=== Integration Test Complete, Tearing Down Namespaces ==="
kill $SERVER_PID $CLIENT_PID 2>/dev/null
sleep 1
ip netns delete client_ns
ip netns delete router_ns
ip netns delete server_ns
echo "✓ [SUCCESS] E2E Integration tests passed cleanly!"
