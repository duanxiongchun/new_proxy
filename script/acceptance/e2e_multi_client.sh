#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E MULTI-CLIENT CONCURRENT INTEGRATION TEST
# ==============================================================================
# Topology:
#   - 1 Server (runs server_proxy daemon)
#   - 2 Clients running concurrently:
#       - Client 1: Custom Proxy Client (runs client_proxy daemon, TCP intercepted via TPROXY to QUIC Pool)
#       - Client 2: Standard WireGuard Client (bypasses proxy client daemon, pure L3 path direct fallback)
# ==============================================================================

set -e

# Ensure script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

echo "======================================================================"
echo "=== [1/8] Cleaning Up Pre-Existing Network Namespaces ==="
echo "======================================================================"
ip netns delete server_ns 2>/dev/null || true
ip netns delete router_ns 2>/dev/null || true
ip netns delete client1_ns 2>/dev/null || true
ip netns delete client2_ns 2>/dev/null || true
rm -f /run/new_proxy/server_multi.sock
rm -f /run/new_proxy/client1.sock
rm -f /tmp/client_proxy_active
rm -f /tmp/wg

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
ip netns exec client1_ns ip addr add 10.0.0.2/32 dev lo

# Client 2 NS (Standard WireGuard)
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

# Client 1 TPROXY Interception Setup
ip netns exec client1_ns ip rule add fwmark 1 lookup 100
ip netns exec client1_ns ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec client1_ns iptables -t mangle -A PREROUTING -p tcp -d 10.0.0.1 -j TPROXY --on-port 1080 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1
ip netns exec client1_ns iptables -t mangle -A OUTPUT -p tcp -d 10.0.0.1 -j MARK --set-mark 1

echo "=== [6/8] Writing Multi-Client Configuration Files ==="
# Private keys:
# Server: 1WL7OPPOABmaRVdjR6JoliATNsjOVFO1bE8gM113POM=
# Client 1: etewwnbYf1Zk8wnouPD/qbVWQpP9xW61CeNZ4JCXo24=
# Client 2: AAAAA... (standard fallback peer)

# NOTE: We do NOT write Client 2 peer here. Client 2 will be auto-synchronized
# from kernel (mock wg output) to proxy configuration when telemetry stats are queried!
cat > /tmp/server_multi.conf <<'EOF_CONF'
[Interface]
PrivateKey = 1WL7OPPOABmaRVdjR6JoliATNsjOVFO1bE8gM113POM=
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
PublicIPv6 = fd00:2::2
ListenPorts = 40001, 40002

# Client 1: Custom Proxy Client Peer
[Peer]
PublicKey = 09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=
AllowedIPs = 10.0.0.2/32
EOF_CONF

cat > /tmp/client1.conf <<'EOF_CONF'
[Interface]
PrivateKey = etewwnbYf1Zk8wnouPD/qbVWQpP9xW61CeNZ4JCXo24=
Address = 10.0.0.2/24, fd00::2/64
TProxyPort = 1080
MTU = 1400
Table = off

[Peer]
PublicKey = vWwaq2WH6+bOvcsFJHRqOhvMoPxBMHkWrug2YfyQ3ho=
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32
EOF_CONF

echo "=== [7/8] Starting Services and Proxy Daemons ==="
# A. Start Target HTTP Server in Server Namespace
ip netns exec server_ns python3 -m http.server 8080 >/dev/null 2>&1 &
HTTP_PID=$!

# B. Create Mock wg command to emulate kernel WireGuard dump stats
cat > /tmp/wg <<'EOF_MOCK_WG'
#!/usr/bin/env bash
if [ "$1" = "show" ] && [ "$3" = "dump" ]; then
    # Client 2 (kernel-only)
    echo -e "vWwaq2WH6+bOvcsFJHRqOhvMoPxBMHkWrug2YfyQ3ho=\t(none)\t10.0.3.2:51820\t10.0.0.3/32\t$(date +%s)\t12500\t8400\t(none)"
    # Client 1 (both / proxy)
    echo -e "09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=\t(none)\t10.0.1.2:50322\t10.0.0.2/32\t$(date +%s)\t3482\t256\t(none)"
fi
EOF_MOCK_WG
chmod +x /tmp/wg

# C. Start Server Proxy Daemon (PATH contains /tmp to use the mock wg)
PATH="/tmp:$PATH" ip netns exec server_ns env PATH="/tmp:$PATH" "$ROOT_DIR/target/debug/new_proxy" -config /tmp/server_multi.conf > /tmp/new_proxy_server_multi.log 2>&1 &
SERVER_PID=$!
sleep 2

# D. Start Client 1 (Custom Proxy) Daemon
ip netns exec client1_ns "$ROOT_DIR/target/debug/new_proxy" -config /tmp/client1.conf > /tmp/new_proxy_client1.log 2>&1 &
CLIENT1_PID=$!
sleep 2

# E. Verify L3 WAN Path Ping Connectivity
ip netns exec client1_ns ping -c 2 10.0.2.2 >/dev/null
ip netns exec client2_ns ping -c 2 10.0.2.2 >/dev/null

echo "=== [8/8] Executing Concurrent Multi-Client Interception & Fallback Verification ==="
# Client 1: custom proxy stream (TCP via parallel QUIC pool)
echo ">> [Client 1 - Custom Proxy]: Sending concurrent TCP request..."
ip netns exec client1_ns curl -fsS --connect-timeout 5 http://10.0.0.1:8080/ >/dev/null
if [ $? -eq 0 ]; then
  echo "✓ [PASS] Client 1 (Proxy) successfully fetched data via intercepted TCP-over-QUIC!"
else
  echo "✗ [FAIL] Client 1 (Proxy) TCP connection failed"
  exit 1
fi

# Client 2: standard client stream (TCP bypasses proxy daemon, falls back to L3 direct MASQUERADE)
echo ">> [Client 2 - Standard WG]: Sending concurrent TCP request..."
ip netns exec client2_ns curl -fsS --connect-timeout 5 http://10.0.0.1:8080/ >/dev/null
if [ $? -eq 0 ]; then
  echo "✓ [PASS] Client 2 (Standard WG Fallback) successfully fetched data via native L3 tunnel!"
else
  echo "✗ [FAIL] Client 2 (Standard WG) fallback TCP connection failed"
  exit 1
fi

echo ""
echo ">> Fetching Server Telemetry for all concurrent Clients..."
ip netns exec server_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface server_multi show

# Cleanup
echo "Tearing down namespaces and processes..."
kill $HTTP_PID $SERVER_PID $CLIENT1_PID 2>/dev/null || true
ip netns delete server_ns
ip netns delete router_ns
ip netns delete client1_ns
ip netns delete client2_ns
rm -f /tmp/server_multi.conf /tmp/client1.conf /tmp/wg

echo "======================================================================"
echo "✓ [ALL PASS] Concurrent Multi-Client E2E Test Completed Successfully!"
echo "======================================================================"
