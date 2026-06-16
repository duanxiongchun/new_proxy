#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E HYBRID WIREGUARD ACCESS TEST SCRIPT
# ==============================================================================
set -euo pipefail

# Ensure script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

# Generate keys for mobile client
new_proxy_generate_test_keypair NEW_PROXY_TEST_MOBILE

ARTIFACT_DIR="/tmp/new_proxy_hybrid_wg"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"

SERVER_CONF="$ARTIFACT_DIR/server.conf"
CLIENT_CONF="$ARTIFACT_DIR/client.conf"
SERVER_LOG="$ARTIFACT_DIR/server.log"
CLIENT_LOG="$ARTIFACT_DIR/client.log"
MOBILE_PRIV_KEY_FILE="$ARTIFACT_DIR/mobile.priv"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
  set +e
  echo "=== Cleaning up ==="
  
  # Kill daemons
  for pid in "$CLIENT_PID" "$SERVER_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid in "$CLIENT_PID" "$SERVER_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done

  # Terminate wireguard-go in namespaces
  pkill -f "wireguard-go wg-mobile" || true
  pkill -f "wireguard-go client-wg" || true
  
  # Delete namespaces
  ip netns delete mobile_ns 2>/dev/null || true
  ip netns delete client_ns 2>/dev/null || true
  ip netns delete server_ns 2>/dev/null || true
  ip netns delete router_ns 2>/dev/null || true

  # Clean up leftover socket files
  rm -f /var/run/wireguard/client-wg.sock /run/wireguard/client-wg.sock
  rm -f /var/run/wireguard/wg-mobile.sock /run/wireguard/wg-mobile.sock
}

# Do not run cleanup on exit automatically during debug
# trap cleanup EXIT

echo "${NEW_PROXY_TEST_MOBILE_PRIVATE_KEY}" > "$MOBILE_PRIV_KEY_FILE"

# Clean up namespaces if they exist
cleanup

# Add namespaces
ip netns add mobile_ns
ip netns add client_ns
ip netns add server_ns
ip netns add router_ns

echo "=== Setting up Veth Links ==="
# Mobile <-> Router
ip link add veth-mobile type veth peer name veth-router-m
ip link set veth-mobile netns mobile_ns
ip link set veth-router-m netns router_ns

# Client <-> Router
ip link add veth-client type veth peer name veth-router-c
ip link set veth-client netns client_ns
ip link set veth-router-c netns router_ns

# Server <-> Router
ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

echo "=== Configuring IP Addresses ==="
# Mobile NS
ip netns exec mobile_ns ip addr add 10.0.4.2/24 dev veth-mobile
ip netns exec mobile_ns ip link set veth-mobile up
ip netns exec mobile_ns ip link set lo up
ip netns exec mobile_ns ip route add default via 10.0.4.1
ip netns exec mobile_ns sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip netns exec mobile_ns sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

# Client NS
ip netns exec client_ns ip addr add 10.0.1.2/24 dev veth-client
ip netns exec client_ns ip link set veth-client up
ip netns exec client_ns ip link set lo up
ip netns exec client_ns ip route add default via 10.0.1.1
ip netns exec client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec client_ns sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip netns exec client_ns sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
ip netns exec client_ns sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
ip netns exec client_ns sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null

# Server NS
ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up
ip netns exec server_ns ip route add default via 10.0.2.1
ip netns exec server_ns sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip netns exec server_ns sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

# Router NS
ip netns exec router_ns ip addr add 10.0.4.1/24 dev veth-router-m
ip netns exec router_ns ip link set veth-router-m up
ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c
ip netns exec router_ns ip link set veth-router-c up
ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip link set lo up
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec router_ns sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip netns exec router_ns sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

echo "=== Writing Configuration Files ==="
# Server Configuration (QUIC Server)
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
AllowedIPs = 10.0.0.2/32, 10.0.0.3/32
EOF_CONF

# Client Configuration (Hybrid Gateway client)
cat > "$CLIENT_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
WgListenPort = 51822
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
AllowedIPs = 10.0.0.1/32
Type = quic

[Peer]
PublicKey = ${NEW_PROXY_TEST_MOBILE_PUBLIC_KEY}
AllowedIPs = 10.0.0.3/32
Type = wireguard
EOF_CONF

echo "=== Starting Server Proxy ==="
ip netns exec server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER_CONF" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

echo "=== Starting Client Hybrid Proxy ==="
ip netns exec client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 3

# Check if processes are running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "❌ Server daemon exited early! Logs:" >&2
  cat "$SERVER_LOG"
  exit 1
fi
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "❌ Client daemon exited early! Logs:" >&2
  cat "$CLIENT_LOG"
  exit 1
fi

echo "=== Setting up Standard WireGuard Client in mobile_ns ==="
ip netns exec mobile_ns wireguard-go wg-mobile
sleep 1
ip netns exec mobile_ns ip addr add 10.0.0.3/24 dev wg-mobile
ip netns exec mobile_ns ip link set wg-mobile up
ip netns exec mobile_ns wg set wg-mobile \
  private-key "$MOBILE_PRIV_KEY_FILE" \
  peer "${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}" \
  endpoint "10.0.1.2:51822" \
  allowed-ips "10.0.0.0/24"

# Add route for the tunnel subnet explicitly to be sure
ip netns exec mobile_ns ip route replace 10.0.0.0/24 dev wg-mobile

# Disable rp_filter and send_redirects specifically on the newly created tunnel interfaces
ip netns exec mobile_ns sysctl -w net.ipv4.conf.wg-mobile.rp_filter=0 >/dev/null || true
ip netns exec client_ns sysctl -w net.ipv4.conf.client-wg.rp_filter=0 >/dev/null || true
ip netns exec client_ns sysctl -w net.ipv4.conf.client-tun.rp_filter=0 >/dev/null || true
ip netns exec server_ns sysctl -w net.ipv4.conf.server-tun.rp_filter=0 >/dev/null || true

ip netns exec client_ns sysctl -w net.ipv4.conf.client-wg.send_redirects=0 >/dev/null || true
ip netns exec client_ns sysctl -w net.ipv4.conf.client-tun.send_redirects=0 >/dev/null || true

echo "=== Starting Tcpdump captures ==="
ip netns exec mobile_ns tcpdump -i wg-mobile -n -w "$ARTIFACT_DIR/mobile_wg.pcap" >/dev/null 2>&1 &
TCPDUMP_M_WG_PID=$!
ip netns exec client_ns tcpdump -i client-wg -n -w "$ARTIFACT_DIR/client_wg.pcap" >/dev/null 2>&1 &
TCPDUMP_C_WG_PID=$!
ip netns exec client_ns tcpdump -i client-tun -n -w "$ARTIFACT_DIR/client_tun.pcap" >/dev/null 2>&1 &
TCPDUMP_C_TUN_PID=$!
ip netns exec server_ns tcpdump -i server -n -w "$ARTIFACT_DIR/server_tun.pcap" >/dev/null 2>&1 &
TCPDUMP_S_TUN_PID=$!

sleep 1

echo "=== Verifying Connectivity: ping from mobile_ns to server (10.0.0.1) ==="
# Send 2 pings
ip netns exec mobile_ns ping -c 2 -W 2 10.0.0.1 || true

sleep 1
kill "$TCPDUMP_M_WG_PID" "$TCPDUMP_C_WG_PID" "$TCPDUMP_C_TUN_PID" "$TCPDUMP_S_TUN_PID" 2>/dev/null || true
sleep 1

echo "--- Tcpdump: wg-mobile in mobile_ns ---"
tcpdump -nn -r "$ARTIFACT_DIR/mobile_wg.pcap" || true
echo "--- Tcpdump: client-wg in client_ns ---"
tcpdump -nn -r "$ARTIFACT_DIR/client_wg.pcap" || true
echo "--- Tcpdump: client-tun in client_ns ---"
tcpdump -nn -r "$ARTIFACT_DIR/client_tun.pcap" || true
echo "--- Tcpdump: server in server_ns ---"
tcpdump -nn -r "$ARTIFACT_DIR/server_tun.pcap" || true

# Check if ping failed
if ip netns exec mobile_ns ping -c 2 -W 2 10.0.0.1 >/dev/null; then
  echo "✅ Ping successful!"
else
  echo "❌ Ping failed!" >&2
  # cleanup
  exit 1
fi

echo "=== Verifying Telemetry Stats ==="
# Query stats from client
ip netns exec client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client show > "$ARTIFACT_DIR/client_stats.txt"
cat "$ARTIFACT_DIR/client_stats.txt"

# Verify that the WireGuard source is present in the output
if grep -q "wireguard" "$ARTIFACT_DIR/client_stats.txt"; then
  echo "✅ Found wireguard source in telemetry stats."
else
  echo "❌ Failed to find wireguard source in telemetry stats!" >&2
  cleanup
  exit 1
fi

# Verify rx_bytes / tx_bytes are non-zero for wireguard source.
WG_LINE=$(grep "wireguard" "$ARTIFACT_DIR/client_stats.txt" || true)
echo "WireGuard Stats Line: $WG_LINE"

# We expect L3 Transfer to show non-zero, e.g. not "0 B/0 B"
if echo "$WG_LINE" | grep -q "0 B/0 B"; then
  echo "❌ WireGuard transfer bytes are 0 B/0 B in telemetry!" >&2
  cleanup
  exit 1
fi

echo "✅ Telemetry stats verified: non-zero transfer detected."

cleanup
echo "=== [SUCCESS] E2E Hybrid WireGuard Access Test Passed ==="
exit 0
