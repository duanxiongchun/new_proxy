#!/usr/bin/env bash
# ==============================================================================
# new_proxy E2E TCP MSS CLAMPING AND ZERO FRAGMENTATION TEST SCRIPT
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

ARTIFACT_DIR="/tmp/new_proxy_mss_$(date +%Y%m%d_%H%M%S)"
SERVER_CONF="$ARTIFACT_DIR/e2e_server.conf"
CLIENT_CONF="$ARTIFACT_DIR/e2e_client.conf"
SERVER_LOG="$ARTIFACT_DIR/server.log"
CLIENT_LOG="$ARTIFACT_DIR/client.log"
HTTP_LOG="$ARTIFACT_DIR/http.log"

SERVER_PID=""
CLIENT_PID=""
HTTP_PID=""
TCPDUMP_R_PID=""
TCPDUMP_T_PID=""

cleanup() {
  set +e
  for pid in "$CLIENT_PID" "$SERVER_PID" "$HTTP_PID" "$TCPDUMP_R_PID" "$TCPDUMP_T_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  ip netns delete client_ns 2>/dev/null || true
  ip netns delete router_ns 2>/dev/null || true
  ip netns delete server_ns 2>/dev/null || true
  rm -f /run/new_proxy/server_e2e.sock /run/new_proxy/client_e2e.sock
}
trap cleanup EXIT

echo "=== [1/9] Cleaning up existing namespaces ==="
ip netns delete client_ns 2>/dev/null || true
ip netns delete router_ns 2>/dev/null || true
ip netns delete server_ns 2>/dev/null || true
rm -f /run/new_proxy/server_e2e.sock /run/new_proxy/client_e2e.sock
mkdir -p "$ARTIFACT_DIR"

echo "=== [2/9] Creating Client, Router, and Server Namespaces ==="
ip netns add client_ns
ip netns add router_ns
ip netns add server_ns

echo "=== [3/9] Creating and Setting Up Virtual Ethernet (veth) Links ==="
ip link add veth-client type veth peer name veth-router-c
ip link set veth-client netns client_ns
ip link set veth-router-c netns router_ns

ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

echo "=== [4/9] Configuring IP Addresses and Interface States ==="
ip netns exec client_ns ip addr add 10.0.1.2/24 dev veth-client
ip netns exec client_ns ip link set veth-client up
ip netns exec client_ns ip link set lo up

ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up

ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c
ip netns exec router_ns ip link set veth-router-c up
ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip link set lo up

echo "=== [5/9] Establishing Routes and Enabling IP Forwarding ==="
ip netns exec client_ns ip route add default via 10.0.1.1
ip netns exec server_ns ip route add default via 10.0.2.1
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "=== [6/9] Generating Configuration Files ==="
cat > "$SERVER_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = off

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
MTU = 1200
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32
EOF_CONF

echo "=== [7/9] Starting Gateway Daemons ==="
ip netns exec server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER_CONF" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for e2e_server interface to appear
for _ in $(seq 1 40); do
  if ip netns exec server_ns ip link show dev e2e_server >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

ip netns exec server_ns ip addr add 10.0.0.1/24 dev e2e_server || true
ip netns exec server_ns ip link set e2e_server up
ip netns exec server_ns ip route replace 10.0.0.2/32 dev e2e_server
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "✗ [FAIL] Server daemon exited early"
  cat "$SERVER_LOG"
  exit 1
fi

ip netns exec client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

# Wait for e2e_client interface to appear
for _ in $(seq 1 40); do
  if ip netns exec client_ns ip link show dev e2e_client >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "✗ [FAIL] Client daemon exited early"
  cat "$CLIENT_LOG"
  exit 1
fi

# Ensure tunnels are fully initialized and routing is established
sleep 2

echo "=== [8/9] Starting Blob Server and Capturing Traffic ==="
# Generate a 2MiB blob file
dd if=/dev/zero of="$ARTIFACT_DIR/large_blob.bin" bs=1M count=2 status=none

# Run HTTP server in server namespace serving from the artifact directory
cd "$ARTIFACT_DIR"
ip netns exec server_ns python3 -m http.server 8080 --bind 10.0.0.1 > "$HTTP_LOG" 2>&1 &
HTTP_PID=$!
cd "$ROOT_DIR"

# Wait for HTTP server to start
for _ in $(seq 1 20); do
  if ip netns exec server_ns curl -fsS --connect-timeout 1 "http://10.0.0.1:8080/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

# Start tcpdump on router physical WAN link (veth-router-c) to check for fragmentation
ip netns exec router_ns tcpdump -i veth-router-c -w "$ARTIFACT_DIR/capture_router.pcap" >/dev/null 2>&1 &
TCPDUMP_R_PID=$!

# Start tcpdump on server TUN interface (e2e_server) to check decapsulated SYN MSS value
ip netns exec server_ns tcpdump -i e2e_server -w "$ARTIFACT_DIR/capture_tun_server.pcap" >/dev/null 2>&1 &
TCPDUMP_T_PID=$!

sleep 2

# Download the file from client namespace (routing via client TUN -> QUIC -> server TUN)
echo "Downloading 2MiB file from client namespace..."
if ! ip netns exec client_ns curl -fsS --connect-timeout 5 --max-time 30 -o "$ARTIFACT_DIR/downloaded_blob.bin" "http://10.0.0.1:8080/large_blob.bin"; then
  echo "✗ [FAIL] Large file download failed!"
  exit 1
fi

# Check download integrity
if ! cmp -s "$ARTIFACT_DIR/large_blob.bin" "$ARTIFACT_DIR/downloaded_blob.bin"; then
  echo "✗ [FAIL] Downloaded file hash does not match original!"
  exit 1
fi
echo "✓ [PASS] Large file downloaded and verified successfully."

# Stop packet captures
kill "$TCPDUMP_R_PID" "$TCPDUMP_T_PID" 2>/dev/null || true
wait "$TCPDUMP_R_PID" "$TCPDUMP_T_PID" 2>/dev/null || true
sleep 1

echo "=== [9/9] Verifying PCAP capture data ==="
python3 "$ROOT_DIR/script/acceptance/verify_pcap.py" \
  "$ARTIFACT_DIR/capture_router.pcap" \
  "$ARTIFACT_DIR/capture_tun_server.pcap"
if [ $? -ne 0 ]; then
  echo "✗ [FAIL] PCAP validation checks failed!"
  exit 1
fi

echo "=== Test Cleanup ==="
echo "Artifact directory: $ARTIFACT_DIR"
echo "✓ [SUCCESS] E2E MSS Clamping and Zero Fragmentation integration tests passed cleanly!"
exit 0
