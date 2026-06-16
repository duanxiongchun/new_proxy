#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E HYBRID HA & RECONNECT TEST SCRIPT
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

ARTIFACT_DIR="/tmp/new_proxy_hybrid_ha"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"

SERVER_CONF="$ARTIFACT_DIR/server-ha.conf"
CLIENT_CONF="$ARTIFACT_DIR/client-ha.conf"
SERVER_LOG="$ARTIFACT_DIR/server.log"
CLIENT_LOG="$ARTIFACT_DIR/client.log"
MOBILE_PRIV_KEY_FILE="$ARTIFACT_DIR/mobile.priv"
TRAFFIC_LOG="$ARTIFACT_DIR/traffic.log"

SERVER_PID=""
CLIENT_PID=""
TRAFFIC_PID=""
TARGET_SERVER_PID=""

cleanup() {
  set +e
  echo "=== Cleaning up ==="
  
  # Kill traffic generator
  if [ -n "${TRAFFIC_PID:-}" ]; then
    kill "$TRAFFIC_PID" 2>/dev/null || true
  fi

  # Kill target server
  if [ -n "${TARGET_SERVER_PID:-}" ]; then
    kill "$TARGET_SERVER_PID" 2>/dev/null || true
  fi

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
  pkill -f "wireguard-go wg-mobile-ha" || true
  pkill -f "wireguard-go client-ha-wg" || true
  
  # Delete namespaces
  ip netns delete mobile_ns 2>/dev/null || true
  ip netns delete client_ns 2>/dev/null || true
  ip netns delete server_ns 2>/dev/null || true
  ip netns delete router_ns 2>/dev/null || true

  # Clean up leftover socket files
  rm -f /var/run/wireguard/client-ha-wg.sock /run/wireguard/client-ha-wg.sock
  rm -f /var/run/wireguard/wg-mobile-ha.sock /run/wireguard/wg-mobile-ha.sock
}

trap cleanup EXIT

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

echo "=== Starting Target TCP Server ==="
ip netns exec server_ns python3 "$ROOT_DIR/script/acceptance/stability_server.py" --host 0.0.0.0 --tcp-port 8080 --udp-port 8081 > "$ARTIFACT_DIR/stability_server.log" 2>&1 &
TARGET_SERVER_PID=$!
sleep 1

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
ip netns exec mobile_ns wireguard-go wg-mobile-ha
sleep 1
ip netns exec mobile_ns ip addr add 10.0.0.3/24 dev wg-mobile-ha
ip netns exec mobile_ns ip link set wg-mobile-ha up
ip netns exec mobile_ns wg set wg-mobile-ha \
  private-key "$MOBILE_PRIV_KEY_FILE" \
  peer "${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}" \
  endpoint "10.0.1.2:51822" \
  allowed-ips "10.0.0.0/24"

# Add route for the tunnel subnet explicitly to be sure
ip netns exec mobile_ns ip route replace 10.0.0.0/24 dev wg-mobile-ha

# Disable rp_filter and send_redirects specifically on the newly created tunnel interfaces
ip netns exec mobile_ns sysctl -w net.ipv4.conf.wg-mobile-ha.rp_filter=0 >/dev/null || true
ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-wg.rp_filter=0 >/dev/null || true
ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-tun.rp_filter=0 >/dev/null || true
ip netns exec server_ns sysctl -w net.ipv4.conf.server-ha-tun.rp_filter=0 >/dev/null || true

ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-wg.send_redirects=0 >/dev/null || true
ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-tun.send_redirects=0 >/dev/null || true

sleep 1

echo "=== Verifying Initial Connectivity (ping 10.0.0.1) ==="
if ip netns exec mobile_ns ping -c 3 -W 2 10.0.0.1 >/dev/null; then
  echo "✅ Initial ping successful!"
else
  echo "❌ Initial ping failed!" >&2
  exit 1
fi

echo "=== Writing Traffic Generator Python Script ==="
cat << 'EOF_PY' > "$ARTIFACT_DIR/traffic_generator.py"
import socket
import time
import sys
import threading

target_host = "10.0.0.1"
target_port = 8080
log_file = sys.argv[1]

success_count = 0
fail_count = 0
lock = threading.Lock()

def worker():
    global success_count, fail_count
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_host, target_port))
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                response += chunk
            s.close()
            
            if b"new-proxy-stability" in response:
                with lock:
                    success_count += 1
            else:
                with lock:
                    fail_count += 1
        except Exception:
            with lock:
                fail_count += 1
        time.sleep(0.01)

# Start 8 threads for high-throughput
threads = []
for _ in range(8):
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    threads.append(t)

# Main thread writes logs periodically
with open(log_file, "w") as f:
    f.write("Traffic generator started\n")
    f.flush()

while True:
    time.sleep(1.0)
    with lock:
        current_success = success_count
        current_fail = fail_count
    with open(log_file, "a") as f:
        f.write(f"{time.time()}: success={current_success}, fail={current_fail}\n")
        f.flush()
EOF_PY

echo "=== Starting Traffic Generator (Background) ==="
ip netns exec mobile_ns python3 "$ARTIFACT_DIR/traffic_generator.py" "$TRAFFIC_LOG" &
TRAFFIC_PID=$!

sleep 3
echo "--- Traffic Log (Initial Running) ---"
cat "$TRAFFIC_LOG"

# Verify traffic is passing
success_before=$(tail -n 1 "$TRAFFIC_LOG" | sed -n 's/.*success=\([0-9]*\).*/\1/p')
if [ -z "$success_before" ] || [ "$success_before" -eq 0 ]; then
  echo "❌ No traffic succeeded initially!" >&2
  exit 1
fi
echo "✅ Traffic is passing successfully: success count = $success_before"

echo "=== [HA TEST 1/2] Server Restart ==="
echo "Stopping server daemon..."
kill "$SERVER_PID"
sleep 2

# Traffic should now encounter failures or pause
success_during_stop=$(tail -n 1 "$TRAFFIC_LOG" | sed -n 's/.*success=\([0-9]*\).*/\1/p')
fail_during_stop=$(tail -n 1 "$TRAFFIC_LOG" | sed -n 's/.*fail=\([0-9]*\).*/\1/p')
echo "Traffic state during server stop: success=$success_during_stop, fail=$fail_during_stop"

echo "Restarting server daemon..."
ip netns exec server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER_CONF" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for server-ha-tun to appear, then disable rp_filter
for i in {1..20}; do
  if ip netns exec server_ns ip link show dev server-ha-tun >/dev/null 2>&1; then
    ip netns exec server_ns sysctl -w net.ipv4.conf.server-ha-tun.rp_filter=0 >/dev/null || true
    echo "✅ Applied sysctl settings to server-ha-tun interface."
    break
  fi
  sleep 0.2
done

echo "Waiting 35 seconds for client QUIC connection to time out and auto-reconnect..."
sleep 35

# Traffic should have resumed
success_after_restart=$(tail -n 1 "$TRAFFIC_LOG" | sed -n 's/.*success=\([0-9]*\).*/\1/p')
echo "Traffic state after server restart: success=$success_after_restart"

if [ "$success_after_restart" -le "$success_during_stop" ]; then
  echo "❌ Traffic did not resume after server restart!" >&2
  exit 1
fi
echo "✅ Server restart test passed! Traffic resumed."

echo "=== [HA TEST 2/2] Client Restart & Clean Takeover ==="
echo "Stopping client daemon..."
kill "$CLIENT_PID"
ip netns exec client_ns pkill -f "wireguard-go client-ha-wg" || true
rm -f /var/run/wireguard/client-ha-wg.sock /run/wireguard/client-ha-wg.sock
sleep 2

success_during_client_stop=$(tail -n 1 "$TRAFFIC_LOG" | sed -n 's/.*success=\([0-9]*\).*/\1/p')
fail_during_client_stop=$(tail -n 1 "$TRAFFIC_LOG" | sed -n 's/.*fail=\([0-9]*\).*/\1/p')
echo "Traffic state during client stop: success=$success_during_client_stop, fail=$fail_during_client_stop"

echo "Restarting client daemon..."
ip netns exec client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

# Wait for client-ha-wg and client-ha-tun to appear, then disable rp_filter/send_redirects
for i in {1..20}; do
  if ip netns exec client_ns ip link show dev client-ha-wg >/dev/null 2>&1 && \
     ip netns exec client_ns ip link show dev client-ha-tun >/dev/null 2>&1; then
    ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-wg.rp_filter=0 >/dev/null || true
    ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-tun.rp_filter=0 >/dev/null || true
    ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-wg.send_redirects=0 >/dev/null || true
    ip netns exec client_ns sysctl -w net.ipv4.conf.client-ha-tun.send_redirects=0 >/dev/null || true
    echo "✅ Applied sysctl settings to client-ha-wg and client-ha-tun interfaces."
    break
  fi
  sleep 0.2
done

echo "Restarting wg-mobile-ha interface in mobile_ns to force a new handshake..."
ip netns exec mobile_ns pkill -f "wireguard-go wg-mobile-ha" || true
rm -f /var/run/wireguard/wg-mobile-ha.sock /run/wireguard/wg-mobile-ha.sock
ip netns exec mobile_ns wireguard-go wg-mobile-ha
sleep 1
ip netns exec mobile_ns ip addr add 10.0.0.3/24 dev wg-mobile-ha
ip netns exec mobile_ns ip link set wg-mobile-ha up
ip netns exec mobile_ns wg set wg-mobile-ha \
  private-key "$MOBILE_PRIV_KEY_FILE" \
  peer "${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}" \
  endpoint "10.0.1.2:51822" \
  allowed-ips "10.0.0.0/24"
ip netns exec mobile_ns ip route replace 10.0.0.0/24 dev wg-mobile-ha
ip netns exec mobile_ns sysctl -w net.ipv4.conf.wg-mobile-ha.rp_filter=0 >/dev/null || true

echo "Waiting 12 seconds for client restart and clean session takeover..."
sleep 12

success_after_client_restart=$(tail -n 1 "$TRAFFIC_LOG" | sed -n 's/.*success=\([0-9]*\).*/\1/p')
echo "Traffic state after client restart: success=$success_after_client_restart"

if [ "$success_after_client_restart" -le "$success_during_client_stop" ]; then
  echo "❌ Traffic did not resume after client restart!" >&2
  exit 1
fi
echo "✅ Client restart and takeover test passed! Traffic resumed."

cleanup
echo "=== [SUCCESS] E2E Hybrid HA & Reconnect Test Passed ==="
exit 0
