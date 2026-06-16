#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

ARTIFACT_DIR="${CLIENT_TOPOLOGY_ARTIFACT_DIR:-/tmp/new_proxy_client_topology_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$ARTIFACT_DIR"

SERVER1_PID=""
SERVER2_PID=""
CLIENT_PID=""
HTTP_PID=""

cleanup() {
  set +e
  for pid in "$CLIENT_PID" "$SERVER1_PID" "$SERVER2_PID" "$HTTP_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid in "$CLIENT_PID" "$SERVER1_PID" "$SERVER2_PID" "$HTTP_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  ip netns delete topo_server1_ns 2>/dev/null || true
  ip netns delete topo_server2_ns 2>/dev/null || true
  ip netns delete topo_router_ns 2>/dev/null || true
  ip netns delete topo_client_ns 2>/dev/null || true
  rm -f /run/new_proxy/srv1_topo.sock /run/new_proxy/srv2_topo.sock /run/new_proxy/client_topo.sock
}
trap cleanup EXIT

for cmd in ip python3 curl wg; do
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

SERVER1_CONF="$ARTIFACT_DIR/srv1_topo.conf"
SERVER2_CONF="$ARTIFACT_DIR/srv2_topo.conf"
CLIENT_CONF="$ARTIFACT_DIR/client_topo.conf"

cat > "$SERVER1_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.70.0.1/24
ListenPort = 51920
Table = off

[QUICPool]
PublicIPv4 = 10.60.2.2
ListenPorts = 40101, 40102, 40103, 40104

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.70.0.2/32
EOF_CONF

cat > "$SERVER2_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT2_PRIVATE_KEY}
Address = 10.70.0.3/24
ListenPort = 52920
Table = off

[QUICPool]
PublicIPv4 = 10.60.3.2
ListenPorts = 40201

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.70.0.2/32
EOF_CONF

cat > "$CLIENT_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.70.0.2/24
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.60.2.2:51920
AllowedIPs = 10.70.0.1/32
EOF_CONF

echo "=== [1/6] Creating topology namespaces ==="
ip netns add topo_server1_ns
ip netns add topo_server2_ns
ip netns add topo_router_ns
ip netns add topo_client_ns

ip link add topo-s1 type veth peer name topo-rs1
ip link set topo-s1 netns topo_server1_ns
ip link set topo-rs1 netns topo_router_ns

ip link add topo-s2 type veth peer name topo-rs2
ip link set topo-s2 netns topo_server2_ns
ip link set topo-rs2 netns topo_router_ns

ip link add topo-c type veth peer name topo-rc
ip link set topo-c netns topo_client_ns
ip link set topo-rc netns topo_router_ns

echo "=== [2/6] Configuring physical routes ==="
ip netns exec topo_server1_ns ip addr add 10.60.2.2/24 dev topo-s1
ip netns exec topo_server1_ns ip addr add 10.70.0.1/32 dev lo
ip netns exec topo_server1_ns ip link set topo-s1 up
ip netns exec topo_server1_ns ip link set lo up
ip netns exec topo_server1_ns ip route add default via 10.60.2.1
ip netns exec topo_server1_ns ip route add 10.70.0.1/32 dev lo scope host
ip netns exec topo_server1_ns ip route add 10.70.0.2/32 via 10.60.2.1

ip netns exec topo_server2_ns ip addr add 10.60.3.2/24 dev topo-s2
ip netns exec topo_server2_ns ip addr add 10.70.0.3/32 dev lo
ip netns exec topo_server2_ns ip link set topo-s2 up
ip netns exec topo_server2_ns ip link set lo up
ip netns exec topo_server2_ns ip route add default via 10.60.3.1
ip netns exec topo_server2_ns ip route add 10.70.0.3/32 dev lo scope host
ip netns exec topo_server2_ns ip route add 10.70.0.2/32 via 10.60.3.1

ip netns exec topo_client_ns ip addr add 10.60.1.2/24 dev topo-c
ip netns exec topo_client_ns ip link set topo-c up
ip netns exec topo_client_ns ip link set lo up
ip netns exec topo_client_ns ip route add default via 10.60.1.1

ip netns exec topo_router_ns ip addr add 10.60.2.1/24 dev topo-rs1
ip netns exec topo_router_ns ip addr add 10.60.3.1/24 dev topo-rs2
ip netns exec topo_router_ns ip addr add 10.60.1.1/24 dev topo-rc
ip netns exec topo_router_ns ip link set topo-rs1 up
ip netns exec topo_router_ns ip link set topo-rs2 up
ip netns exec topo_router_ns ip link set topo-rc up
ip netns exec topo_router_ns ip link set lo up
ip netns exec topo_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec topo_router_ns ip route add 10.70.0.1/32 via 10.60.1.2
ip netns exec topo_router_ns ip route add 10.70.0.2/32 via 10.60.1.2
ip netns exec topo_router_ns ip route add 10.70.0.3/32 via 10.60.1.2

echo "=== [3/6] Starting servers ==="
ip netns exec topo_server1_ns python3 -m http.server 8080 --bind 10.70.0.1 > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!
ip netns exec topo_server1_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER1_CONF" > "$ARTIFACT_DIR/server1.log" 2>&1 &
SERVER1_PID=$!
ip netns exec topo_server2_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER2_CONF" > "$ARTIFACT_DIR/server2.log" 2>&1 &
SERVER2_PID=$!
sleep 2
ip netns exec topo_server1_ns ip addr add 10.70.0.1/24 dev srv1_topo-tun || true
ip netns exec topo_server1_ns ip link set srv1_topo-tun up
ip netns exec topo_server1_ns ip route replace 10.70.0.2/32 dev srv1_topo-tun
for pid in "$SERVER1_PID" "$SERVER2_PID"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "A server daemon exited early"
    cat "$ARTIFACT_DIR/server1.log"
    cat "$ARTIFACT_DIR/server2.log"
    exit 1
  fi
done

echo "=== [4/6] Starting client and verifying fixed worker topology ==="
ip netns exec topo_client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$ARTIFACT_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "Client daemon exited early"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi

ip netns exec topo_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_topo dump > "$ARTIFACT_DIR/client_dump.txt"
cat "$ARTIFACT_DIR/client_dump.txt"
worker_count="$(grep -c '^worker:' "$ARTIFACT_DIR/client_dump.txt")"
if [ "$worker_count" -ne 4 ]; then
  echo "Expected client worker count to follow negotiated 4 QUIC data ports, got $worker_count"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi
if ! grep -q "data_ports 4, using 4" "$ARTIFACT_DIR/client.log"; then
  echo "Client log did not record the negotiated 4-port topology"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi

if ! ip netns exec topo_client_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.70.0.1:8080/ >/dev/null; then
  echo "Expected initial 4-port QUIC peer traffic to succeed"
  cat "$ARTIFACT_DIR/client.log"
  cat "$ARTIFACT_DIR/server1.log"
  exit 1
fi

echo "=== [5/6] Rejecting dynamic proxy peer with mismatched fixed baseline ==="
if ! ip netns exec topo_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_topo remove-peer \
  "${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}"; then
  echo "Failed to remove original 4-port proxy peer"
  exit 1
fi
sleep 1

set +e
add_output="$(ip netns exec topo_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_topo add-peer \
  "${NEW_PROXY_TEST_CLIENT2_PUBLIC_KEY}" \
  "10.70.0.3/32" \
  "10.60.3.2:52920" \
  "52920" 2>&1)"
add_status=$?
set -e
echo "$add_output"
if [ "$add_status" -eq 0 ]; then
  echo "Expected mismatched 1-port peer add to fail"
  exit 1
fi
if ! grep -q "established baseline uses 4" <<<"$add_output"; then
  echo "Expected add-peer failure to report the fixed 4-port baseline"
  exit 1
fi

ip netns exec topo_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_topo dump > "$ARTIFACT_DIR/client_dump_after_reject.txt"
worker_count_after="$(grep -c '^worker:' "$ARTIFACT_DIR/client_dump_after_reject.txt")"
if [ "$worker_count_after" -ne 4 ]; then
  echo "Rejected peer changed worker topology from 4 to $worker_count_after"
  cat "$ARTIFACT_DIR/client_dump_after_reject.txt"
  exit 1
fi

echo "=== [6/6] Re-adding original peer and verifying traffic still works ==="
readd_output="$(ip netns exec topo_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_topo add-peer \
  "${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}" \
  "10.70.0.1/32" \
  "10.60.2.2:51920" \
  "51920")"
echo "$readd_output"
if ! grep -q "Peer added successfully" <<<"$readd_output"; then
  echo "Expected original 4-port peer to be accepted after rejected mismatch"
  cat "$ARTIFACT_DIR/client.log"
  exit 1
fi
sleep 2
if ! ip netns exec topo_client_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.70.0.1:8080/ >/dev/null; then
  echo "Expected original 4-port peer traffic to work after re-add"
  cat "$ARTIFACT_DIR/client.log"
  cat "$ARTIFACT_DIR/server1.log"
  exit 1
fi

echo "Artifact directory: $ARTIFACT_DIR"
echo "✓ [SUCCESS] Client topology gate E2E passed"
