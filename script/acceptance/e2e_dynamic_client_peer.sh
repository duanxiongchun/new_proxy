#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${DYNAMIC_PEER_ARTIFACT_DIR:-/tmp/new_proxy_dynamic_peer_$(date +%Y%m%d_%H%M%S)}"
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
  ip netns delete dyn_server_ns 2>/dev/null || true
  ip netns delete dyn_router_ns 2>/dev/null || true
  ip netns delete dyn_client_ns 2>/dev/null || true
  ip netns delete dyn_work_ns 2>/dev/null || true
  rm -f /tmp/new_proxy_wg_dump_mock
}
trap cleanup EXIT

cleanup

cat > "$ARTIFACT_DIR/server.conf" <<'EOF_CONF'
[Interface]
PrivateKey = 1WL7OPPOABmaRVdjR6JoliATNsjOVFO1bE8gM113POM=
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = 40001, 40002

[Peer]
PublicKey = 09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=
AllowedIPs = 10.0.0.2/32
EOF_CONF

cat > "$ARTIFACT_DIR/client_dyn.conf" <<'EOF_CONF'
[Interface]
PrivateKey = etewwnbYf1Zk8wnouPD/qbVWQpP9xW61CeNZ4JCXo24=
Address = 10.0.0.2/24
TProxyPort = 1080
MTU = 1400
Table = off

[Peer]
PublicKey = vWwaq2WH6+bOvcsFJHRqOhvMoPxBMHkWrug2YfyQ3ho=
AllowedIPs = 10.0.0.1/32
EOF_CONF

now_ts="$(date +%s)"
cat > /tmp/new_proxy_wg_dump_mock <<EOF_WG
09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=	(none)	10.0.1.2:50322	10.0.0.2/32	${now_ts}	2048	1024	(none)
EOF_WG

echo "=== [1/6] Creating namespaces ==="
ip netns add dyn_server_ns
ip netns add dyn_router_ns
ip netns add dyn_client_ns
ip netns add dyn_work_ns

ip link add vd-s type veth peer name vd-rs
ip link set vd-s netns dyn_server_ns
ip link set vd-rs netns dyn_router_ns

ip link add vd-c type veth peer name vd-rc
ip link set vd-c netns dyn_client_ns
ip link set vd-rc netns dyn_router_ns

ip link add vd-w type veth peer name vd-c-w
ip link set vd-w netns dyn_work_ns
ip link set vd-c-w netns dyn_client_ns

echo "=== [2/6] Configuring routes ==="
ip netns exec dyn_server_ns ip addr add 10.0.2.2/24 dev vd-s
ip netns exec dyn_server_ns ip addr add 10.0.0.1/32 dev lo
ip netns exec dyn_server_ns ip link set vd-s up
ip netns exec dyn_server_ns ip link set lo up
ip netns exec dyn_server_ns ip route add default via 10.0.2.1
ip netns exec dyn_server_ns ip route add 10.0.0.1/32 dev lo scope host
ip netns exec dyn_server_ns ip route add 10.0.0.2/32 via 10.0.2.1

ip netns exec dyn_client_ns ip addr add 10.0.1.2/24 dev vd-c
ip netns exec dyn_client_ns ip addr add 10.0.4.1/24 dev vd-c-w
ip netns exec dyn_client_ns ip addr add 10.0.0.2/32 dev lo
ip netns exec dyn_client_ns ip link set vd-c up
ip netns exec dyn_client_ns ip link set vd-c-w up
ip netns exec dyn_client_ns ip link set lo up
ip netns exec dyn_client_ns ip route add default via 10.0.1.1
ip netns exec dyn_client_ns ip route add 10.0.0.1/32 via 10.0.1.1
ip netns exec dyn_client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec dyn_work_ns ip addr add 10.0.4.2/24 dev vd-w
ip netns exec dyn_work_ns ip link set vd-w up
ip netns exec dyn_work_ns ip link set lo up
ip netns exec dyn_work_ns ip route add default via 10.0.4.1

ip netns exec dyn_router_ns ip addr add 10.0.2.1/24 dev vd-rs
ip netns exec dyn_router_ns ip addr add 10.0.1.1/24 dev vd-rc
ip netns exec dyn_router_ns ip link set vd-rs up
ip netns exec dyn_router_ns ip link set vd-rc up
ip netns exec dyn_router_ns ip link set lo up
ip netns exec dyn_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec dyn_router_ns ip route add 10.0.0.1/32 via 10.0.2.2
ip netns exec dyn_router_ns ip route add 10.0.0.2/32 via 10.0.1.2

ip netns exec dyn_client_ns ip rule add fwmark 1 lookup 100
ip netns exec dyn_client_ns ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec dyn_client_ns iptables -t mangle -A PREROUTING -p tcp -d 10.0.0.1 -j TPROXY --on-port 1080 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1

echo "=== [3/6] Starting daemons ==="
ip netns exec dyn_server_ns python3 -m http.server 8080 --bind 10.0.0.1 > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!
ip netns exec dyn_server_ns env NEW_PROXY_WG_MOCK_DUMP=/tmp/new_proxy_wg_dump_mock NEW_PROXY_WG_SKIP_KERNEL_SYNC=1 "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/server.conf" > "$ARTIFACT_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
ip netns exec dyn_client_ns env NEW_PROXY_WG_MOCK_DUMP=/tmp/new_proxy_wg_dump_mock NEW_PROXY_WG_SKIP_KERNEL_SYNC=1 "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/client_dyn.conf" > "$ARTIFACT_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 2

echo "=== [4/6] Verifying traffic is blocked before dynamic proxy add-peer ==="
if ip netns exec dyn_work_ns curl -fsS --connect-timeout 2 --max-time 4 http://10.0.0.1:8080/ >/dev/null 2>&1; then
  echo "Expected pre-add curl to fail because no QUIC pool exists"
  exit 1
fi

echo "=== [5/6] Dynamically adding proxy peer on client ==="
add_output="$(ip netns exec dyn_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_dyn add-peer \
  "vWwaq2WH6+bOvcsFJHRqOhvMoPxBMHkWrug2YfyQ3ho=" \
  "10.0.0.1/32" \
  "10.0.2.2:51820" \
  "51821")"
echo "$add_output"
if ! grep -q "Peer added successfully" <<<"$add_output"; then
  echo "Dynamic add-peer failed"
  exit 1
fi
sleep 2
ip netns exec dyn_work_ns curl -fsS --connect-timeout 5 --max-time 10 http://10.0.0.1:8080/ >/dev/null

echo "=== [6/6] Removing proxy peer and verifying interception stops ==="
ip netns exec dyn_client_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface client_dyn remove-peer \
  "vWwaq2WH6+bOvcsFJHRqOhvMoPxBMHkWrug2YfyQ3ho="
sleep 1
if ip netns exec dyn_work_ns curl -fsS --connect-timeout 2 --max-time 4 http://10.0.0.1:8080/ >/dev/null 2>&1; then
  echo "Expected post-remove curl to fail because QUIC pool was removed"
  exit 1
fi

echo "Artifact directory: $ARTIFACT_DIR"
echo "✓ [SUCCESS] Dynamic client peer E2E passed"
