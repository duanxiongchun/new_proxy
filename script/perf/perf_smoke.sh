#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"
source "$ROOT_DIR/script/acceptance/wireguard_backend.sh"
new_proxy_select_wireguard_backend
ARTIFACT_DIR="${PERF_SMOKE_ARTIFACT_DIR:-/tmp/new_proxy_perf_smoke_$(date +%Y%m%d_%H%M%S)}"
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
  ip netns delete perf_server_ns 2>/dev/null || true
  ip netns delete perf_router_ns 2>/dev/null || true
  ip netns delete perf_client_ns 2>/dev/null || true
  ip netns delete perf_work_ns 2>/dev/null || true
}
trap cleanup EXIT

cleanup

cat > "$ARTIFACT_DIR/server.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = 40001, 40002, 40003, 40004

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32
EOF_CONF

cat > "$ARTIFACT_DIR/client_perf.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
TProxyPort = 1080
MTU = 1400
Table = off

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32
EOF_CONF

ip netns add perf_server_ns
ip netns add perf_router_ns
ip netns add perf_client_ns
ip netns add perf_work_ns

ip link add vp-s type veth peer name vp-rs
ip link set vp-s netns perf_server_ns
ip link set vp-rs netns perf_router_ns
ip link add vp-c type veth peer name vp-rc
ip link set vp-c netns perf_client_ns
ip link set vp-rc netns perf_router_ns
ip link add vp-w type veth peer name vp-c-w
ip link set vp-w netns perf_work_ns
ip link set vp-c-w netns perf_client_ns

ip netns exec perf_server_ns ip addr add 10.0.2.2/24 dev vp-s
ip netns exec perf_server_ns ip addr add 10.0.0.1/32 dev lo
ip netns exec perf_server_ns ip link set vp-s up
ip netns exec perf_server_ns ip link set lo up
ip netns exec perf_server_ns ip route add default via 10.0.2.1
ip netns exec perf_server_ns ip route add 10.0.0.1/32 dev lo scope host
ip netns exec perf_server_ns ip route add 10.0.0.2/32 via 10.0.2.1

ip netns exec perf_client_ns ip addr add 10.0.1.2/24 dev vp-c
ip netns exec perf_client_ns ip addr add 10.0.4.1/24 dev vp-c-w
ip netns exec perf_client_ns ip addr add 10.0.0.2/32 dev lo
ip netns exec perf_client_ns ip link set vp-c up
ip netns exec perf_client_ns ip link set vp-c-w up
ip netns exec perf_client_ns ip link set lo up
ip netns exec perf_client_ns ip route add default via 10.0.1.1
ip netns exec perf_client_ns ip route add 10.0.0.1/32 via 10.0.1.1
ip netns exec perf_client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec perf_work_ns ip addr add 10.0.4.2/24 dev vp-w
ip netns exec perf_work_ns ip link set vp-w up
ip netns exec perf_work_ns ip link set lo up
ip netns exec perf_work_ns ip route add default via 10.0.4.1

ip netns exec perf_router_ns ip addr add 10.0.2.1/24 dev vp-rs
ip netns exec perf_router_ns ip addr add 10.0.1.1/24 dev vp-rc
ip netns exec perf_router_ns ip link set vp-rs up
ip netns exec perf_router_ns ip link set vp-rc up
ip netns exec perf_router_ns ip link set lo up
ip netns exec perf_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec perf_router_ns ip route add 10.0.0.1/32 via 10.0.2.2
ip netns exec perf_router_ns ip route add 10.0.0.2/32 via 10.0.1.2

ip netns exec perf_client_ns ip rule add fwmark 1 lookup 100
ip netns exec perf_client_ns ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec perf_client_ns iptables -t mangle -A PREROUTING -p tcp -d 10.0.0.1 -j TPROXY --on-port 1080 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1

dd if=/dev/zero of="$ARTIFACT_DIR/blob.bin" bs=1M count=8 status=none
ip netns exec perf_server_ns python3 -m http.server 8080 --bind 10.0.0.1 --directory "$ARTIFACT_DIR" > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!
ip netns exec perf_server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/server.conf" > "$ARTIFACT_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
ip netns exec perf_client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$ARTIFACT_DIR/client_perf.conf" > "$ARTIFACT_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3

python3 - "$ARTIFACT_DIR/perf_smoke.json" <<'PY'
import json
import os
import time
path = os.sys.argv[1]
json.dump({"started_at": int(time.time())}, open(path, "w", encoding="utf-8"))
PY

echo "=== TTFB sample ==="
ip netns exec perf_work_ns python3 - "$ARTIFACT_DIR/perf_smoke.json" <<'PY'
import json
import subprocess
import sys
import time

out = sys.argv[1]
samples = []
for _ in range(20):
    value = subprocess.check_output([
        "curl", "-fsS", "-o", "/dev/null", "-w", "%{time_starttransfer}",
        "--connect-timeout", "5", "--max-time", "10", "http://10.0.0.1:8080/"
    ], text=True)
    samples.append(float(value))
samples.sort()
data = json.load(open(out, encoding="utf-8"))
data["ttfb_seconds"] = {
    "p50": samples[len(samples)//2],
    "p95": samples[int(len(samples)*0.95)-1],
    "max": max(samples),
}
json.dump(data, open(out, "w", encoding="utf-8"), indent=2, sort_keys=True)
print(json.dumps(data["ttfb_seconds"], sort_keys=True))
PY

echo "=== Throughput sample ==="
ip netns exec perf_work_ns python3 - "$ARTIFACT_DIR/perf_smoke.json" <<'PY'
import json
import subprocess
import sys
import time

out = sys.argv[1]
start = time.monotonic()
subprocess.check_call([
    "curl", "-fsS", "-o", "/dev/null", "--connect-timeout", "5", "--max-time", "20",
    "http://10.0.0.1:8080/blob.bin"
])
elapsed = time.monotonic() - start
size = 8 * 1024 * 1024
data = json.load(open(out, encoding="utf-8"))
data["throughput_mib_s"] = size / elapsed / 1024 / 1024
json.dump(data, open(out, "w", encoding="utf-8"), indent=2, sort_keys=True)
print(json.dumps({"throughput_mib_s": data["throughput_mib_s"]}, sort_keys=True))
PY

ip netns exec perf_server_ns "$ROOT_DIR/target/debug/new-proxy-cli" --interface server show > "$ARTIFACT_DIR/server_show.txt"

echo "Artifact directory: $ARTIFACT_DIR"
cat "$ARTIFACT_DIR/perf_smoke.json"
echo
echo "✓ [SUCCESS] Perf smoke passed"
