#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - HYBRID TUNNEL PERFORMANCE COMPARISON TEST
# ==============================================================================
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"
ARTIFACT_DIR="/tmp/new_proxy_perf_compare"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"

if [ ! -x "$ROOT_DIR/target/release/new_proxy" ]; then
  echo "Missing release binary. Run: cargo build --release --bins" >&2
  exit 1
fi

# Size of file to download in Mebibytes (MiB)
BLOB_MIB=50
dd if=/dev/zero of="$ARTIFACT_DIR/blob.bin" bs=1M count=$BLOB_MIB status=none

SERVER_WG_PRIV_B64="$NEW_PROXY_TEST_SERVER_PRIVATE_KEY"
SERVER_WG_PUB_B64="$NEW_PROXY_TEST_SERVER_PUBLIC_KEY"
CLIENT_WG_PRIV_B64="$NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY"
CLIENT_WG_PUB_B64="$NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY"

SERVER_PID=""
CLIENT_PID=""
HTTP_PID=""

cleanup() {
  set +e
  echo "=== Cleaning up ==="
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
  # Terminate wireguard-go in namespaces
  pkill -f "wireguard-go wg-server" || true
  pkill -f "wireguard-go wg-client" || true

  ip netns delete perf_server_ns 2>/dev/null || true
  ip netns delete perf_router_ns 2>/dev/null || true
  ip netns delete perf_client_ns 2>/dev/null || true
  ip netns delete perf_work_ns 2>/dev/null || true
  rm -f /run/new_proxy/client.sock /run/new_proxy/server.sock
  rm -f /var/run/wireguard/wg-server.sock /run/wireguard/wg-server.sock
  rm -f /var/run/wireguard/wg-client.sock /run/wireguard/wg-client.sock
}
trap cleanup EXIT

setup_common_namespaces() {
  cleanup
  
  mkdir -p /dev/net
  if [ ! -e /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
  fi
  chmod 666 /dev/net/tun

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

  # Server NS Physical Link
  ip netns exec perf_server_ns ip addr add 10.0.2.2/24 dev vp-s
  ip netns exec perf_server_ns ip link set vp-s up
  ip netns exec perf_server_ns ip link set lo up
  ip netns exec perf_server_ns ip route add default via 10.0.2.1

  # Client NS Physical Links
  ip netns exec perf_client_ns ip addr add 10.0.1.2/24 dev vp-c
  ip netns exec perf_client_ns ip addr add 10.0.4.1/24 dev vp-c-w
  ip netns exec perf_client_ns ip link set vp-c up
  ip netns exec perf_client_ns ip link set vp-c-w up
  ip netns exec perf_client_ns ip link set lo up
  ip netns exec perf_client_ns ip route add default via 10.0.1.1
  ip netns exec perf_client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # Work NS Physical Link
  ip netns exec perf_work_ns ip addr add 10.0.4.2/24 dev vp-w
  ip netns exec perf_work_ns ip link set vp-w up
  ip netns exec perf_work_ns ip link set lo up
  ip netns exec perf_work_ns ip route add default via 10.0.4.1

  # Router NS Physical Links & Forwarding
  ip netns exec perf_router_ns ip addr add 10.0.2.1/24 dev vp-rs
  ip netns exec perf_router_ns ip addr add 10.0.1.1/24 dev vp-rc
  ip netns exec perf_router_ns ip link set vp-rs up
  ip netns exec perf_router_ns ip link set vp-rc up
  ip netns exec perf_router_ns ip link set lo up
  ip netns exec perf_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec perf_router_ns ip route add 10.0.0.1/32 via 10.0.2.2
  ip netns exec perf_router_ns ip route add 10.0.0.2/32 via 10.0.1.2
}

start_in_memory_http_server() {
  ip netns exec perf_server_ns python3 - "$BLOB_MIB" <<'PY' > "$ARTIFACT_DIR/http.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
import sys

class ForkingHTTPServer(socketserver.ForkingMixIn, HTTPServer):
    pass

blob_mib = int(sys.argv[1])
blob_data = b'\x00' * (blob_mib * 1024 * 1024)

class InMemoryHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, format, *args):
        pass
    def do_GET(self):
        if self.path == '/blob.bin' or self.path == '/':
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob_data)))
            self.end_headers()
            chunk_size = 128 * 1024
            for i in range(0, len(blob_data), chunk_size):
                self.wfile.write(blob_data[i:i+chunk_size])
        else:
            self.send_error(404, "Not Found")

server = ForkingHTTPServer(('10.0.0.1', 8080), InMemoryHandler)
server.serve_forever()
PY
  HTTP_PID=$!
  sleep 1
}

wait_http_ready() {
  local ready=0
  for i in {1..20}; do
    if ip netns exec perf_work_ns curl -fsS --connect-timeout 1 --max-time 2 -o /dev/null "http://10.0.0.1:8080/" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.5
  done
  if [ "$ready" -ne 1 ]; then
    echo "Failed to connect to HTTP server at 10.0.0.1:8080" >&2
    exit 1
  fi
}

run_benchmarks() {
  local mode_name="$1"
  local output_file="$ARTIFACT_DIR/perf_${mode_name}.json"
  
  python3 - "$output_file" <<'PY'
import json, os, time
json.dump({"mode": os.sys.argv[1]}, open(os.sys.argv[1], "w"))
PY

  # TTFB benchmark
  ip netns exec perf_work_ns python3 - "$output_file" <<'PY'
import json, subprocess, sys, time
out = sys.argv[1]
samples = []
for _ in range(20):
    val = subprocess.check_output([
        "curl", "-fsS", "-o", "/dev/null", "-w", "%{time_starttransfer}",
        "--connect-timeout", "5", "--max-time", "10", "http://10.0.0.1:8080/"
    ], text=True)
    samples.append(float(val))
samples.sort()
data = json.load(open(out, encoding="utf-8"))
data["ttfb"] = {
    "p50": samples[len(samples)//2],
    "p95": samples[int(len(samples)*0.95)-1],
    "max": max(samples)
}
json.dump(data, open(out, "w", encoding="utf-8"), indent=2)
PY

  # Throughput benchmark
  ip netns exec perf_work_ns python3 - "$output_file" "$BLOB_MIB" <<'PY'
import json, subprocess, sys, time
out = sys.argv[1]
blob_mib = int(sys.argv[2])
start = time.monotonic()
subprocess.check_call([
    "curl", "-fsS", "-o", "/dev/null", "--connect-timeout", "5", "--max-time", "20",
    "http://10.0.0.1:8080/blob.bin"
])
elapsed = time.monotonic() - start
data = json.load(open(out, encoding="utf-8"))
data["throughput_mib_s"] = blob_mib / elapsed
json.dump(data, open(out, "w", encoding="utf-8"), indent=2)
PY
}

# ------------------------------------------------------------------------------
# 1. Benchmark: WireGuard Tunnel Mode
# ------------------------------------------------------------------------------
echo "=== [1/3] Benchmarking WireGuard (wireguard-go Userspace) ==="
setup_common_namespaces

# Configure Server WireGuard
ip netns exec perf_server_ns wireguard-go wg-server
sleep 0.5
ip netns exec perf_server_ns ip addr add 10.0.0.1/24 dev wg-server
ip netns exec perf_server_ns ip link set wg-server up
ip netns exec perf_server_ns wg set wg-server \
  private-key <(echo "$SERVER_WG_PRIV_B64") \
  listen-port 51820 \
  peer "$CLIENT_WG_PUB_B64" \
  allowed-ips "10.0.0.2/32,10.0.4.0/24"
ip netns exec perf_server_ns ip route replace 10.0.4.0/24 dev wg-server

# Configure Client WireGuard
ip netns exec perf_client_ns wireguard-go wg-client
sleep 0.5
ip netns exec perf_client_ns ip addr add 10.0.0.2/24 dev wg-client
ip netns exec perf_client_ns ip link set wg-client up
ip netns exec perf_client_ns wg set wg-client \
  private-key <(echo "$CLIENT_WG_PRIV_B64") \
  listen-port 51822 \
  peer "$SERVER_WG_PUB_B64" \
  endpoint "10.0.2.2:51820" \
  allowed-ips "10.0.0.0/24"
ip netns exec perf_client_ns ip route replace 10.0.0.0/24 dev wg-client

# Start HTTP Server and Loader
start_in_memory_http_server
wait_http_ready
run_benchmarks "wireguard"

# ------------------------------------------------------------------------------
# 2. Benchmark: QUIC TUN Mode
# ------------------------------------------------------------------------------
echo "=== [2/3] Benchmarking QUIC TUN Mode ==="
setup_common_namespaces

cat > "$ARTIFACT_DIR/server_tun.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
MTU = 1420
Table = auto

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = 40001, 40002

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32, 10.0.4.0/24
EOF_CONF

cat > "$ARTIFACT_DIR/client_tun.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
MTU = 1420
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32
EOF_CONF

ip netns exec perf_server_ns "$ROOT_DIR/target/release/new_proxy" -config "$ARTIFACT_DIR/server_tun.conf" > "$ARTIFACT_DIR/server_tun.log" 2>&1 &
SERVER_PID=$!
sleep 2

ip netns exec perf_client_ns "$ROOT_DIR/target/release/new_proxy" -config "$ARTIFACT_DIR/client_tun.conf" > "$ARTIFACT_DIR/client_tun.log" 2>&1 &
CLIENT_PID=$!
sleep 2

start_in_memory_http_server
wait_http_ready
run_benchmarks "quic_tun"

# ------------------------------------------------------------------------------
# 3. Benchmark: QUIC XDP Mode
# ------------------------------------------------------------------------------
echo "=== [3/3] Benchmarking QUIC XDP Mode ==="
setup_common_namespaces

# Build veth links for server-side XDP intercept (like perf_smoke_xdp.sh)
ip link add vp-s-w1 type veth peer name vp-s-w2
ip link set vp-s-w1 address 00:00:00:00:00:11
ip link set vp-s-w2 address 00:00:00:00:00:22
ip link set vp-s-w1 netns perf_server_ns
ip link set vp-s-w2 netns perf_server_ns
ip netns exec perf_server_ns ip addr add 10.0.0.1/24 dev vp-s-w1
ip netns exec perf_server_ns ip link set vp-s-w1 mtu 1420 up
ip netns exec perf_server_ns ip link set vp-s-w2 mtu 1420 up
ip netns exec perf_server_ns ip neighbor add 10.0.0.2 lladdr 00:00:00:00:00:22 dev vp-s-w1
ip netns exec perf_server_ns ip route add 10.0.4.0/24 via 10.0.0.2 dev vp-s-w1

# Update client side XDP routes
ip netns exec perf_client_ns ip route replace 10.0.0.1/32 dev lo

# Disable rp_filter & tx/rx checksum offloads for XDP
for ns in perf_server_ns perf_client_ns perf_work_ns perf_router_ns; do
  ip netns exec $ns sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec $ns sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
done

ip netns exec perf_server_ns ethtool -K vp-s tx off rx off 2>/dev/null || true
ip netns exec perf_server_ns ethtool -K vp-s-w1 tx off rx off 2>/dev/null || true
ip netns exec perf_server_ns ethtool -K vp-s-w2 tx off rx off 2>/dev/null || true
ip netns exec perf_client_ns ethtool -K vp-c tx off rx off 2>/dev/null || true
ip netns exec perf_client_ns ethtool -K vp-c-w tx off rx off 2>/dev/null || true
ip netns exec perf_work_ns ethtool -K vp-w tx off rx off 2>/dev/null || true
ip netns exec perf_router_ns ethtool -K vp-rs tx off rx off 2>/dev/null || true
ip netns exec perf_router_ns ethtool -K vp-rc tx off rx off 2>/dev/null || true

cat > "$ARTIFACT_DIR/server_xdp.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
MTU = 1420
Table = off
Mode = af_xdp

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = 40001

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32, 10.0.4.0/24

[XDP]
QuicInterface = vp-s
InterceptInterfaces = vp-s-w2
XdpMode = native
EOF_CONF

cat > "$ARTIFACT_DIR/client_xdp.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
MTU = 1420
Table = off
Mode = af_xdp

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32

[XDP]
QuicInterface = vp-c
InterceptInterfaces = vp-c-w, lo
XdpMode = native
EOF_CONF

ip netns exec perf_server_ns bash -c "mount -t bpf bpf /sys/fs/bpf && exec $ROOT_DIR/target/release/new_proxy -config $ARTIFACT_DIR/server_xdp.conf" > "$ARTIFACT_DIR/server_xdp.log" 2>&1 &
SERVER_PID=$!
sleep 2

ip netns exec perf_client_ns bash -c "mount -t bpf bpf /sys/fs/bpf && exec $ROOT_DIR/target/release/new_proxy -config $ARTIFACT_DIR/client_xdp.conf" > "$ARTIFACT_DIR/client_xdp.log" 2>&1 &
CLIENT_PID=$!
sleep 2

start_in_memory_http_server
wait_http_ready
run_benchmarks "quic_xdp"

# ------------------------------------------------------------------------------
# Report Generation
# ------------------------------------------------------------------------------
echo "=== Comparison Results ==="
python3 - "$ARTIFACT_DIR" <<'PY'
import json, os, sys

dir_path = sys.argv[1]
modes = ["wireguard", "quic_tun", "quic_xdp"]

print("| Mode | Throughput (MiB/s) | TTFB P50 (ms) | TTFB P95 (ms) | TTFB Max (ms) |")
print("| :--- | :----------------- | :------------ | :------------ | :------------ |")

for mode in modes:
    path = os.path.join(dir_path, f"perf_{mode}.json")
    if not os.path.exists(path):
        print(f"| {mode} | N/A | N/A | N/A | N/A |")
        continue
    data = json.load(open(path, encoding="utf-8"))
    
    tp = f"{data['throughput_mib_s']:.2f}"
    p50 = f"{data['ttfb']['p50'] * 1000:.2f}"
    p95 = f"{data['ttfb']['p95'] * 1000:.2f}"
    m = f"{data['ttfb']['max'] * 1000:.2f}"
    
    print(f"| {mode.upper()} | {tp} | {p50} | {p95} | {m} |")
PY
