#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

ARTIFACT_DIR="/tmp/new_proxy_profile_$(date +%Y%m%d_%H%M%S)"
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
  ip netns delete profile_server_ns 2>/dev/null || true
  ip netns delete profile_router_ns 2>/dev/null || true
  ip netns delete profile_client_ns 2>/dev/null || true
  ip netns delete profile_work_ns 2>/dev/null || true
  rm -f /tmp/profile_http_server.py
}
trap cleanup EXIT

cleanup

# Create namespaces
ip netns add profile_server_ns
ip netns add profile_router_ns
ip netns add profile_client_ns
ip netns add profile_work_ns

# Create veth pairs
ip link add vp-s type veth peer name vp-rs
ip link set vp-s netns profile_server_ns
ip link set vp-rs netns profile_router_ns
ip link add vp-c type veth peer name vp-rc
ip link set vp-c netns profile_client_ns
ip link set vp-rc netns profile_router_ns
ip link add vp-w type veth peer name client-veth
ip link set vp-w netns profile_work_ns
ip link set client-veth netns profile_client_ns

# Configure Server NS
ip netns exec profile_server_ns ip addr add 10.0.2.2/24 dev vp-s
ip netns exec profile_server_ns ip link set vp-s up
ip netns exec profile_server_ns ip link set lo up
ip netns exec profile_server_ns ip route add default via 10.0.2.1

# Configure Server Inner Virtual Interface
ip link add vp-s-w1 type veth peer name server-veth
ip link set vp-s-w1 address 00:00:00:00:00:11
ip link set server-veth address 00:00:00:00:00:22
ip link set vp-s-w1 netns profile_server_ns
ip link set server-veth netns profile_server_ns
ip netns exec profile_server_ns ip addr add 10.0.0.1/24 dev vp-s-w1
ip netns exec profile_server_ns ip link set vp-s-w1 mtu 1420 up
ip netns exec profile_server_ns ip link set server-veth mtu 1420 up
ip netns exec profile_server_ns ip neighbor add 10.0.0.2 lladdr 00:00:00:00:00:22 dev vp-s-w1
ip netns exec profile_server_ns ip route add 10.0.4.0/24 via 10.0.0.2 dev vp-s-w1

# Configure Client NS
ip netns exec profile_client_ns ip addr add 10.0.1.2/24 dev vp-c
ip netns exec profile_client_ns ip addr add 10.0.4.1/24 dev client-veth
ip netns exec profile_client_ns ip addr add 10.0.0.2/32 dev lo
ip netns exec profile_client_ns ip link set vp-c up
ip netns exec profile_client_ns ip link set client-veth mtu 1420 up
ip netns exec profile_client_ns ip link set lo up
ip netns exec profile_client_ns ip route add default via 10.0.1.1
ip netns exec profile_client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Configure Work NS
ip netns exec profile_work_ns ip addr add 10.0.4.2/24 dev vp-w
ip netns exec profile_work_ns ip link set vp-w mtu 1420 up
ip netns exec profile_work_ns ip link set lo up
ip netns exec profile_work_ns ip route add default via 10.0.4.1

# Configure Router NS
ip netns exec profile_router_ns ip addr add 10.0.2.1/24 dev vp-rs
ip netns exec profile_router_ns ip addr add 10.0.1.1/24 dev vp-rc
ip netns exec profile_router_ns ip link set vp-rs up
ip netns exec profile_router_ns ip link set vp-rc up
ip netns exec profile_router_ns ip link set lo up
ip netns exec profile_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec profile_router_ns ip route add 10.0.0.1/32 via 10.0.2.2
ip netns exec profile_router_ns ip route add 10.0.0.2/32 via 10.0.1.2

# Disable rp_filter in all namespaces
for ns in profile_server_ns profile_router_ns profile_client_ns profile_work_ns; do
  ip netns exec $ns sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec $ns sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
done

# Disable checksum/GRO offloads on veth interfaces
ip netns exec profile_server_ns ethtool -K vp-s tx off rx off 2>/dev/null || true
ip netns exec profile_server_ns ethtool -K vp-s-w1 tx off rx off 2>/dev/null || true
ip netns exec profile_server_ns ethtool -K server-veth tx off rx off 2>/dev/null || true
ip netns exec profile_client_ns ethtool -K vp-c tx off rx off 2>/dev/null || true
ip netns exec profile_client_ns ethtool -K client-veth tx off rx off 2>/dev/null || true
ip netns exec profile_work_ns ethtool -K vp-w tx off rx off 2>/dev/null || true
ip netns exec profile_router_ns ethtool -K vp-rs tx off rx off 2>/dev/null || true
ip netns exec profile_router_ns ethtool -K vp-rc tx off rx off 2>/dev/null || true

# Write configs with MTU 1420
cat > "$ARTIFACT_DIR/server.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
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
XdpMode = native
EOF_CONF

cat > "$ARTIFACT_DIR/client.conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
MTU = 1420
Table = off
Mode = af_xdp

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
AllowedIPs = 10.0.0.1/32

[XDP]
QuicInterface = vp-c
XdpMode = native
EOF_CONF

# Start new_proxy server daemon first (creates 'server' TUN with 10.0.0.1)
ip netns exec profile_server_ns bash -c "mount -t bpf bpf /sys/fs/bpf && exec \"$ROOT_DIR/target/release/new_proxy\" -config \"$ARTIFACT_DIR/server.conf\"" > "$ARTIFACT_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

# Start in-memory Python HTTP server (no disk I/O bottleneck)
cat > /tmp/profile_http_server.py <<'PYEOF'
import http.server
import io
import socketserver

# Pre-allocate 64 MiB of zero bytes in memory
BLOB_SIZE = 64 * 1024 * 1024
BLOB_DATA = b'\x00' * BLOB_SIZE

class InMemoryHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/ping' or self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')
        elif self.path == '/blob.bin':
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(BLOB_SIZE))
            self.end_headers()
            # Write in 64KB chunks to avoid overwhelming the socket
            offset = 0
            chunk_size = 65536
            while offset < BLOB_SIZE:
                try:
                    self.wfile.write(BLOB_DATA[offset:offset+chunk_size])
                    offset += chunk_size
                except BrokenPipeError:
                    break
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress access logs

class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == '__main__':
    server = ThreadedServer(('0.0.0.0', 8080), InMemoryHandler)
    print('HTTP server started on 0.0.0.0:8080', flush=True)
    server.serve_forever()
PYEOF
ip netns exec profile_server_ns python3 /tmp/profile_http_server.py > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

if ! kill -0 "$HTTP_PID" 2>/dev/null; then
  echo "HTTP server failed to start:" >&2
  cat "$ARTIFACT_DIR/http.log" >&2
  exit 1
fi

# Start new_proxy client daemon
ip netns exec profile_client_ns bash -c "mount -t bpf bpf /sys/fs/bpf && exec \"$ROOT_DIR/target/release/new_proxy\" -config \"$ARTIFACT_DIR/client.conf\"" > "$ARTIFACT_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3

# Warm up and check
echo "=== Waiting for tunnel connection to be fully established ==="
established=0
for i in {1..15}; do
  if ip netns exec profile_work_ns curl -fsS --connect-timeout 2 --max-time 5 -o /dev/null "http://10.0.0.1:8080/ping" 2>/dev/null; then
    echo "Connection established successfully!"
    established=1
    break
  fi
  echo "Tunnel not ready yet, retrying... ($i/15)"
  sleep 1
done

if [ "$established" -ne 1 ]; then
  echo "Error: Tunnel connection failed to establish." >&2
  echo "=== client log (tail) ==="
  tail -20 "$ARTIFACT_DIR/client.log" || true
  echo "=== server log (tail) ==="
  tail -20 "$ARTIFACT_DIR/server.log" || true
  exit 1
fi

# Confirm thread count
echo "=== Thread count for client process ==="
ls /proc/$CLIENT_PID/task/ 2>/dev/null | wc -l || true
echo "=== Thread names ==="
for tid in $(ls /proc/$CLIENT_PID/task/ 2>/dev/null); do
  name=$(cat /proc/$CLIENT_PID/task/$tid/comm 2>/dev/null || echo "?")
  echo "  TID $tid: $name"
done

# ========================
# Phase 1: Measure baseline throughput (no perf overhead)
# ========================
echo "=== Phase 1: Baseline throughput measurement (no perf) ==="
baseline_start=$(date +%s.%N)
ip netns exec profile_work_ns python3 -c "
import concurrent.futures, subprocess, sys
url = 'http://10.0.0.1:8080/blob.bin'
def one(_):
    subprocess.check_call(['curl', '-fsS', '--connect-timeout', '5', '--max-time', '120', '-o', '/dev/null', url],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
    list(ex.map(one, range(8)))  # 4 workers * 8 tasks = 512 MB
"
baseline_end=$(date +%s.%N)
baseline_elapsed=$(python3 -c "print(${baseline_end} - ${baseline_start})")
baseline_throughput=$(python3 -c "print(512 / ${baseline_elapsed})")
echo "Baseline elapsed: ${baseline_elapsed} s"
echo "Baseline throughput: ${baseline_throughput} MiB/s"

# ========================
# Phase 2: ON-CPU profiling with sustained load
# ========================
echo "=== Phase 2: ON-CPU Profile (with concurrent load) ==="

# Start sustained load in background
ip netns exec profile_work_ns python3 -c "
import concurrent.futures, subprocess
url = 'http://10.0.0.1:8080/blob.bin'
def one(_):
    subprocess.check_call(['curl', '-fsS', '--connect-timeout', '5', '--max-time', '120', '-o', '/dev/null', url],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
    list(ex.map(one, range(16)))  # sustained load for ~30+ seconds
" &
LOAD_PID=$!

sleep 3  # let load ramp up

# Record ON-CPU profile with higher frequency and DWARF call graphs
perf record -F 999 -g --call-graph dwarf -p "$CLIENT_PID" -o "$ARTIFACT_DIR/perf_oncpu.data" -- sleep 10

echo "ON-CPU recording complete"
echo "ON-CPU data size: $(du -h "$ARTIFACT_DIR/perf_oncpu.data" | cut -f1)"

# ========================
# Phase 3: OFF-CPU profiling with sustained load
# ========================
echo "=== Phase 3: OFF-CPU Profile (with concurrent load) ==="

# Record OFF-CPU profile
perf record -g -e 'sched:sched_switch' -p "$CLIENT_PID" -o "$ARTIFACT_DIR/perf_offcpu.data" -- sleep 10

echo "OFF-CPU recording complete"
echo "OFF-CPU data size: $(du -h "$ARTIFACT_DIR/perf_offcpu.data" | cut -f1)"

# Wait for load to finish
wait $LOAD_PID 2>/dev/null || true

# ========================
# Phase 4: Generate flamegraphs
# ========================
echo "=== Phase 4: Generating flamegraphs ==="

# ON-CPU flamegraph
oncpu_stacks=$(perf script -i "$ARTIFACT_DIR/perf_oncpu.data" 2>/dev/null | /tmp/FlameGraph/stackcollapse-perf.pl 2>/dev/null)
oncpu_count=$(echo "$oncpu_stacks" | wc -l)
echo "ON-CPU stack count: $oncpu_count"

if [ "$oncpu_count" -gt 1 ]; then
  echo "$oncpu_stacks" | /tmp/FlameGraph/flamegraph.pl > "$ARTIFACT_DIR/client_oncpu.svg"
  echo "ON-CPU flamegraph generated successfully"
else
  echo "WARNING: ON-CPU stack count is low ($oncpu_count)"
  # Try raw perf script dump for debugging
  perf script -i "$ARTIFACT_DIR/perf_oncpu.data" > "$ARTIFACT_DIR/perf_oncpu_raw.txt" 2>&1
  echo "Raw perf script output: $(wc -l < "$ARTIFACT_DIR/perf_oncpu_raw.txt") lines"
  head -50 "$ARTIFACT_DIR/perf_oncpu_raw.txt"
  # Still generate even if low
  echo "$oncpu_stacks" | /tmp/FlameGraph/flamegraph.pl > "$ARTIFACT_DIR/client_oncpu.svg" 2>/dev/null || true
fi

# OFF-CPU flamegraph
offcpu_stacks=$(perf script -F trace:time,comm,pid,tid,event,ip,sym,dso,trace -i "$ARTIFACT_DIR/perf_offcpu.data" 2>/dev/null | \
  /tmp/FlameGraph/stackcollapse-perf-sched.awk -v recurse=1 2>/dev/null || true)
offcpu_count=$(echo "$offcpu_stacks" | grep -c '[^ ]' || true)
echo "OFF-CPU stack count: $offcpu_count"

if [ "$offcpu_count" -gt 0 ]; then
  echo "$offcpu_stacks" | /tmp/FlameGraph/flamegraph.pl --color=io --countname=us > "$ARTIFACT_DIR/client_offcpu.svg"
  echo "OFF-CPU flamegraph generated successfully"
else
  echo "WARNING: OFF-CPU stack count is 0"
  perf script -i "$ARTIFACT_DIR/perf_offcpu.data" > "$ARTIFACT_DIR/perf_offcpu_raw.txt" 2>&1
  echo "Raw OFF-CPU perf script output: $(wc -l < "$ARTIFACT_DIR/perf_offcpu_raw.txt") lines"
fi

# Export results
cp "$ARTIFACT_DIR/client_oncpu.svg" /tmp/client_oncpu.svg 2>/dev/null || true
cp "$ARTIFACT_DIR/client_offcpu.svg" /tmp/client_offcpu.svg 2>/dev/null || true
chmod 666 /tmp/client_oncpu.svg /tmp/client_offcpu.svg 2>/dev/null || true

echo ""
echo "=============================================="
echo "=== Performance profiling completed! ==="
echo "=============================================="
echo "Baseline throughput: ${baseline_throughput} MiB/s"
echo "Artifacts saved in: $ARTIFACT_DIR"
echo "ON-CPU Flamegraph: /tmp/client_oncpu.svg"
echo "OFF-CPU Flamegraph: /tmp/client_offcpu.svg"
