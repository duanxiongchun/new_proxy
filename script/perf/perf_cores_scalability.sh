#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

DATA_PORT_COUNTS="${PERF_DATA_PORT_COUNTS:-1 2 3 4}"
PARALLEL="${PERF_PARALLEL:-16}"
ROUNDS="${PERF_ROUNDS:-2}"
BLOB_MIB="${PERF_BLOB_MIB:-16}"
ARTIFACT_DIR="${PERF_ARTIFACT_DIR:-/tmp/new_proxy_cores_scalability_$(date +%Y%m%d_%H%M%S)}"
RESULTS_CSV="$ARTIFACT_DIR/results.csv"

SERVER_PID=""
CLIENT_PID=""
HTTP_PID=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

expand_cpu_count() {
  python3 - "$1" <<'PY'
import sys

cpus = []
for part in sys.argv[1].split(","):
    part = part.strip()
    if not part:
        continue
    if "-" in part:
        start, end = [int(x) for x in part.split("-", 1)]
        if end < start:
            raise SystemExit(f"invalid CPU range: {part}")
        cpus.extend(range(start, end + 1))
    else:
        cpus.append(int(part))
print(len(cpus))
PY
}

cpus_for_data_ports() {
  python3 - "$ALLOWED_CPU_LIST" "$1" <<'PY'
import sys

allowed = []
for part in sys.argv[1].split(","):
    part = part.strip()
    if not part:
        continue
    if "-" in part:
        start, end = [int(x) for x in part.split("-", 1)]
        if end < start:
            raise SystemExit(f"invalid CPU range: {part}")
        allowed.extend(range(start, end + 1))
    else:
        allowed.append(int(part))

data_ports = int(sys.argv[2])
if data_ports < 1:
    raise SystemExit("data port count must be >= 1")
if data_ports > len(allowed):
    raise SystemExit(
        f"data_ports={data_ports} requires {data_ports} CPUs, but allowed cpuset has {len(allowed)}: {sys.argv[1]}"
    )
print(",".join(str(cpu) for cpu in allowed[:data_ports]))
PY
}

validate_data_port_counts() {
  for data_ports in $DATA_PORT_COUNTS; do
    if ! [[ "$data_ports" =~ ^[0-9]+$ ]] || [ "$data_ports" -lt 1 ]; then
      echo "Invalid PERF_DATA_PORT_COUNTS entry: $data_ports" >&2
      exit 1
    fi
    if [ "$data_ports" -gt "$ALLOWED_CPU_COUNT" ]; then
      echo "data_ports=$data_ports requires $data_ports CPUs, but allowed cpuset has $ALLOWED_CPU_COUNT: $ALLOWED_CPU_LIST" >&2
      echo "Set PERF_CPU_LIST or PERF_DATA_PORT_COUNTS to match this host." >&2
      exit 1
    fi
  done
}

quic_listen_ports() {
  python3 - "$1" <<'PY'
import sys
count = int(sys.argv[1])
print(", ".join(str(40001 + i) for i in range(count)))
PY
}

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
  ip netns delete scale_server_ns 2>/dev/null || true
  ip netns delete scale_router_ns 2>/dev/null || true
  ip netns delete scale_client_ns 2>/dev/null || true
  ip netns delete scale_work_ns 2>/dev/null || true
}
trap cleanup EXIT

for cmd in ip python3 curl taskset awk; do
  require_cmd "$cmd"
done

ALLOWED_CPU_LIST="${PERF_CPU_LIST:-$(taskset -pc $$ | awk -F: '{ gsub(/^[ \t]+/, "", $2); print $2 }')}"
if [ -z "$ALLOWED_CPU_LIST" ]; then
  echo "Failed to determine allowed CPU list; set PERF_CPU_LIST explicitly." >&2
  exit 1
fi
ALLOWED_CPU_COUNT="$(expand_cpu_count "$ALLOWED_CPU_LIST")"
validate_data_port_counts

if [ ! -x "$ROOT_DIR/target/release/new_proxy" ] || [ ! -x "$ROOT_DIR/target/release/new-proxy-cli" ]; then
  echo "Missing release binaries. Run: cargo build --release --bins" >&2
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"
: > "$RESULTS_CSV"

cleanup
mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then
  mknod /dev/net/tun c 10 200
fi
chmod 666 /dev/net/tun

CLIENT_CONF="$ARTIFACT_DIR/client.conf"

cat > "$CLIENT_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32
EOF_CONF

write_server_conf() {
  local data_ports="$1"
  local server_conf="$2"
  local listen_ports
  listen_ports="$(quic_listen_ports "$data_ports")"
  cat > "$server_conf" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = auto

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = ${listen_ports}

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32, 10.0.4.0/24
EOF_CONF
}

ip netns add scale_server_ns
ip netns add scale_router_ns
ip netns add scale_client_ns
ip netns add scale_work_ns

ip link add vs-s numtxqueues 4 numrxqueues 4 type veth peer name vs-rs numtxqueues 4 numrxqueues 4
ip link set vs-s netns scale_server_ns
ip link set vs-rs netns scale_router_ns
ip link add vs-c numtxqueues 4 numrxqueues 4 type veth peer name vs-rc numtxqueues 4 numrxqueues 4
ip link set vs-c netns scale_client_ns
ip link set vs-rc netns scale_router_ns
ip link add vs-w numtxqueues 4 numrxqueues 4 type veth peer name vs-cw numtxqueues 4 numrxqueues 4
ip link set vs-w netns scale_work_ns
ip link set vs-cw netns scale_client_ns

ip netns exec scale_server_ns ip addr add 10.0.2.2/24 dev vs-s
ip netns exec scale_server_ns ip link set vs-s up
ip netns exec scale_server_ns ip link set lo up
ip netns exec scale_server_ns ip route add default via 10.0.2.1

ip netns exec scale_client_ns ip addr add 10.0.1.2/24 dev vs-c
ip netns exec scale_client_ns ip addr add 10.0.4.1/24 dev vs-cw
ip netns exec scale_client_ns ip link set vs-c up
ip netns exec scale_client_ns ip link set vs-cw up
ip netns exec scale_client_ns ip link set lo up
ip netns exec scale_client_ns ip route add default via 10.0.1.1
ip netns exec scale_client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec scale_work_ns ip addr add 10.0.4.2/24 dev vs-w
ip netns exec scale_work_ns ip link set vs-w up
ip netns exec scale_work_ns ip link set lo up
ip netns exec scale_work_ns ip route add default via 10.0.4.1

ip netns exec scale_router_ns ip addr add 10.0.2.1/24 dev vs-rs
ip netns exec scale_router_ns ip addr add 10.0.1.1/24 dev vs-rc
ip netns exec scale_router_ns ip link set vs-rs up
ip netns exec scale_router_ns ip link set vs-rc up
ip netns exec scale_router_ns ip link set lo up
ip netns exec scale_router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec scale_router_ns ip route add 10.0.0.1/32 via 10.0.2.2
ip netns exec scale_router_ns ip route add 10.0.0.2/32 via 10.0.1.2

dd if=/dev/zero of="$ARTIFACT_DIR/blob.bin" bs=1M count="$BLOB_MIB" status=none

run_group() {
  local data_ports="$1"
  local cpus
  local server_cpus
  local loader_cpus="8-15"
  local target_cpus="16-23"
  local server_conf="$ARTIFACT_DIR/server_${data_ports}.conf"
  local server_log="$ARTIFACT_DIR/server_${data_ports}.log"
  local client_log="$ARTIFACT_DIR/client_${data_ports}.log"
  local worker_dump="$ARTIFACT_DIR/client_${data_ports}_dump.txt"
  cpus="$(cpus_for_data_ports "$data_ports")"
  server_cpus="$(python3 - "$data_ports" <<'PY'
import sys
dp = int(sys.argv[1])
print(",".join(str(4 + i) for i in range(dp)))
PY
)"
  write_server_conf "$data_ports" "$server_conf"

  ip netns exec scale_server_ns taskset -c "$server_cpus" "$ROOT_DIR/target/release/new_proxy" -config "$server_conf" > "$server_log" 2>&1 &
  SERVER_PID=$!
  sleep 2
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Server daemon exited early for data_ports=$data_ports" >&2
    cat "$server_log" >&2
    exit 1
  fi

  ip netns exec scale_server_ns taskset -c "$target_cpus" python3 - "$BLOB_MIB" <<'PY' > "$ARTIFACT_DIR/http.log" 2>&1 &
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
        if self.path == '/blob.bin':
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

  ip netns exec scale_client_ns taskset -c "$cpus" "$ROOT_DIR/target/release/new_proxy" -config "$CLIENT_CONF" > "$client_log" 2>&1 &
  CLIENT_PID=$!
  sleep 3
  if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "Client daemon exited early for data_ports=$data_ports" >&2
    cat "$client_log" >&2
    exit 1
  fi

  ip netns exec scale_work_ns curl -fsS --connect-timeout 5 --max-time 30 -o /dev/null "http://10.0.0.1:8080/blob.bin"

  echo "Starting perf record on client ($CLIENT_PID) and server ($SERVER_PID) for 10 seconds..." >&2
  perf record -F 99 -g -p "$CLIENT_PID" -o "$ARTIFACT_DIR/perf_client_${data_ports}.data" -- sleep 10 >/dev/null 2>&1 &
  perf record -F 99 -g -p "$SERVER_PID" -o "$ARTIFACT_DIR/perf_server_${data_ports}.data" -- sleep 10 >/dev/null 2>&1 &

  local line
  if ! line="$(ip netns exec scale_work_ns taskset -c "$loader_cpus" python3 - "$data_ports" "$PARALLEL" "$ROUNDS" "$BLOB_MIB" <<'PY'
import concurrent.futures
import subprocess
import sys
import time

data_ports = int(sys.argv[1])
parallel = int(sys.argv[2])
rounds = int(sys.argv[3])
blob_mib = int(sys.argv[4])
url = "http://10.0.0.1:8080/blob.bin"

def one(_):
    subprocess.check_call(
        ["curl", "-fsS", "--connect-timeout", "5", "--max-time", "90", "-o", "/dev/null", url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

start = time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
    list(ex.map(one, range(parallel * rounds)))
elapsed = time.monotonic() - start
total_mib = blob_mib * parallel * rounds
print(f"{data_ports},{parallel},{rounds},{total_mib},{elapsed:.6f},{total_mib / elapsed:.3f}")
PY
)"; then
    echo "Throughput load failed for data_ports=$data_ports" >&2
    cat "$client_log" >&2
    cat "$server_log" >&2
    kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
    CLIENT_PID=""
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    exit 1
  fi

  # Run UDP benchmark
  ip netns exec scale_server_ns taskset -c "$target_cpus" python3 - "$data_ports" "$target_cpus" <<'PY' > "$ARTIFACT_DIR/udp_recv_${data_ports}.log" 2>&1 &
import socket
import sys
import time
import multiprocessing

data_ports = int(sys.argv[1])
cpu_str = sys.argv[2]
target_cpus = []
for part in cpu_str.split(','):
    part = part.strip()
    if not part:
        continue
    if '-' in part:
        start, end = part.split('-')
        target_cpus.extend(range(int(start), int(end) + 1))
    else:
        target_cpus.append(int(part))

def recv_worker(port, cpu, conn):
    try:
        import os
        if hasattr(os, 'sched_setaffinity'):
            os.sched_setaffinity(0, {cpu})
    except:
        pass
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(('10.0.0.1', port))
    sock.settimeout(5.0)
    
    bytes_received = 0
    start = None
    last_packet_time = None
    
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            if not data:
                break
            if start is None:
                start = time.monotonic()
            if data == b'EOF':
                break
            bytes_received += len(data)
        last_packet_time = time.monotonic()
    except socket.timeout:
        last_packet_time = time.monotonic()
        
    duration = last_packet_time - start if (start and last_packet_time) else 0.001
    conn.send((bytes_received, duration))

if __name__ == '__main__':
    processes = []
    pipes = []
    for i in range(data_ports):
        port = 9990 + i
        cpu = target_cpus[i % len(target_cpus)]
        parent_conn, child_conn = multiprocessing.Pipe()
        p = multiprocessing.Process(target=recv_worker, args=(port, cpu, child_conn))
        p.start()
        processes.append(p)
        pipes.append(parent_conn)
        
    total_bytes = 0
    max_duration = 0.001
    for i, p in enumerate(processes):
        p.join()
        bytes_rec, duration = pipes[i].recv()
        total_bytes += bytes_rec
        if duration > max_duration:
            max_duration = duration
            
    print(f"{total_bytes},{max_duration:.6f}")
PY
  UDP_RECV_PID=$!
  sleep 1

  ip netns exec scale_work_ns taskset -c "$loader_cpus" python3 - "$PARALLEL" "$data_ports" <<'PY' > "$ARTIFACT_DIR/udp_send_${data_ports}.log" 2>&1
import socket
import sys
import multiprocessing

parallel = int(sys.argv[1])
data_ports = int(sys.argv[2])
total_to_send = 128 * 1024 * 1024
per_thread = total_to_send // parallel
chunk_size = 1100
data = b'X' * chunk_size

def send_worker(thread_idx):
    import time
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = 9990 + (thread_idx % data_ports)
    dest = ('10.0.0.1', port)
    sent = 0
    
    # Target: 50 MiB/s per port
    target_port_rate = 50.0 # MiB/s
    total_rate = target_port_rate * data_ports
    rate_per_thread = total_rate / parallel # MiB/s
    
    sleep_interval = 0.002
    packets_per_sec = (rate_per_thread * 1024 * 1024) / chunk_size
    burst_size = max(1, int(packets_per_sec * sleep_interval))
    
    burst_count = 0
    while sent < per_thread:
        sock.sendto(data, dest)
        sent += chunk_size
        burst_count += 1
        if burst_count >= burst_size:
            time.sleep(sleep_interval)
            burst_count = 0

if __name__ == '__main__':
    processes = []
    for i in range(parallel):
        p = multiprocessing.Process(target=send_worker, args=(i,))
        p.start()
        processes.append(p)
        
    for p in processes:
        p.join()
        
    # Send EOF to all ports
    for i in range(data_ports):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(20):
            sock.sendto(b'EOF', ('10.0.0.1', 9990 + i))
PY

  wait "$UDP_RECV_PID" || true
  local udp_line
  udp_line="$(cat "$ARTIFACT_DIR/udp_recv_${data_ports}.log")"
  local udp_bytes
  local udp_secs
  udp_bytes="$(echo "$udp_line" | cut -d',' -f1)"
  udp_secs="$(echo "$udp_line" | cut -d',' -f2)"
  local udp_mib_s
  udp_mib_s="$(python3 -c "print('{:.3f}'.format(int($udp_bytes) / 1024 / 1024 / float($udp_secs)))" 2>/dev/null || echo "0.000")"

  ip netns exec scale_client_ns "$ROOT_DIR/target/release/new-proxy-cli" --interface client dump > "$worker_dump"
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=""
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  kill "$HTTP_PID" 2>/dev/null || true
  wait "$HTTP_PID" 2>/dev/null || true
  HTTP_PID=""

  printf "%s,%s" "$line" "$udp_mib_s"
}

echo "Artifact directory: $ARTIFACT_DIR"
RAW_RESULTS_CSV="$ARTIFACT_DIR/results.raw.csv"
echo "data_ports,parallel,rounds,total_mib,seconds,mib_per_s,udp_mib_per_s,worker_new_flows" > "$RAW_RESULTS_CSV"
echo "data_ports,parallel,rounds,total_mib,seconds,mib_per_s,udp_mib_per_s,relative_to_1,linear_efficiency,worker_new_flows" > "$RESULTS_CSV"
for data_ports in $DATA_PORT_COUNTS; do
  if ! line="$(run_group "$data_ports")"; then
    exit 1
  fi
  worker_dump="$ARTIFACT_DIR/client_${data_ports}_dump.txt"
  worker_flows="$(awk -F'new_flows=' '/^worker:/ { split($2, a, "\t"); printf "%s%s", sep, a[1]; sep="|" }' "$worker_dump")"
  worker_count="$(awk '/^worker:/ { count++ } END { print count + 0 }' "$worker_dump")"
  if [ "$worker_count" -ne "$data_ports" ]; then
    echo "Expected $data_ports worker telemetry rows, got $worker_count in $worker_dump" >&2
    cat "$worker_dump" >&2
    exit 1
  fi
  if [ -z "$worker_flows" ]; then
    echo "Missing worker flow telemetry in $worker_dump" >&2
    cat "$worker_dump" >&2
    exit 1
  fi
  printf "%s,%s\n" "$line" "$worker_flows" | tee -a "$RAW_RESULTS_CSV"
  sleep 1
done

base_rate="$(awk -F, '$1 == 1 { print $6; found=1; exit } END { if (!found) exit 1 }' "$RAW_RESULTS_CSV")" || {
  echo "PERF_DATA_PORT_COUNTS must include 1 to compute relative_to_1" >&2
  cat "$RAW_RESULTS_CSV" >&2
  exit 1
}

awk -F, -v base="$base_rate" '
  NR == 1 { next }
  {
    relative = ($6 / base)
    efficiency = ($1 > 0) ? (relative / $1) : 0
    printf "%s,%s,%s,%s,%s,%s,%s,%.3f,%.3f,%s\n", $1, $2, $3, $4, $5, $6, $7, relative, efficiency, $8
  }
' "$RAW_RESULTS_CSV" > "$RESULTS_CSV.tmp"
{
  echo "data_ports,parallel,rounds,total_mib,seconds,mib_per_s,udp_mib_per_s,relative_to_1,linear_efficiency,worker_new_flows"
  cat "$RESULTS_CSV.tmp"
} | tee "$RESULTS_CSV"
rm -f "$RESULTS_CSV.tmp"
