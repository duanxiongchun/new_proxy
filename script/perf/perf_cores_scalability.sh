#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"

DATA_PORT_COUNTS="${PERF_DATA_PORT_COUNTS:-1 2 3 4}"
PARALLEL="${PERF_PARALLEL:-32}"
ROUNDS="${PERF_ROUNDS:-2}"
BLOB_MIB="${PERF_BLOB_MIB:-64}"
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
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = ${listen_ports}

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32
EOF_CONF
}

ip netns add scale_server_ns
ip netns add scale_router_ns
ip netns add scale_client_ns
ip netns add scale_work_ns

ip link add vs-s type veth peer name vs-rs
ip link set vs-s netns scale_server_ns
ip link set vs-rs netns scale_router_ns
ip link add vs-c type veth peer name vs-rc
ip link set vs-c netns scale_client_ns
ip link set vs-rc netns scale_router_ns
ip link add vs-w type veth peer name vs-cw
ip link set vs-w netns scale_work_ns
ip link set vs-cw netns scale_client_ns

ip netns exec scale_server_ns ip addr add 10.0.2.2/24 dev vs-s
ip netns exec scale_server_ns ip addr add 10.0.0.1/32 dev lo
ip netns exec scale_server_ns ip link set vs-s up
ip netns exec scale_server_ns ip link set lo up
ip netns exec scale_server_ns ip route add default via 10.0.2.1
ip netns exec scale_server_ns ip route add 10.0.0.1/32 dev lo scope host
ip netns exec scale_server_ns ip route add 10.0.0.2/32 via 10.0.2.1

ip netns exec scale_client_ns ip addr add 10.0.1.2/24 dev vs-c
ip netns exec scale_client_ns ip addr add 10.0.4.1/24 dev vs-cw
ip netns exec scale_client_ns ip addr add 10.0.0.2/32 dev lo
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
ip netns exec scale_server_ns python3 -m http.server 8080 --bind 10.0.0.1 --directory "$ARTIFACT_DIR" > "$ARTIFACT_DIR/http.log" 2>&1 &
HTTP_PID=$!

run_group() {
  local data_ports="$1"
  local cpus
  local server_conf="$ARTIFACT_DIR/server_${data_ports}.conf"
  local server_log="$ARTIFACT_DIR/server_${data_ports}.log"
  local client_log="$ARTIFACT_DIR/client_${data_ports}.log"
  local worker_dump="$ARTIFACT_DIR/client_${data_ports}_dump.txt"
  cpus="$(cpus_for_data_ports "$data_ports")"
  write_server_conf "$data_ports" "$server_conf"

  ip netns exec scale_server_ns "$ROOT_DIR/target/release/new_proxy" -config "$server_conf" > "$server_log" 2>&1 &
  SERVER_PID=$!
  sleep 2
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Server daemon exited early for data_ports=$data_ports" >&2
    cat "$server_log" >&2
    exit 1
  fi

  ip netns exec scale_client_ns taskset -c "$cpus" "$ROOT_DIR/target/release/new_proxy" -config "$CLIENT_CONF" > "$client_log" 2>&1 &
  CLIENT_PID=$!
  sleep 3
  if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "Client daemon exited early for data_ports=$data_ports" >&2
    cat "$client_log" >&2
    exit 1
  fi

  ip netns exec scale_work_ns curl -fsS --connect-timeout 5 --max-time 30 -o /dev/null "http://10.0.0.1:8080/blob.bin"

  local line
  if ! line="$(ip netns exec scale_work_ns python3 - "$data_ports" "$PARALLEL" "$ROUNDS" "$BLOB_MIB" <<'PY'
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

  ip netns exec scale_client_ns "$ROOT_DIR/target/release/new-proxy-cli" --interface client dump > "$worker_dump"
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=""
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""

  printf "%s" "$line"
}

echo "Artifact directory: $ARTIFACT_DIR"
echo "data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows" | tee "$RESULTS_CSV"
base_rate=""
for data_ports in $DATA_PORT_COUNTS; do
  if ! line="$(run_group "$data_ports")"; then
    exit 1
  fi
  rate="$(printf "%s" "$line" | awk -F, '{print $6}')"
  if [ -z "$base_rate" ]; then
    base_rate="$rate"
  fi
  relative="$(awk -v rate="$rate" -v base="$base_rate" 'BEGIN { if (base > 0) printf "%.3f", rate / base; else printf "0.000" }')"
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
  printf "%s,%s,%s\n" "$line" "$relative" "$worker_flows" | tee -a "$RESULTS_CSV"
  sleep 1
done

cat "$RESULTS_CSV"
