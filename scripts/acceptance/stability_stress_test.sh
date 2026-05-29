#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

DURATION="${STABILITY_DURATION:-3600}"
SAMPLE_INTERVAL="${STABILITY_SAMPLE_INTERVAL:-30}"
LONG_THREADS="${STABILITY_LONG_THREADS:-8}"
SHORT_PARALLEL="${STABILITY_SHORT_PARALLEL:-4}"
ARTIFACT_DIR="${STABILITY_ARTIFACT_DIR:-/tmp/new_proxy_stability_$(date +%Y%m%d_%H%M%S)}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_CONF="$ARTIFACT_DIR/server_stability.conf"
CLIENT_CONF="$ARTIFACT_DIR/client_stability.conf"
METRICS="$ARTIFACT_DIR/stability_metrics.jsonl"

SERVER_PID=""
CLIENT_PID=""
TARGET_PID=""
LONG_PID=""
SHORT_PID=""
UDP_PID=""
PING_PID=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1"
    exit 1
  fi
}

cleanup() {
  set +e
  for pid in "$SHORT_PID" "$UDP_PID" "$PING_PID" "$LONG_PID" "$CLIENT_PID" "$SERVER_PID" "$TARGET_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null
    fi
  done
  sleep 1
  for pid in "$SHORT_PID" "$UDP_PID" "$PING_PID" "$LONG_PID" "$CLIENT_PID" "$SERVER_PID" "$TARGET_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null
    fi
  done
  ip netns delete client_ns 2>/dev/null
  ip netns delete router_ns 2>/dev/null
  ip netns delete server_ns 2>/dev/null
  rm -f /tmp/new_proxy_api.sock /tmp/new_proxy_api_client.sock /tmp/client_proxy_active
}
trap cleanup EXIT

for cmd in ip iptables python3 curl ping ps; do
  require_cmd "$cmd"
done

if [ ! -x "$ROOT_DIR/target/debug/new_proxy" ] || [ ! -x "$ROOT_DIR/target/debug/new-proxy-cli" ]; then
  echo "Missing target/debug binaries. Run: cargo build --bins"
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"
: > "$METRICS"
: > "$ARTIFACT_DIR/short_conn.log"
: > "$ARTIFACT_DIR/udp.log"
: > "$ARTIFACT_DIR/ping.log"

cat > "$SERVER_CONF" <<'EOF_CONF'
[Interface]
PrivateKey = 1WL7OPPOABmaRVdjR6JoliATNsjOVFO1bE8gM113POM=
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
ListenControlPort = 51821

[QUICPool]
PublicIPv4 = 10.0.2.2
PublicIPv6 = fd00:2::2
ListenPorts = 40001, 40002, 40003, 40004

[Peer]
PublicKey = 09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=
AllowedIPs = 10.0.0.2/32, fd00::2/128
EOF_CONF

cat > "$CLIENT_CONF" <<'EOF_CONF'
[Interface]
PrivateKey = etewwnbYf1Zk8wnouPD/qbVWQpP9xW61CeNZ4JCXo24=
Address = 10.0.0.2/24, fd00::2/64
TProxyPort = 1080
MTU = 1400

[Peer]
PublicKey = vWwaq2WH6+bOvcsFJHRqOhvMoPxBMHkWrug2YfyQ3ho=
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32, fd00::1/128
EOF_CONF

echo "=== [1/7] Setting up namespaces ==="
cleanup
ip netns add client_ns
ip netns add router_ns
ip netns add server_ns

ip link add veth-client type veth peer name veth-router-c
ip link set veth-client netns client_ns
ip link set veth-router-c netns router_ns
ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

ip netns exec client_ns ip addr add 10.0.1.2/24 dev veth-client
ip netns exec client_ns ip link set veth-client up
ip netns exec client_ns ip link set lo up
ip netns exec client_ns ip addr add 10.0.0.2/32 dev lo
ip netns exec client_ns ip route add default via 10.0.1.1
ip netns exec client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up
ip netns exec server_ns ip addr add 10.0.0.1/32 dev lo
ip netns exec server_ns ip route add default via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.1/32 dev lo scope host

ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c
ip netns exec router_ns ip link set veth-router-c up
ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip link set lo up
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec router_ns ip route add 10.0.0.1/32 via 10.0.1.2
ip netns exec client_ns ip route add 10.0.0.1/32 via 10.0.1.1

ip netns exec client_ns ip rule add fwmark 1 lookup 100
ip netns exec client_ns ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec client_ns iptables -t mangle -A PREROUTING -p tcp -d 10.0.0.1 -j TPROXY --on-port 1080 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1

echo "=== [2/7] Starting target TCP/UDP server ==="
ip netns exec server_ns python3 "$ROOT_DIR/scripts/acceptance/stability_server.py" > "$ARTIFACT_DIR/target_server.log" 2>&1 &
TARGET_PID=$!
sleep 1

echo "=== [3/7] Starting server/client proxies with 4 QUIC ports ==="
ip netns exec server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER_CONF" > "$ARTIFACT_DIR/server_daemon.log" 2>&1 &
SERVER_PID=$!
sleep 2
ip netns exec client_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$ARTIFACT_DIR/client_daemon.log" 2>&1 &
CLIENT_PID=$!
sleep 3

echo "=== [4/7] Verifying initial TCP path ==="
ip netns exec router_ns curl -fsS --connect-timeout 5 --max-time 10 -o /dev/null http://10.0.0.1:8080/

monitor_once() {
  python3 - "$METRICS" "$SERVER_PID" "$CLIENT_PID" "$START_TS" <<'PY'
import json
import os
import socket
import subprocess
import sys
import time

metrics_path, server_pid, client_pid, start_ts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])

def proc(pid):
    alive = os.path.exists(f"/proc/{pid}")
    data = {"pid": pid, "alive": alive, "cpu_percent": None, "rss_kib": None}
    if alive:
        out = subprocess.run(["ps", "-p", str(pid), "-o", "%cpu=", "-o", "rss="], text=True, capture_output=True)
        parts = out.stdout.split()
        if len(parts) >= 2:
            data["cpu_percent"] = float(parts[0])
            data["rss_kib"] = int(parts[1])
    return data

def telemetry():
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect("/tmp/new_proxy_api.sock")
        sock.sendall(json.dumps({"type": "Stats"}).encode())
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        sock.close()
        return json.loads(b"".join(chunks).decode() or "[]")
    except Exception as exc:
        return {"error": str(exc)}

now = int(time.time())
row = {
    "timestamp": now,
    "elapsed_seconds": now - start_ts,
    "server": proc(server_pid),
    "client": proc(client_pid),
    "telemetry": telemetry(),
}
with open(metrics_path, "a", encoding="utf-8") as f:
    f.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

short_loop() {
  end=$((START_TS + DURATION))
  while [ "$(date +%s)" -lt "$end" ]; do
    for _ in $(seq 1 "$SHORT_PARALLEL"); do
      if ip netns exec router_ns curl -fsS --connect-timeout 3 --max-time 5 -o /dev/null http://10.0.0.1:8080/; then
        echo "$(date +%s) OK" >> "$ARTIFACT_DIR/short_conn.log"
      else
        echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/short_conn.log"
      fi &
    done
    wait
    sleep 1
  done
}

udp_loop() {
  end=$((START_TS + DURATION))
  while [ "$(date +%s)" -lt "$end" ]; do
    if ip netns exec client_ns python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b"stability-udp", ("10.0.2.2", 8081))
print(s.recvfrom(1024)[0].decode(errors="replace"))
PY
    then
      echo "$(date +%s) OK" >> "$ARTIFACT_DIR/udp.log"
    else
      echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/udp.log"
    fi
    sleep 5
  done
}

ping_loop() {
  end=$((START_TS + DURATION))
  while [ "$(date +%s)" -lt "$end" ]; do
    if ip netns exec client_ns ping -c 1 -W 2 10.0.2.2 >/dev/null; then
      echo "$(date +%s) OK" >> "$ARTIFACT_DIR/ping.log"
    else
      echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/ping.log"
    fi
    sleep 2
  done
}

echo "=== [5/7] Starting background traffic for ${DURATION}s ==="
START_TS="$(date +%s)"
ip netns exec router_ns python3 "$ROOT_DIR/scripts/acceptance/stability_long_tcp.py" --duration "$DURATION" --threads "$LONG_THREADS" --stats-out "$ARTIFACT_DIR/long_tcp_stats.json" > "$ARTIFACT_DIR/long_tcp.log" 2>&1 &
LONG_PID=$!
short_loop &
SHORT_PID=$!
udp_loop > "$ARTIFACT_DIR/udp_loop.log" 2>&1 &
UDP_PID=$!
ping_loop &
PING_PID=$!

echo "=== [6/7] Sampling telemetry ==="
END_TS=$((START_TS + DURATION))
while [ "$(date +%s)" -lt "$END_TS" ]; do
  monitor_once
  sleep "$SAMPLE_INTERVAL"
done
monitor_once

wait "$LONG_PID" || true
wait "$SHORT_PID" || true
wait "$UDP_PID" || true
wait "$PING_PID" || true

echo "=== [7/7] Generating report ==="
REPORT_PATH="$(python3 "$ROOT_DIR/scripts/acceptance/stability_report.py" "$ARTIFACT_DIR")"
echo "Artifacts: $ARTIFACT_DIR"
echo "Report: $REPORT_PATH"
