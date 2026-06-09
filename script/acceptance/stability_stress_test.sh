#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

DURATION="${STABILITY_DURATION:-3600}"
SAMPLE_INTERVAL="${STABILITY_SAMPLE_INTERVAL:-30}"
LONG_WORKERS="${STABILITY_LONG_WORKERS:-8}"
SHORT_PARALLEL="${STABILITY_SHORT_PARALLEL:-4}"
ARTIFACT_DIR="${STABILITY_ARTIFACT_DIR:-/tmp/new_proxy_stability_$(date +%Y%m%d_%H%M%S)}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"
SERVER_CONF="$ARTIFACT_DIR/srv_stab.conf"
CLIENT_CONF="$ARTIFACT_DIR/cli_stab.conf"
CLIENT2_CONF="$ARTIFACT_DIR/cli2_stab.conf"
METRICS="$ARTIFACT_DIR/stability_metrics.jsonl"

SERVER_PID=""
CLIENT_PID=""
CLIENT2_PID=""
TARGET_PID=""
LONG_PID=""
LONG2_PID=""
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
  for pid in "$SHORT_PID" "$UDP_PID" "$PING_PID" "$LONG_PID" "$LONG2_PID" "$CLIENT_PID" "$CLIENT2_PID" "$SERVER_PID" "$TARGET_PID"; do
    if [ -n "${pid:-}" ]; then
      kill "$pid" 2>/dev/null
    fi
  done
  sleep 1
  for pid in "$SHORT_PID" "$UDP_PID" "$PING_PID" "$LONG_PID" "$LONG2_PID" "$CLIENT_PID" "$CLIENT2_PID" "$SERVER_PID" "$TARGET_PID"; do
    if [ -n "${pid:-}" ]; then
      kill -9 "$pid" 2>/dev/null
    fi
  done
  ip netns delete client1_ns 2>/dev/null || true
  ip netns delete client1_work_ns 2>/dev/null || true
  ip netns delete client2_ns 2>/dev/null || true
  ip netns delete client2_work_ns 2>/dev/null || true
  ip netns delete client3_ns 2>/dev/null || true
  ip netns delete client4_ns 2>/dev/null || true
  ip netns delete router_ns 2>/dev/null || true
  ip netns delete server_ns 2>/dev/null || true
  rm -f /run/new_proxy/srv_stab.sock /run/new_proxy/cli_stab.sock
}
trap cleanup EXIT

for cmd in ip python3 curl ping ps; do
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

cat > "$SERVER_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
PublicIPv6 = fd00:2::2
ListenPorts = 40001, 40002, 40003, 40004

# Client 1: Custom Proxy Client Peer (Defined in config, so it's 'both')
[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32, fd00::2/128, 10.0.4.0/24

# Client 2: second independent QUIC proxy peer
[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT2_PUBLIC_KEY}
AllowedIPs = 10.0.0.4/32, 10.0.8.0/24

# Client 3/4: direct physical L3 baseline namespaces; they must not enter any QUIC pool.
[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT3_PUBLIC_KEY}
AllowedIPs = 10.0.0.3/32

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT4_PUBLIC_KEY}
AllowedIPs = 10.0.0.5/32
EOF_CONF

cat > "$CLIENT_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24, fd00::2/64
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32, fd00::1/128
EOF_CONF

cat > "$CLIENT2_CONF" <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT2_PRIVATE_KEY}
Address = 10.0.0.4/24
MTU = 1400
Table = auto

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32
EOF_CONF

echo "=== [1/7] Setting up namespaces ==="
cleanup
ip netns add server_ns
ip netns add router_ns
ip netns add client1_ns
ip netns add client1_work_ns
ip netns add client2_ns
ip netns add client2_work_ns
ip netns add client3_ns
ip netns add client4_ns

# Server <-> Router
ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

# Client 1 <-> Router
ip link add veth-client1 type veth peer name veth-router-c1
ip link set veth-client1 netns client1_ns
ip link set veth-router-c1 netns router_ns

# Client 1 workload <-> Client 1 proxy router
ip link add veth-work type veth peer name veth-client1-w
ip link set veth-work netns client1_work_ns
ip link set veth-client1-w netns client1_ns

# Client 2 <-> Router (second QUIC proxy client)
ip link add veth-client2 type veth peer name veth-router-c2
ip link set veth-client2 netns client2_ns
ip link set veth-router-c2 netns router_ns

# Client 2 workload <-> Client 2 proxy router
ip link add veth-work2 type veth peer name veth-client2-w
ip link set veth-work2 netns client2_work_ns
ip link set veth-client2-w netns client2_ns

# Client 3/4 <-> Router (direct physical L3 baseline clients)
ip link add veth-client3 type veth peer name veth-router-c3
ip link set veth-client3 netns client3_ns
ip link set veth-router-c3 netns router_ns
ip link add veth-client4 type veth peer name veth-router-c4
ip link set veth-client4 netns client4_ns
ip link set veth-router-c4 netns router_ns

# Server NS
ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up
ip netns exec server_ns ip addr add 10.0.0.1/32 dev lo

# Client 1 NS (Custom Proxy)
ip netns exec client1_ns ip addr add 10.0.1.2/24 dev veth-client1
ip netns exec client1_ns ip link set veth-client1 up
ip netns exec client1_ns ip addr add 10.0.4.1/24 dev veth-client1-w
ip netns exec client1_ns ip link set veth-client1-w up
ip netns exec client1_ns ip link set lo up

# Client 1 workload NS. Its TCP traffic enters client1_ns and is routed into
# the userspace TUN route installed by new_proxy Table=auto.
ip netns exec client1_work_ns ip addr add 10.0.4.2/24 dev veth-work
ip netns exec client1_work_ns ip link set veth-work up
ip netns exec client1_work_ns ip link set lo up
ip netns exec client1_work_ns ip route add default via 10.0.4.1

# Client 2 NS (second Custom Proxy)
ip netns exec client2_ns ip addr add 10.0.5.2/24 dev veth-client2
ip netns exec client2_ns ip link set veth-client2 up
ip netns exec client2_ns ip addr add 10.0.8.1/24 dev veth-client2-w
ip netns exec client2_ns ip link set veth-client2-w up
ip netns exec client2_ns ip link set lo up

# Client 2 workload NS.
ip netns exec client2_work_ns ip addr add 10.0.8.2/24 dev veth-work2
ip netns exec client2_work_ns ip link set veth-work2 up
ip netns exec client2_work_ns ip link set lo up
ip netns exec client2_work_ns ip route add default via 10.0.8.1

# Client 3/4 NS (direct physical L3 baseline)
ip netns exec client3_ns ip addr add 10.0.6.2/24 dev veth-client3
ip netns exec client3_ns ip link set veth-client3 up
ip netns exec client3_ns ip link set lo up
ip netns exec client3_ns ip addr add 10.0.0.3/32 dev lo
ip netns exec client4_ns ip addr add 10.0.7.2/24 dev veth-client4
ip netns exec client4_ns ip link set veth-client4 up
ip netns exec client4_ns ip link set lo up
ip netns exec client4_ns ip addr add 10.0.0.5/32 dev lo

# Router NS
ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c1
ip netns exec router_ns ip link set veth-router-c1 up
ip netns exec router_ns ip addr add 10.0.5.1/24 dev veth-router-c2
ip netns exec router_ns ip link set veth-router-c2 up
ip netns exec router_ns ip addr add 10.0.6.1/24 dev veth-router-c3
ip netns exec router_ns ip link set veth-router-c3 up
ip netns exec router_ns ip addr add 10.0.7.1/24 dev veth-router-c4
ip netns exec router_ns ip link set veth-router-c4 up
ip netns exec router_ns ip link set lo up

# Enable IP forwarding
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec client1_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec client2_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Clients Gateway Routes
ip netns exec client1_ns ip route add default via 10.0.1.1

ip netns exec client2_ns ip route add default via 10.0.5.1
ip netns exec client3_ns ip route add default via 10.0.6.1
ip netns exec client3_ns ip route add 10.0.0.1/32 via 10.0.6.1
ip netns exec client4_ns ip route add default via 10.0.7.1
ip netns exec client4_ns ip route add 10.0.0.1/32 via 10.0.7.1

# Server Gateway & Client Routes
ip netns exec server_ns ip route add default via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.2/32 via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.3/32 via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.4/32 via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.5/32 via 10.0.2.1
ip netns exec server_ns ip route add 10.0.0.1/32 dev lo scope host

# Router Routing Table
ip netns exec router_ns ip route add 10.0.0.1/32 via 10.0.2.2
ip netns exec router_ns ip route add 10.0.0.2/32 via 10.0.1.2
ip netns exec router_ns ip route add 10.0.0.3/32 via 10.0.6.2
ip netns exec router_ns ip route add 10.0.0.4/32 via 10.0.5.2
ip netns exec router_ns ip route add 10.0.0.5/32 via 10.0.7.2


echo "=== [2/7] Starting target TCP/UDP server ==="
ip netns exec server_ns python3 "$ROOT_DIR/script/acceptance/stability_server.py" > "$ARTIFACT_DIR/target_server.log" 2>&1 &
TARGET_PID=$!
sleep 1

echo "=== [3/7] Starting server/client proxies with 4 QUIC ports ==="
ip netns exec server_ns "$ROOT_DIR/target/debug/new_proxy" -config "$SERVER_CONF" > "$ARTIFACT_DIR/server_daemon.log" 2>&1 &
SERVER_PID=$!
sleep 2
ip netns exec server_ns ip addr add 10.0.0.1/24 dev srv_stab || true
ip netns exec server_ns ip link set srv_stab up
ip netns exec server_ns ip route replace 10.0.4.0/24 dev srv_stab
ip netns exec server_ns ip route replace 10.0.8.0/24 dev srv_stab
ip netns exec client1_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT_CONF" > "$ARTIFACT_DIR/client_daemon.log" 2>&1 &
CLIENT_PID=$!
ip netns exec client2_ns "$ROOT_DIR/target/debug/new_proxy" -config "$CLIENT2_CONF" > "$ARTIFACT_DIR/client2_daemon.log" 2>&1 &
CLIENT2_PID=$!
sleep 3

echo "=== [4/7] Verifying initial TCP paths for both clients ==="
# Direct L3 path (router_ns -> server_ns)
ip netns exec router_ns curl -fsS --connect-timeout 5 --max-time 10 -o /dev/null http://10.0.0.1:8080/
# Direct physical L3 baseline paths (client3/4_ns -> router_ns -> server_ns)
ip netns exec client3_ns curl -fsS --connect-timeout 5 --max-time 10 -o /dev/null http://10.0.0.1:8080/
ip netns exec client4_ns curl -fsS --connect-timeout 5 --max-time 10 -o /dev/null http://10.0.0.1:8080/
# QUIC offload path (client1_work_ns -> client1_ns TUN/smoltcp -> QUIC pool -> server_ns)
ip netns exec client1_work_ns curl -fsS --connect-timeout 5 --max-time 10 -o /dev/null http://10.0.0.1:8080/
ip netns exec client2_work_ns curl -fsS --connect-timeout 5 --max-time 10 -o /dev/null http://10.0.0.1:8080/

monitor_once() {
  python3 - "$METRICS" "$SERVER_PID" "$CLIENT_PID" "$CLIENT2_PID" "$START_TS" <<'PY'
import json
import os
import socket
import subprocess
import sys
import time

metrics_path, server_pid, client_pid, client2_pid, start_ts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])

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
        sock.connect("/run/new_proxy/srv_stab.sock")
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
    "client2": proc(client2_pid),
    "telemetry": telemetry(),
}
with open(metrics_path, "a", encoding="utf-8") as f:
    f.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

short_loop() {
  end=$((START_TS + DURATION))
  while [ "$(date +%s)" -lt "$end" ]; do
    # QUIC offload paths: two independent proxy peers, each with its own QUIC pool.
    for _ in $(seq 1 "$SHORT_PARALLEL"); do
      if ip netns exec client1_work_ns curl -fsS --connect-timeout 3 --max-time 5 -o /dev/null http://10.0.0.1:8080/; then
        echo "$(date +%s) OK" >> "$ARTIFACT_DIR/short_conn.log"
      else
        echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/short_conn.log"
      fi &
    done
    for _ in $(seq 1 "$SHORT_PARALLEL"); do
      if ip netns exec client2_work_ns curl -fsS --connect-timeout 3 --max-time 5 -o /dev/null http://10.0.0.1:8080/; then
        echo "$(date +%s) OK" >> "$ARTIFACT_DIR/short_conn.log"
      else
        echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/short_conn.log"
      fi &
    done
    # Direct L3 path: router_ns -> server_ns (bypasses QUIC, tests standard routing)
    for _ in $(seq 1 "$SHORT_PARALLEL"); do
      if ip netns exec router_ns curl -fsS --connect-timeout 3 --max-time 5 -o /dev/null http://10.0.0.1:8080/; then
        echo "$(date +%s) OK" >> "$ARTIFACT_DIR/short_conn.log"
      else
        echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/short_conn.log"
      fi &
    done
    # Direct physical L3 baseline paths: two namespaces bypass QUIC entirely.
    for _ in $(seq 1 "$SHORT_PARALLEL"); do
      if ip netns exec client3_ns curl -fsS --connect-timeout 3 --max-time 5 -o /dev/null http://10.0.0.1:8080/; then
        echo "$(date +%s) OK" >> "$ARTIFACT_DIR/short_conn.log"
      else
        echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/short_conn.log"
      fi &
    done
    for _ in $(seq 1 "$SHORT_PARALLEL"); do
      if ip netns exec client4_ns curl -fsS --connect-timeout 3 --max-time 5 -o /dev/null http://10.0.0.1:8080/; then
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
    if ip netns exec client1_ns python3 - <<'PY'
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
    if ip netns exec client3_ns python3 - <<'PY'
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
    if ip netns exec client4_ns python3 - <<'PY'
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
    if ip netns exec client1_ns ping -c 1 -W 2 10.0.2.2 >/dev/null; then
      echo "$(date +%s) OK" >> "$ARTIFACT_DIR/ping.log"
    else
      echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/ping.log"
    fi
    if ip netns exec client2_ns ping -c 1 -W 2 10.0.2.2 >/dev/null; then
      echo "$(date +%s) OK" >> "$ARTIFACT_DIR/ping.log"
    else
      echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/ping.log"
    fi
    if ip netns exec client3_ns ping -c 1 -W 2 10.0.2.2 >/dev/null; then
      echo "$(date +%s) OK" >> "$ARTIFACT_DIR/ping.log"
    else
      echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/ping.log"
    fi
    if ip netns exec client4_ns ping -c 1 -W 2 10.0.2.2 >/dev/null; then
      echo "$(date +%s) OK" >> "$ARTIFACT_DIR/ping.log"
    else
      echo "$(date +%s) FAIL" >> "$ARTIFACT_DIR/ping.log"
    fi
    sleep 2
  done
}

echo "=== [5/7] Starting background traffic for ${DURATION}s ==="
START_TS="$(date +%s)"
# Long TCP MUST run from client workload namespaces so connections enter the
# client gateway and are routed through TUN/smoltcp -> QUIC pool.
ip netns exec client1_work_ns python3 "$ROOT_DIR/script/acceptance/stability_long_tcp.py" --duration "$DURATION" --workers "$LONG_WORKERS" --stats-out "$ARTIFACT_DIR/long_tcp_stats.json" > "$ARTIFACT_DIR/long_tcp.log" 2>&1 &
LONG_PID=$!
ip netns exec client2_work_ns python3 "$ROOT_DIR/script/acceptance/stability_long_tcp.py" --duration "$DURATION" --workers "$LONG_WORKERS" --stats-out "$ARTIFACT_DIR/long_tcp2_stats.json" > "$ARTIFACT_DIR/long_tcp2.log" 2>&1 &
LONG2_PID=$!
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
wait "$LONG2_PID" || true
wait "$SHORT_PID" || true
wait "$UDP_PID" || true
wait "$PING_PID" || true

echo "=== [7/7] Generating report ==="
REPORT_PATH="$(python3 "$ROOT_DIR/script/acceptance/stability_report.py" "$ARTIFACT_DIR")"
echo "Artifacts: $ARTIFACT_DIR"
echo "Report: $REPORT_PATH"
