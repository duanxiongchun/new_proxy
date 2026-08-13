#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN="${V1_BIN:-$ROOT_DIR/target/release/new_proxy}"
SCENARIO="${SCENARIO:-v1}"
TOKEN="v1$$_"
ARTIFACT_DIR="${V1_ARTIFACT_DIR:-/tmp/new_proxy_${SCENARIO}_$$}"
CLIENT_NS="${TOKEN}c"
TRANSIT_NS="${TOKEN}r"
SERVER_NS="${TOKEN}s"
SOURCE_NS="${TOKEN}w"
SOURCE2_NS="${TOKEN}x"
TARGET_NS="${TOKEN}t"
CLIENT_PID=""
SERVER_PID=""
TARGET_PID=""
EXTRA_PIDS=()
CLIENT_STATS="$ARTIFACT_DIR/client-stats.json"
SERVER_STATS="$ARTIFACT_DIR/server-stats.json"
CLIENT_TUNNEL_MAC="02:00:00:00:10:01"
SERVER_TUNNEL_MAC="02:00:00:00:10:02"
CLIENT_INTERCEPT_MAC="02:00:00:00:30:01"
SOURCE_MAC="02:00:00:00:30:02"
CLIENT_INTERCEPT2_MAC="02:00:00:00:31:01"
SOURCE2_MAC="02:00:00:00:31:02"
SERVER_INTERCEPT_MAC="02:00:00:00:20:01"
TARGET_MAC="02:00:00:00:20:02"
SHARED_KEY="0101010101010101010101010101010101010101010101010101010101010101"
FLOW_WORKER_COUNT="${V1_FLOW_WORKER_COUNT:-1}"
CHANNEL_CAPACITY="${V1_CHANNEL_CAPACITY:-8192}"
CLIENT_ALLOWED_IPS_PREFIXES="${CLIENT_ALLOWED_IPS_PREFIXES:-10.20.1.0/24,2001:db8:20::/64}"
SERVER_ALLOWED_IPS_PREFIXES="${SERVER_ALLOWED_IPS_PREFIXES:-10.30.0.0/15,2001:db8:30::/47}"

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "v1 E2E requires root" >&2
    exit 1
  fi
  for command in bpftool ip mount openssl python3 timeout unshare; do
    command -v "$command" >/dev/null || {
      echo "missing required command: $command" >&2
      exit 1
    }
  done
  if [[ ! -x "$BIN" ]] || ! "$BIN" --help 2>&1 | grep -q 'Usage: new_proxy'; then
    echo "missing or stale v1 release binary; run: cargo build --release --bin new_proxy" >&2
    exit 1
  fi
}

cleanup() {
  set +e
  for pid in "$CLIENT_PID" "$SERVER_PID" "$TARGET_PID" "${EXTRA_PIDS[@]}"; do
    if [[ -n "$pid" ]]; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  sleep 0.2
  for pid in "$CLIENT_PID" "$SERVER_PID" "$TARGET_PID" "${EXTRA_PIDS[@]}"; do
    if [[ -n "$pid" ]]; then
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  for namespace in "$CLIENT_NS" "$TRANSIT_NS" "$SERVER_NS" "$SOURCE_NS" "$SOURCE2_NS" "$TARGET_NS"; do
    ip netns delete "$namespace" 2>/dev/null || true
  done
}

create_veth() {
  local left_name="$1"
  local left_ns="$2"
  local left_final="$3"
  local right_name="$4"
  local right_ns="$5"
  local right_final="$6"
  ip link add "$left_name" type veth peer name "$right_name"
  ip link set "$left_name" netns "$left_ns"
  ip link set "$right_name" netns "$right_ns"
  ip -n "$left_ns" link set "$left_name" name "$left_final"
  ip -n "$right_ns" link set "$right_name" name "$right_final"
}

configure_link() {
  local namespace="$1"
  local interface="$2"
  local mac="$3"
  ip -n "$namespace" link set "$interface" address "$mac"
  ip -n "$namespace" link set "$interface" up
  ip netns exec "$namespace" ethtool -K "$interface" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
}

setup_namespaces() {
  for namespace in "$CLIENT_NS" "$TRANSIT_NS" "$SERVER_NS" "$SOURCE_NS" "$TARGET_NS"; do
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
  done
}

setup_standard_topology() {
  setup_namespaces
  create_veth "${TOKEN}ct" "$CLIENT_NS" ct0 "${TOKEN}rc" "$TRANSIT_NS" rc0
  create_veth "${TOKEN}st" "$SERVER_NS" st0 "${TOKEN}rs" "$TRANSIT_NS" rs0
  create_veth "${TOKEN}ci" "$CLIENT_NS" ci0 "${TOKEN}sw" "$SOURCE_NS" sw0
  create_veth "${TOKEN}si" "$SERVER_NS" si0 "${TOKEN}tg" "$TARGET_NS" tg0
  ip -n "$TRANSIT_NS" link add br0 type bridge
  ip -n "$TRANSIT_NS" link set br0 up
  ip -n "$TRANSIT_NS" link set rc0 master br0
  ip -n "$TRANSIT_NS" link set rs0 master br0
  configure_link "$CLIENT_NS" ct0 "$CLIENT_TUNNEL_MAC"
  configure_link "$SERVER_NS" st0 "$SERVER_TUNNEL_MAC"
  configure_link "$CLIENT_NS" ci0 "$CLIENT_INTERCEPT_MAC"
  configure_link "$SOURCE_NS" sw0 "$SOURCE_MAC"
  configure_link "$SERVER_NS" si0 "$SERVER_INTERCEPT_MAC"
  configure_link "$TARGET_NS" tg0 "$TARGET_MAC"
  ip -n "$TRANSIT_NS" link set rc0 up
  ip -n "$TRANSIT_NS" link set rs0 up
  ip -n "$CLIENT_NS" addr add 10.10.0.1/24 dev ct0
  ip -n "$SERVER_NS" addr add 10.10.0.2/24 dev st0
  ip -n "$CLIENT_NS" addr add 10.30.1.1/24 dev ci0
  ip -n "$CLIENT_NS" addr add 2001:db8:30::1/64 dev ci0 nodad
  ip -n "$SOURCE_NS" addr add 10.30.1.2/24 dev sw0
  ip -n "$SOURCE_NS" addr add 2001:db8:30::2/64 dev sw0 nodad
  ip -n "$SERVER_NS" addr add 10.20.1.1/24 dev si0
  ip -n "$SERVER_NS" addr add 2001:db8:20::1/64 dev si0 nodad
  ip -n "$TARGET_NS" addr add 10.20.1.2/24 dev tg0
  ip -n "$TARGET_NS" addr add 2001:db8:20::2/64 dev tg0 nodad
  ip -n "$SOURCE_NS" route add 10.20.1.0/24 via 10.30.1.1 dev sw0
  ip -n "$SOURCE_NS" -6 route add 2001:db8:20::/64 via 2001:db8:30::1 dev sw0
  ip -n "$SOURCE_NS" neigh replace 10.30.1.1 lladdr "$CLIENT_INTERCEPT_MAC" dev sw0
  ip -n "$SOURCE_NS" -6 neigh replace 2001:db8:30::1 lladdr "$CLIENT_INTERCEPT_MAC" dev sw0
  configure_target_neighbors
  CLIENT_TUNNEL_INTERFACE="ct0"
  CLIENT_INTERCEPTS=$'[Intercept]\nInterface=ci0\nNextHopMac='"$SOURCE_MAC"
  CLIENT_NAT_V4="10.30.1.1"
  CLIENT_NAT_V6="2001:db8:30::1"
}

setup_same_interface_topology() {
  setup_namespaces
  create_veth "${TOKEN}ca" "$CLIENT_NS" ca0 "${TOKEN}rc" "$TRANSIT_NS" rc0
  create_veth "${TOKEN}st" "$SERVER_NS" st0 "${TOKEN}rs" "$TRANSIT_NS" rs0
  create_veth "${TOKEN}sw" "$SOURCE_NS" sw0 "${TOKEN}rw" "$TRANSIT_NS" rw0
  create_veth "${TOKEN}si" "$SERVER_NS" si0 "${TOKEN}tg" "$TARGET_NS" tg0
  ip -n "$TRANSIT_NS" link add br0 type bridge
  ip -n "$TRANSIT_NS" link set br0 up
  for interface in rc0 rs0 rw0; do
    ip -n "$TRANSIT_NS" link set "$interface" master br0
    ip -n "$TRANSIT_NS" link set "$interface" up
  done
  configure_link "$CLIENT_NS" ca0 "$CLIENT_TUNNEL_MAC"
  configure_link "$SERVER_NS" st0 "$SERVER_TUNNEL_MAC"
  configure_link "$SOURCE_NS" sw0 "$SOURCE_MAC"
  configure_link "$SERVER_NS" si0 "$SERVER_INTERCEPT_MAC"
  configure_link "$TARGET_NS" tg0 "$TARGET_MAC"
  ip -n "$CLIENT_NS" addr add 10.10.0.1/24 dev ca0
  ip -n "$CLIENT_NS" addr add 2001:db8:10::1/64 dev ca0 nodad
  ip -n "$SERVER_NS" addr add 10.10.0.2/24 dev st0
  ip -n "$SERVER_NS" addr add 2001:db8:10::2/64 dev st0 nodad
  ip -n "$SOURCE_NS" addr add 10.10.0.100/24 dev sw0
  ip -n "$SOURCE_NS" addr add 2001:db8:10::100/64 dev sw0 nodad
  ip -n "$SERVER_NS" addr add 10.20.1.1/24 dev si0
  ip -n "$SERVER_NS" addr add 2001:db8:20::1/64 dev si0 nodad
  ip -n "$TARGET_NS" addr add 10.20.1.2/24 dev tg0
  ip -n "$TARGET_NS" addr add 2001:db8:20::2/64 dev tg0 nodad
  ip -n "$SOURCE_NS" route add 10.20.1.0/24 via 10.10.0.1 dev sw0
  ip -n "$SOURCE_NS" -6 route add 2001:db8:20::/64 via 2001:db8:10::1 dev sw0
  ip -n "$SOURCE_NS" neigh replace 10.10.0.1 lladdr "$CLIENT_TUNNEL_MAC" dev sw0
  ip -n "$SOURCE_NS" -6 neigh replace 2001:db8:10::1 lladdr "$CLIENT_TUNNEL_MAC" dev sw0
  configure_target_neighbors
  CLIENT_TUNNEL_INTERFACE="ca0"
  CLIENT_INTERCEPTS=$'[Intercept]\nInterface=ca0\nNextHopMac='"$SOURCE_MAC"
  CLIENT_NAT_V4="10.10.0.1"
  CLIENT_NAT_V6="2001:db8:10::1"
}

add_second_intercept() {
  ip netns add "$SOURCE2_NS"
  ip -n "$SOURCE2_NS" link set lo up
  create_veth "${TOKEN}cj" "$CLIENT_NS" ci1 "${TOKEN}sx" "$SOURCE2_NS" sx0
  configure_link "$CLIENT_NS" ci1 "$CLIENT_INTERCEPT2_MAC"
  configure_link "$SOURCE2_NS" sx0 "$SOURCE2_MAC"
  ip -n "$CLIENT_NS" addr add 10.31.1.1/24 dev ci1
  ip -n "$CLIENT_NS" addr add 2001:db8:31::1/64 dev ci1 nodad
  ip -n "$SOURCE2_NS" addr add 10.31.1.2/24 dev sx0
  ip -n "$SOURCE2_NS" addr add 2001:db8:31::2/64 dev sx0 nodad
  ip -n "$SOURCE2_NS" route add 10.20.1.0/24 via 10.31.1.1 dev sx0
  ip -n "$SOURCE2_NS" -6 route add 2001:db8:20::/64 via 2001:db8:31::1 dev sx0
  ip -n "$SOURCE2_NS" neigh replace 10.31.1.1 lladdr "$CLIENT_INTERCEPT2_MAC" dev sx0
  ip -n "$SOURCE2_NS" -6 neigh replace 2001:db8:31::1 lladdr "$CLIENT_INTERCEPT2_MAC" dev sx0
  CLIENT_INTERCEPTS+=$'\n[Intercept.2]\nInterface=ci1\nNextHopMac='"$SOURCE2_MAC"
}

configure_target_neighbors() {
  ip -n "$TARGET_NS" neigh replace 10.20.1.1 lladdr "$SERVER_INTERCEPT_MAC" dev tg0
  ip -n "$TARGET_NS" -6 neigh replace 2001:db8:20::1 lladdr "$SERVER_INTERCEPT_MAC" dev tg0
}

generate_certificate() {
  openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=new-proxy-v1 \
    -keyout "$ARTIFACT_DIR/server-key.pem" -out "$ARTIFACT_DIR/server-cert.pem" \
    -days 1 >/dev/null 2>&1
  openssl x509 -in "$ARTIFACT_DIR/server-cert.pem" -outform DER \
    -out "$ARTIFACT_DIR/server-cert.der"
  openssl pkcs8 -topk8 -nocrypt -in "$ARTIFACT_DIR/server-key.pem" -outform DER \
    -out "$ARTIFACT_DIR/server-key.der"
  CERTIFICATE_SHA256="$(openssl dgst -sha256 "$ARTIFACT_DIR/server-cert.der" | awk '{print $2}')"
}

write_configs() {
  cat >"$ARTIFACT_DIR/client.conf" <<EOF
[Appliance]
Role=client
FlowWorkerCount=$FLOW_WORKER_COUNT
ChannelCapacity=$CHANNEL_CAPACITY
DcidLength=8
StatsPath=$CLIENT_STATS
SharedKey=$SHARED_KEY

[Tunnel]
Interface=$CLIENT_TUNNEL_INTERFACE
Endpoint=10.10.0.2:4433
NextHopMac=$SERVER_TUNNEL_MAC
ServerCertificateSha256=$CERTIFICATE_SHA256

$CLIENT_INTERCEPTS

[NAT]
AddressV4=$CLIENT_NAT_V4
AddressV6=$CLIENT_NAT_V6
PortStart=40000
PortEnd=49999

${CLIENT_DNS_SECTION:-}
[AllowedIPs]
Prefixes=$CLIENT_ALLOWED_IPS_PREFIXES

[XDP]
Mode=skb
EOF
  cat >"$ARTIFACT_DIR/server.conf" <<EOF
[Appliance]
Role=server
FlowWorkerCount=$FLOW_WORKER_COUNT
ChannelCapacity=$CHANNEL_CAPACITY
DcidLength=8
StatsPath=$SERVER_STATS
SharedKey=$SHARED_KEY

[Tunnel]
Interface=st0
Listen=10.10.0.2:4433
NextHopMac=$CLIENT_TUNNEL_MAC
ServerCertificate=$ARTIFACT_DIR/server-cert.der
ServerPrivateKey=$ARTIFACT_DIR/server-key.der

[Intercept]
Interface=si0
NextHopMac=$TARGET_MAC

[NAT]
AddressV4=10.20.1.1
AddressV6=2001:db8:20::1
PortStart=50000
PortEnd=59999

[XDP]
Mode=skb
EOF
}

start_in_namespace() {
  local namespace="$1"
  local config="$2"
  local log="$3"
  ip netns exec "$namespace" unshare -m -- bash -c \
    'mount --make-rprivate /; umount /sys/fs/bpf 2>/dev/null || true; mount -t bpf bpf /sys/fs/bpf; cd "$1"; exec env RUST_LOG=new_proxy=trace "$2" --config "$3"' \
    bash "$ARTIFACT_DIR" "$BIN" "$config" >"$log" 2>&1 &
  local launcher_pid=$!
  for _ in $(seq 1 100); do
    local daemon_pid
    daemon_pid="$(find_daemon_pid "$config")"
    if [[ -n "$daemon_pid" ]]; then
      echo "$daemon_pid"
      return 0
    fi
    if ! kill -0 "$launcher_pid" 2>/dev/null; then
      wait "$launcher_pid" 2>/dev/null || true
      cat "$log" >&2
      return 1
    fi
    sleep 0.01
  done
  echo "timed out waiting for daemon process using config: $config" >&2
  kill -TERM "$launcher_pid" 2>/dev/null || true
  return 1
}

find_daemon_pid() {
  local config="$1"
  python3 - "$BIN" "$config" <<'PY'
import glob
import os
import sys

binary = os.path.realpath(sys.argv[1])
config = os.path.realpath(sys.argv[2])
for path in glob.glob("/proc/[0-9]*/cmdline"):
    try:
        arguments = open(path, "rb").read().split(b"\0")
        arguments = [argument.decode() for argument in arguments if argument]
        if not arguments or os.path.realpath(arguments[0]) != binary:
            continue
        for index, argument in enumerate(arguments[:-1]):
            if argument in ("-config", "--config") and os.path.realpath(arguments[index + 1]) == config:
                print(path.split("/")[2])
                raise SystemExit(0)
    except (FileNotFoundError, PermissionError, ProcessLookupError, UnicodeDecodeError):
        continue
PY
}

kill_daemon_and_wait() {
  local pid="$1"
  local config="$2"
  kill -KILL "$pid"
  for _ in $(seq 1 100); do
    if [[ -z "$(find_daemon_pid "$config")" ]]; then
      return 0
    fi
    sleep 0.01
  done
  echo "daemon did not exit after SIGKILL: pid=$pid config=$config" >&2
  return 1
}

wait_for_json() {
  local path="$1"
  local expression="$2"
  for _ in $(seq 1 100); do
    if [[ -s "$path" ]] && python3 - "$path" "$expression" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
safe = {
    "__builtins__": {},
    "all": all,
    "len": len,
    "str": str,
    "sum": sum,
    "value": value,
}
if not eval(sys.argv[2], safe, {}):
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for stats expression: $expression" >&2
  [[ -f "$path" ]] && cat "$path" >&2
  return 1
}

assert_daemon_running() {
  local pid="$1"
  local log="$2"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "new_proxy daemon exited during startup" >&2
    cat "$log" >&2
    return 1
  fi
}

start_runtime() {
  generate_certificate
  write_configs
  : >"$ARTIFACT_DIR/target.log"
  ip netns exec "$TARGET_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
    server --log "$ARTIFACT_DIR/target.log" >"$ARTIFACT_DIR/target-server.log" 2>&1 &
  TARGET_PID=$!
  SERVER_PID="$(start_in_namespace "$SERVER_NS" "$ARTIFACT_DIR/server.conf" "$ARTIFACT_DIR/server.log")"
  sleep 0.5
  assert_daemon_running "$SERVER_PID" "$ARTIFACT_DIR/server.log"
  CLIENT_PID="$(start_in_namespace "$CLIENT_NS" "$ARTIFACT_DIR/client.conf" "$ARTIFACT_DIR/client.log")"
  sleep 0.5
  assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client.log"
  wait_for_json "$CLIENT_STATS" \
    "len(value[\"flow_workers\"]) == $FLOW_WORKER_COUNT and all(worker[\"authenticated\"] for worker in value[\"flow_workers\"])" || {
    cat "$ARTIFACT_DIR/client.log" "$ARTIFACT_DIR/server.log" >&2
    return 1
  }
  wait_for_json "$SERVER_STATS" \
    "len(value[\"flow_workers\"]) == $FLOW_WORKER_COUNT and all(worker[\"authenticated\"] for worker in value[\"flow_workers\"])" || {
    cat "$ARTIFACT_DIR/client.log" "$ARTIFACT_DIR/server.log" >&2
    return 1
  }
}

setup_runtime() {
  local mode="${1:-standard}"
  require_root
  mkdir -p "$ARTIFACT_DIR"
  trap cleanup EXIT INT TERM
  cleanup
  set -e
  if [[ "$mode" == "same" ]]; then
    setup_same_interface_topology
  else
    setup_standard_topology
  fi
  if [[ "$mode" == "multi" ]]; then
    add_second_intercept
  fi
  start_runtime
}

exercise_matrix() {
  local namespace="${1:-$SOURCE_NS}"
  local tag="${2:-v1}"
  ip netns exec "$namespace" timeout 20s python3 \
    "$ROOT_DIR/script/acceptance/v1/traffic.py" client --tag "$tag"
  ip netns exec "$namespace" timeout 5s ping -c 1 10.20.1.2 >/dev/null
  ip netns exec "$namespace" timeout 5s ping -6 -c 1 2001:db8:20::2 >/dev/null
}

exercise_large_packets() {
  local namespace="${1:-$SOURCE_NS}"
  ip netns exec "$namespace" timeout 20s python3 \
    "$ROOT_DIR/script/acceptance/v1/traffic.py" client \
    --tag standard-mtu --payload-size 1472
}

exercise_idle_connections() {
  local namespace="${1:-$SOURCE_NS}"
  ip netns exec "$namespace" timeout 30s python3 \
    "$ROOT_DIR/script/acceptance/v1/traffic.py" idle-client --seconds 12
}

assert_target_snat() {
  python3 - "$ARTIFACT_DIR/target.log" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
peers = {record["peer"] for record in records}
if "10.20.1.1" not in peers or "2001:db8:20::1" not in peers:
    raise SystemExit(f"target did not observe both server SNAT addresses: {sorted(peers)}")
PY
}

assert_runtime_state() {
  local minimum_sessions="${1:-6}"
  for path in "$CLIENT_STATS" "$SERVER_STATS"; do
    wait_for_json "$path" \
      "value[\"active_dcid_count\"] > 0 and value[\"reverse_nat_count\"] >= $minimum_sessions and sum(worker[\"session_count\"] for worker in value[\"flow_workers\"]) >= $minimum_sessions and sum(worker[\"nat_count\"] for worker in value[\"flow_workers\"]) >= $minimum_sessions"
  done
}

assert_same_interface_owner() {
  python3 - "$CLIENT_STATS" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
dual = [owner for owner in value["io_owners"] if owner["tunnel"] and owner["intercept"]]
if len(dual) != 1:
    raise SystemExit(f"expected one dual-role IO owner, got {dual!r}")
PY
}

assert_multiple_intercepts() {
  python3 - "$CLIENT_STATS" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
ifindices = {
    session["intercept_ifindex"]
    for worker in value["flow_workers"]
    for session in worker["sessions"]
}
if len(ifindices) < 2:
    raise SystemExit(f"expected sessions from two intercept interfaces, got {ifindices!r}")
PY
}

quic_flow_ids() {
  python3 - "$1" <<'PY'
import json
import sys

print(",".join(str(worker["quic_flow_id"]) for worker in json.load(open(sys.argv[1], encoding="utf-8"))["flow_workers"]))
PY
}

force_reconnect() {
  local old_client
  local old_server
  old_client="$(quic_flow_ids "$CLIENT_STATS")"
  old_server="$(quic_flow_ids "$SERVER_STATS")"
  kill -HUP "$SERVER_PID"
  kill -HUP "$CLIENT_PID"
  wait_for_json "$CLIENT_STATS" \
    "'$old_client' != \",\".join(str(worker[\"quic_flow_id\"]) for worker in value[\"flow_workers\"]) and all(worker[\"session_count\"] == 0 for worker in value[\"flow_workers\"])"
  wait_for_json "$SERVER_STATS" \
    "'$old_server' != \",\".join(str(worker[\"quic_flow_id\"]) for worker in value[\"flow_workers\"]) and all(worker[\"session_count\"] == 0 for worker in value[\"flow_workers\"])"
  wait_for_json "$CLIENT_STATS" 'all(worker["authenticated"] for worker in value["flow_workers"])'
  wait_for_json "$SERVER_STATS" 'all(worker["authenticated"] for worker in value["flow_workers"])'
}
