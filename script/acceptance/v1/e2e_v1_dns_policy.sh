#!/usr/bin/env bash
set -euo pipefail

SCENARIO=dns_policy
source "$(dirname "$0")/lib.sh"

mkdir -p "$ARTIFACT_DIR"
printf 'google.com\n' >"$ARTIFACT_DIR/remote-domains.txt"
printf '8.8.8.10/32\n' >"$ARTIFACT_DIR/direct-cidrs.txt"
CLIENT_ALLOWED_IPS_PREFIXES="!file:$ARTIFACT_DIR/direct-cidrs.txt"

CLIENT_DNS_SECTION=$'[DNS]\nListen=10.30.1.53:53\nLocalResolver=10.30.1.2:53\nRemoteResolver=10.20.1.2:53\nRemoteDomainsFile='"$ARTIFACT_DIR"$'/remote-domains.txt\nTransactionCapacity=128\nTimeoutSeconds=5'

require_root
trap cleanup EXIT INT TERM
cleanup
set -e
setup_standard_topology
ip -n "$CLIENT_NS" addr add 10.30.1.53/32 dev ci0
ip -n "$CLIENT_NS" addr add 8.8.8.10/32 dev ci0
ip -n "$SOURCE_NS" route add 8.8.8.10/32 via 10.30.1.1 dev sw0
start_runtime

ip -n "$SOURCE_NS" neigh replace 10.30.1.53 \
  lladdr "$CLIENT_INTERCEPT_MAC" nud permanent dev sw0

ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  dns-server \
  --bind 10.30.1.2 \
  --port 53 \
  --answer 8.8.8.10 \
  --log "$ARTIFACT_DIR/local-dns.log" \
  --tag local \
  --ready "$ARTIFACT_DIR/local-dns.ready" \
  >"$ARTIFACT_DIR/local-dns-server.log" 2>&1 &
EXTRA_PIDS+=("$!")
wait_for_ready "$ARTIFACT_DIR/local-dns.ready" "${EXTRA_PIDS[-1]}" \
  "$ARTIFACT_DIR/local-dns-server.log"

ip netns exec "$TARGET_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  dns-server \
  --bind 10.20.1.2 \
  --port 53 \
  --answer 8.8.8.10 \
  --log "$ARTIFACT_DIR/remote-dns.log" \
  --tag remote \
  --ready "$ARTIFACT_DIR/remote-dns.ready" \
  >"$ARTIFACT_DIR/remote-dns-server.log" 2>&1 &
EXTRA_PIDS+=("$!")
wait_for_ready "$ARTIFACT_DIR/remote-dns.ready" "${EXTRA_PIDS[-1]}" \
  "$ARTIFACT_DIR/remote-dns-server.log"

ip netns exec "$CLIENT_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  server --bind-ipv4 8.8.8.10 --log "$ARTIFACT_DIR/direct-target.log" \
  --ready "$ARTIFACT_DIR/direct-target.ready" \
  >"$ARTIFACT_DIR/direct-target-server.log" 2>&1 &
EXTRA_PIDS+=("$!")
wait_for_ready "$ARTIFACT_DIR/direct-target.ready" "${EXTRA_PIDS[-1]}" \
  "$ARTIFACT_DIR/direct-target-server.log"

ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" dns-client \
  --server 10.30.1.53 \
  --domain local.test \
  --expect-address 8.8.8.10 \
  --expect-peer 10.30.1.53

remote_answer="$(ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" dns-client \
  --server 10.30.1.53 \
  --domain www.google.com \
  --expect-address 8.8.8.10 \
  --expect-peer 10.30.1.53)"

wait_for_json "$CLIENT_STATS" \
  'sum(worker["dns_response_remote"] for worker in value["flow_workers"]) >= 1'
wait_for_json "$SERVER_STATS" \
  'sum(worker["session_count"] for worker in value["flow_workers"]) >= 1 and sum(worker["nat_count"] for worker in value["flow_workers"]) >= 1'
client_sessions_before="$(read_stats_metric "$CLIENT_STATS" 'sum(worker["session_count"] for worker in value["flow_workers"])')"
client_nat_before="$(read_stats_metric "$CLIENT_STATS" 'sum(worker["nat_count"] for worker in value["flow_workers"])')"
server_sessions_before="$(read_stats_metric "$SERVER_STATS" 'sum(worker["session_count"] for worker in value["flow_workers"])')"
server_nat_before="$(read_stats_metric "$SERVER_STATS" 'sum(worker["nat_count"] for worker in value["flow_workers"])')"
client_sequence_before="$(read_stats_metric "$CLIENT_STATS" 'value["sequence"]')"
server_sequence_before="$(read_stats_metric "$SERVER_STATS" 'value["sequence"]')"
ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" client \
  --tag dns-answer-static-policy \
  --address "$remote_answer"
wait_for_json "$CLIENT_STATS" \
  "value[\"sequence\"] > $client_sequence_before and sum(worker[\"session_count\"] for worker in value[\"flow_workers\"]) == $client_sessions_before and sum(worker[\"nat_count\"] for worker in value[\"flow_workers\"]) == $client_nat_before"
wait_for_json "$SERVER_STATS" \
  "value[\"sequence\"] > $server_sequence_before and sum(worker[\"session_count\"] for worker in value[\"flow_workers\"]) == $server_sessions_before and sum(worker[\"nat_count\"] for worker in value[\"flow_workers\"]) == $server_nat_before"
python3 - "$ARTIFACT_DIR/direct-target.log" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
for protocol in ("tcp4", "udp4"):
    matches = [
        record
        for record in records
        if record["protocol"] == protocol
    ]
    if not matches:
        raise SystemExit(f"direct target did not observe {protocol}: {records!r}")
    if {record["peer"] for record in matches} != {"10.30.1.2"}:
        raise SystemExit(f"{protocol} did not preserve source address: {matches!r}")
PY

kill -TERM "${EXTRA_PIDS[1]}"
wait "${EXTRA_PIDS[1]}" 2>/dev/null || true

ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" dns-client \
  --server 10.30.1.53 \
  --domain timeout.google.com \
  --expect-rcode 2 \
  --expect-peer 10.30.1.53 \
  --timeout 7 \
  --retries 2

python3 - "$ARTIFACT_DIR/local-dns.log" "$ARTIFACT_DIR/remote-dns.log" <<'PY'
import json
import sys

local_records = [
    json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()
]
remote_records = [
    json.loads(line) for line in open(sys.argv[2], encoding="utf-8") if line.strip()
]

if not any(record["qname"] == "local.test" for record in local_records):
    raise SystemExit(f"local resolver did not receive local.test: {local_records!r}")
if not any(record["peer"] == "10.30.1.1" for record in local_records):
    raise SystemExit(f"local resolver did not observe client SNAT: {local_records!r}")
if any(record["qname"] == "www.google.com" for record in local_records):
    raise SystemExit(f"remote domain leaked to local resolver: {local_records!r}")

if not any(record["qname"] == "www.google.com" for record in remote_records):
    raise SystemExit(f"remote resolver did not receive www.google.com: {remote_records!r}")
if not any(record["peer"] == "10.20.1.1" for record in remote_records):
    raise SystemExit(f"remote resolver did not observe server SNAT: {remote_records!r}")
if any(record["qname"] == "local.test" for record in remote_records):
    raise SystemExit(f"local domain leaked to remote resolver: {remote_records!r}")
PY

wait_for_json "$CLIENT_STATS" \
  'sum(worker["dns_query_local"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_query_remote"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_response_local"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_response_remote"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_servfail"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_timeout"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_transactions_active"] for worker in value["flow_workers"]) == 0'

wait_for_json "$SERVER_STATS" \
  'sum(worker["dns_query_local"] + worker["dns_query_remote"] + worker["dns_transactions_active"] for worker in value["flow_workers"]) == 0'
