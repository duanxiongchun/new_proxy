#!/usr/bin/env bash
set -euo pipefail

SCENARIO=dns_policy
source "$(dirname "$0")/lib.sh"

mkdir -p "$ARTIFACT_DIR"
printf 'google.com\n' >"$ARTIFACT_DIR/remote-domains.txt"

CLIENT_DNS_SECTION=$'[DNS]\nListen=10.30.1.53:53\nLocalResolver=10.30.1.2:53\nRemoteResolver=10.20.1.2:53\nRemoteDomainsFile='"$ARTIFACT_DIR"$'/remote-domains.txt\nTransactionCapacity=128\nTimeoutSeconds=5'

require_root
trap cleanup EXIT INT TERM
cleanup
set -e
setup_standard_topology
ip -n "$CLIENT_NS" addr add 10.30.1.53/32 dev ci0
start_runtime

ip -n "$SOURCE_NS" neigh replace 10.30.1.53 \
  lladdr "$CLIENT_INTERCEPT_MAC" nud permanent dev sw0

ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  dns-server \
  --bind 10.30.1.2 \
  --port 53 \
  --answer 198.51.100.10 \
  --log "$ARTIFACT_DIR/local-dns.log" \
  --tag local >"$ARTIFACT_DIR/local-dns-server.log" 2>&1 &
EXTRA_PIDS+=("$!")

ip netns exec "$TARGET_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  dns-server \
  --bind 10.20.1.2 \
  --port 53 \
  --answer 203.0.113.10 \
  --log "$ARTIFACT_DIR/remote-dns.log" \
  --tag remote >"$ARTIFACT_DIR/remote-dns-server.log" 2>&1 &
EXTRA_PIDS+=("$!")

ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" dns-client \
  --server 10.30.1.53 \
  --domain local.test \
  --expect-address 198.51.100.10 \
  --expect-peer 10.30.1.53

ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" dns-client \
  --server 10.30.1.53 \
  --domain www.google.com \
  --expect-address 203.0.113.10 \
  --expect-peer 10.30.1.53

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
