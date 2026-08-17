#!/usr/bin/env bash
set -euo pipefail

SCENARIO=dns_policy_v6
source "$(dirname "$0")/lib.sh"

mkdir -p "$ARTIFACT_DIR"
printf 'google.com\n' >"$ARTIFACT_DIR/remote-domains.txt"

CLIENT_DNS_SECTION=$'[DNS]\nListen=[2001:db8:30::53]:53\nLocalResolver=[2001:db8:30::2]:53\nRemoteResolver=[2001:db8:20::2]:53\nRemoteDomainsFile='"$ARTIFACT_DIR"$'/remote-domains.txt\nTransactionCapacity=128\nTimeoutSeconds=5'

require_root
trap cleanup EXIT INT TERM
cleanup
set -e
setup_standard_topology
ip -n "$CLIENT_NS" addr add 2001:db8:30::53/128 dev ci0 nodad
start_runtime

ip -n "$SOURCE_NS" -6 neigh replace 2001:db8:30::53 \
  lladdr "$CLIENT_INTERCEPT_MAC" nud permanent dev sw0

ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  dns-server \
  --bind 2001:db8:30::2 \
  --port 53 \
  --answer 198.51.100.10 \
  --log "$ARTIFACT_DIR/local-dns.log" \
  --tag local-v6 \
  --ready "$ARTIFACT_DIR/local-dns.ready" \
  >"$ARTIFACT_DIR/local-dns-server.log" 2>&1 &
EXTRA_PIDS+=("$!")
wait_for_ready "$ARTIFACT_DIR/local-dns.ready" "${EXTRA_PIDS[-1]}" \
  "$ARTIFACT_DIR/local-dns-server.log"

ip netns exec "$TARGET_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  dns-server \
  --bind 2001:db8:20::2 \
  --port 53 \
  --answer 203.0.113.10 \
  --log "$ARTIFACT_DIR/remote-dns.log" \
  --tag remote-v6 \
  --ready "$ARTIFACT_DIR/remote-dns.ready" \
  >"$ARTIFACT_DIR/remote-dns-server.log" 2>&1 &
EXTRA_PIDS+=("$!")
wait_for_ready "$ARTIFACT_DIR/remote-dns.ready" "${EXTRA_PIDS[-1]}" \
  "$ARTIFACT_DIR/remote-dns-server.log"

ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" dns-client \
  --server 2001:db8:30::53 \
  --domain local.test \
  --expect-address 198.51.100.10 \
  --expect-peer 2001:db8:30::53

ip netns exec "$SOURCE_NS" timeout 20s python3 \
  "$ROOT_DIR/script/acceptance/v1/traffic.py" dns-client \
  --server 2001:db8:30::53 \
  --domain www.google.com \
  --expect-address 203.0.113.10 \
  --expect-peer 2001:db8:30::53

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
if not any(record["peer"] == "2001:db8:30::1" for record in local_records):
    raise SystemExit(f"local resolver did not observe client IPv6 SNAT: {local_records!r}")
if any(record["qname"] == "www.google.com" for record in local_records):
    raise SystemExit(f"remote domain leaked to local resolver: {local_records!r}")

if not any(record["qname"] == "www.google.com" for record in remote_records):
    raise SystemExit(f"remote resolver did not receive www.google.com: {remote_records!r}")
if not any(record["peer"] == "2001:db8:20::1" for record in remote_records):
    raise SystemExit(f"remote resolver did not observe server IPv6 SNAT: {remote_records!r}")
if any(record["qname"] == "local.test" for record in remote_records):
    raise SystemExit(f"local domain leaked to remote resolver: {remote_records!r}")
PY

wait_for_json "$CLIENT_STATS" \
  'sum(worker["dns_query_local"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_query_remote"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_response_local"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_response_remote"] for worker in value["flow_workers"]) >= 1 and sum(worker["dns_transactions_active"] for worker in value["flow_workers"]) == 0'

wait_for_json "$SERVER_STATS" \
  'sum(worker["dns_query_local"] + worker["dns_query_remote"] + worker["dns_transactions_active"] for worker in value["flow_workers"]) == 0'

xdp_dns_fragment_before="$(
  read_stats_metric "$CLIENT_STATS" 'value["xdp_dns_fragment_drops"]'
)"
ip netns exec "$SOURCE_NS" python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" \
  xdp-parser-drop \
  --kind dns-ipv6-non-initial-fragment \
  --interface sw0 \
  --source-mac "$SOURCE_MAC" \
  --destination-mac "$CLIENT_INTERCEPT_MAC" \
  --source-ip 2001:db8:30::2 \
  --destination-ip 2001:db8:30::53
wait_for_json "$CLIENT_STATS" \
  "value[\"xdp_dns_fragment_drops\"] > $xdp_dns_fragment_before"
assert_daemon_running "$CLIENT_PID" "$ARTIFACT_DIR/client.log"
