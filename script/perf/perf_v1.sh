#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUN_V1_PERF:-0}" != "1" ]]; then
  echo "Set RUN_V1_PERF=1 to run the v1 performance baseline." >&2
  exit 2
fi

SCENARIO=perf
V1_TARGET_LOG_EVERY="${V1_TARGET_LOG_EVERY:-100}"
source "$(dirname "$0")/../acceptance/v1/lib.sh"

PERF_ITERATIONS="${V1_PERF_ITERATIONS:-100}"
PERF_MAX_P99_MS="${V1_PERF_MAX_P99_MS:-250}"
PERF_LOAD_SECONDS="${V1_PERF_LOAD_SECONDS:-10}"
PERF_LOAD_CONCURRENCY="${V1_PERF_LOAD_CONCURRENCY:-8}"
PERF_LOAD_WINDOW="${V1_PERF_LOAD_WINDOW:-32}"
PERF_LOAD_PAYLOAD_SIZE="${V1_PERF_LOAD_PAYLOAD_SIZE:-1200}"
PERF_MIN_MBIT_PER_SECOND="${V1_PERF_MIN_MBIT_PER_SECOND:-0.1}"

setup_runtime standard
capture_success_baseline

start_ns="$(date +%s%N)"
ip netns exec "$SOURCE_NS" python3 - "$PERF_ITERATIONS" "$PERF_MAX_P99_MS" <<'PY'
import math
import socket
import sys
import time

iterations = int(sys.argv[1])
maximum_p99_ms = float(sys.argv[2])
if iterations < 2:
    raise SystemExit("performance baseline requires at least two iterations")
results = {}
for family, address, suffix in [
    (socket.AF_INET, "10.20.1.2", "4"),
    (socket.AF_INET6, "2001:db8:20::2", "6"),
]:
    for socket_type, port, protocol in [
        (socket.SOCK_STREAM, 8080, "tcp"),
        (socket.SOCK_DGRAM, 8081, "udp"),
    ]:
        samples = []
        for sequence in range(iterations):
            payload = f"perf-{protocol}{suffix}-{sequence}".encode()
            sock = socket.socket(family, socket_type)
            sock.settimeout(5)
            started = time.perf_counter_ns()
            sock.connect((address, port))
            if socket_type == socket.SOCK_STREAM:
                sock.sendall(payload)
                received = sock.recv(4096)
            else:
                sock.send(payload)
                received = sock.recv(4096)
            samples.append((time.perf_counter_ns() - started) / 1_000_000)
            sock.close()
            if received != payload:
                raise SystemExit(f"echo mismatch for {protocol}{suffix}")
        samples.sort()
        p50 = samples[len(samples) // 2]
        p99 = samples[max(0, math.ceil(len(samples) * 0.99) - 1)]
        results[f"{protocol}{suffix}"] = {"p50_ms": p50, "p99_ms": p99}

for name, values in results.items():
    print(f"{name}: p50={values['p50_ms']:.3f}ms p99={values['p99_ms']:.3f}ms")
    if values["p99_ms"] > maximum_p99_ms:
        raise SystemExit(
            f"{name} p99 {values['p99_ms']:.3f}ms exceeds "
            f"{maximum_p99_ms:.3f}ms"
        )
PY
load_result="$(
  ip netns exec "$SOURCE_NS" timeout "$((PERF_LOAD_SECONDS + 10))s" \
    python3 "$ROOT_DIR/script/acceptance/v1/traffic.py" load-client \
    --duration "$PERF_LOAD_SECONDS" \
    --concurrency "$PERF_LOAD_CONCURRENCY" \
    --payload-size "$PERF_LOAD_PAYLOAD_SIZE" \
    --window "$PERF_LOAD_WINDOW"
)"
printf 'windowed concurrent load: %s\n' "$load_result"
python3 - "$load_result" "$PERF_MIN_MBIT_PER_SECOND" <<'PY'
import json
import sys

result = json.loads(sys.argv[1])
minimum = float(sys.argv[2])
if result["mbit_per_second"] < minimum:
    raise SystemExit(
        f"throughput {result['mbit_per_second']:.3f} Mbit/s is below "
        f"{minimum:.3f} Mbit/s"
    )
PY
end_ns="$(date +%s%N)"

assert_success_counters_unchanged
assert_target_snat
assert_runtime_state 4

python3 - "$CLIENT_STATS" "$SERVER_STATS" <<'PY'
import json
import sys

for role, path in zip(("client", "server"), sys.argv[1:]):
    value = json.load(open(path, encoding="utf-8"))
    print(f"{role} IO queues:")
    for owner in value["io_owners"]:
        print(
            "  "
            f"ifindex={owner['ifindex']} queue={owner['queue_id']} "
            f"rx={owner['rx_frames']} tx={owner['tx_frames']} "
            f"drops={owner['dropped_frames'] + owner['tx_drops']}"
        )
PY

elapsed_ms="$(( (end_ns - start_ns) / 1000000 ))"
printf 'v1 performance baseline completed: iterations=%s elapsed_ms=%s\n' \
  "$PERF_ITERATIONS" "$elapsed_ms"
