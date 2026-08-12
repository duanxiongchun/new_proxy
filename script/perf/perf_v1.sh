#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUN_V1_PERF:-0}" != "1" ]]; then
  echo "Set RUN_V1_PERF=1 to run the v1 performance baseline." >&2
  exit 2
fi

SCENARIO=perf
source "$(dirname "$0")/../acceptance/v1/lib.sh"

PERF_ITERATIONS="${V1_PERF_ITERATIONS:-100}"

setup_runtime standard

start_ns="$(date +%s%N)"
ip netns exec "$SOURCE_NS" python3 - "$PERF_ITERATIONS" <<'PY'
import socket
import sys
import time

iterations = int(sys.argv[1])
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
        p99 = samples[min(len(samples) - 1, (len(samples) * 99) // 100)]
        results[f"{protocol}{suffix}"] = {"p50_ms": p50, "p99_ms": p99}

for name, values in results.items():
    print(f"{name}: p50={values['p50_ms']:.3f}ms p99={values['p99_ms']:.3f}ms")
PY
end_ns="$(date +%s%N)"

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
