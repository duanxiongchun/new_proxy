#!/usr/bin/env python3
import argparse
import json
import os
import socket
import threading
import time


def worker(idx, host, port, duration, payload_size, interval, stats, lock):
    deadline = time.monotonic() + duration
    sock = None
    while time.monotonic() < deadline:
        try:
            if sock is None:
                sock = socket.create_connection((host, port), timeout=5)
                sock.settimeout(5)
                with lock:
                    stats["connections"] += 1
            payload = os.urandom(payload_size)
            sock.sendall(payload)
            data = sock.recv(max(2, payload_size + 2))
            if not data:
                raise OSError("peer closed")
            with lock:
                stats["sent_bytes"] += len(payload)
                stats["received_bytes"] += len(data)
                stats["iterations"] += 1
            sleep_for = max(0.0, interval - 0.001)
            time.sleep(sleep_for)
        except Exception as exc:
            with lock:
                stats["errors"] += 1
                if len(stats["last_errors"]) < 20:
                    stats["last_errors"].append(f"worker {idx}: {exc}")
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            sock = None
            with lock:
                stats["reconnects"] += 1
            time.sleep(0.25)
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="10.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--payload-size", type=int, default=1024)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--stats-out", required=True)
    args = parser.parse_args()

    stats = {
        "connections": 0,
        "reconnects": 0,
        "iterations": 0,
        "sent_bytes": 0,
        "received_bytes": 0,
        "errors": 0,
        "last_errors": [],
    }
    lock = threading.Lock()
    threads = [
        threading.Thread(
            target=worker,
            args=(i, args.host, args.port, args.duration, args.payload_size, args.interval, stats, lock),
        )
        for i in range(args.threads)
    ]
    started = int(time.time())
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stats["started_at"] = started
    stats["finished_at"] = int(time.time())
    stats["duration_seconds"] = stats["finished_at"] - started
    with open(args.stats_out, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, sort_keys=True)
        f.write("\n")
    raise SystemExit(1 if stats["errors"] else 0)


if __name__ == "__main__":
    main()
