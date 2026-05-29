#!/usr/bin/env python3
import json
import math
import os
import sys


def read_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def count_lines(path, needle=None):
    if not os.path.exists(path):
        return 0
    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if needle is None or needle in line:
                count += 1
    return count


def cv_percent(values):
    if not values or sum(values) == 0:
        return None
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance) / mean * 100.0


def latest_connections(metrics):
    for row in reversed(metrics):
        peers = row.get("telemetry") or []
        conns = []
        for peer in peers:
            conns.extend(peer.get("quic_connections") or [])
        if conns:
            by_port = {}
            for conn in conns:
                port = str(conn.get("local_port"))
                item = by_port.setdefault(port, {"rx_bytes": 0, "tx_bytes": 0, "active_streams": 0})
                item["rx_bytes"] += int(conn.get("rx_bytes") or 0)
                item["tx_bytes"] += int(conn.get("tx_bytes") or 0)
                item["active_streams"] += int(conn.get("active_streams") or 0)
            return by_port
    return {}


def rss_growth(metrics, side):
    samples = [row for row in metrics if row.get(side, {}).get("rss_kib")]
    if not samples:
        return None
    base = None
    started = samples[0]["elapsed_seconds"]
    for row in samples:
        if row["elapsed_seconds"] - started >= 300:
            base = row
            break
    if base is None:
        base = samples[0]
    end = samples[-1]
    base_rss = float(base[side]["rss_kib"])
    end_rss = float(end[side]["rss_kib"])
    growth = 0.0 if base_rss == 0 else (end_rss - base_rss) / base_rss * 100.0
    return base_rss / 1024.0, end_rss / 1024.0, growth


def main():
    if len(sys.argv) != 2:
        print("usage: stability_report.py <artifact_dir>", file=sys.stderr)
        return 2
    artifact_dir = sys.argv[1]
    metrics = read_jsonl(os.path.join(artifact_dir, "stability_metrics.jsonl"))
    long_stats = read_json(os.path.join(artifact_dir, "long_tcp_stats.json"))
    short_ok = count_lines(os.path.join(artifact_dir, "short_conn.log"), "OK")
    short_fail = count_lines(os.path.join(artifact_dir, "short_conn.log"), "FAIL")
    udp_ok = count_lines(os.path.join(artifact_dir, "udp.log"), "OK")
    udp_fail = count_lines(os.path.join(artifact_dir, "udp.log"), "FAIL")
    ping_ok = count_lines(os.path.join(artifact_dir, "ping.log"), "OK")
    ping_fail = count_lines(os.path.join(artifact_dir, "ping.log"), "FAIL")

    conns = latest_connections(metrics)
    totals = {port: item["rx_bytes"] + item["tx_bytes"] for port, item in conns.items()}
    cv = cv_percent(list(totals.values()))
    client_rss = rss_growth(metrics, "client")
    server_rss = rss_growth(metrics, "server")
    crashes = [row for row in metrics if not row.get("client", {}).get("alive") or not row.get("server", {}).get("alive")]

    report_path = os.path.join(artifact_dir, "stability_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Stability Test Report\n\n")
        f.write(f"- Artifact directory: `{artifact_dir}`\n")
        f.write(f"- Samples collected: {len(metrics)}\n")
        f.write(f"- Proxy crash samples: {len(crashes)}\n")
        f.write(f"- Long TCP iterations: {long_stats.get('iterations', 0)}\n")
        f.write(f"- Long TCP errors: {long_stats.get('errors', 0)}\n")
        f.write(f"- Short curl OK/FAIL: {short_ok}/{short_fail}\n")
        f.write(f"- UDP OK/FAIL: {udp_ok}/{udp_fail}\n")
        f.write(f"- Ping OK/FAIL: {ping_ok}/{ping_fail}\n")
        if cv is None:
            f.write("- QUIC balance CV: unavailable\n")
        else:
            f.write(f"- QUIC balance CV: {cv:.2f}%\n")
        if client_rss:
            f.write(f"- Client RSS MiB: {client_rss[0]:.1f} -> {client_rss[1]:.1f} ({client_rss[2]:+.2f}%)\n")
        if server_rss:
            f.write(f"- Server RSS MiB: {server_rss[0]:.1f} -> {server_rss[1]:.1f} ({server_rss[2]:+.2f}%)\n")
        f.write("\n## QUIC Physical Connections\n\n")
        if totals:
            total_all = sum(totals.values())
            for port in sorted(totals):
                item = conns[port]
                share = 0.0 if total_all == 0 else totals[port] / total_all * 100.0
                f.write(
                    f"- Port {port}: tx={item['tx_bytes']} rx={item['rx_bytes']} "
                    f"total={totals[port]} share={share:.2f}% active_streams={item['active_streams']}\n"
                )
        else:
            f.write("- No per-connection QUIC telemetry was captured.\n")
        f.write("\n## Pass Criteria\n\n")
        f.write(f"- No proxy crash: {'PASS' if not crashes else 'FAIL'}\n")
        f.write(f"- Short curl success: {'PASS' if short_fail == 0 and short_ok > 0 else 'FAIL'}\n")
        f.write(f"- Long TCP success: {'PASS' if long_stats.get('errors', 0) == 0 and long_stats.get('iterations', 0) > 0 else 'FAIL'}\n")
        f.write(f"- QUIC CV < 5%: {'PASS' if cv is not None and cv < 5.0 else 'FAIL'}\n")
        mem_pass = True
        if client_rss and client_rss[2] > 10.0:
            mem_pass = False
        if server_rss and server_rss[2] > 10.0:
            mem_pass = False
        f.write(f"- RSS growth <= 10%: {'PASS' if mem_pass else 'FAIL'}\n")
    print(report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
