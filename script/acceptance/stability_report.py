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


def latest_connections_by_peer(metrics):
    for row in reversed(metrics):
        telemetry = row.get("telemetry")
        if not isinstance(telemetry, list):
            continue
        by_peer = {}
        for peer in telemetry:
            if not isinstance(peer, dict):
                continue
            conns = peer.get("quic_connections") or []
            if not conns:
                continue
            peer_key = peer.get("public_key") or "(unknown)"
            by_port = {}
            for conn in conns:
                port = str(conn.get("local_port"))
                item = by_port.setdefault(port, {"rx_bytes": 0, "tx_bytes": 0, "active_streams": 0})
                item["rx_bytes"] += int(conn.get("rx_bytes") or 0)
                item["tx_bytes"] += int(conn.get("tx_bytes") or 0)
                item["active_streams"] += int(conn.get("active_streams") or 0)
            by_peer[peer_key] = by_port
        if by_peer:
            return by_peer
    return {}


def rss_growth(metrics, side, warmup_seconds):
    samples = [row for row in metrics if row.get(side, {}).get("rss_kib")]
    if not samples:
        return None
    base = None
    started = samples[0]["elapsed_seconds"]
    for row in samples:
        if row["elapsed_seconds"] - started >= warmup_seconds:
            base = row
            break
    if base is None:
        base = samples[0]
    end = samples[-1]
    base_rss = float(base[side]["rss_kib"])
    end_rss = float(end[side]["rss_kib"])
    growth = 0.0 if base_rss == 0 else (end_rss - base_rss) / base_rss * 100.0
    return base_rss / 1024.0, end_rss / 1024.0, growth


def rss_pass(rss, max_pct, max_mib):
    if not rss:
        return True
    base_mib, end_mib, growth_pct = rss
    growth_mib = end_mib - base_mib
    return growth_pct <= max_pct or growth_mib <= max_mib


def main():
    if len(sys.argv) != 2:
        print("usage: stability_report.py <artifact_dir>", file=sys.stderr)
        return 2
    artifact_dir = sys.argv[1]
    metrics = read_jsonl(os.path.join(artifact_dir, "stability_metrics.jsonl"))
    long_stats = read_json(os.path.join(artifact_dir, "long_tcp_stats.json"))
    long2_stats = read_json(os.path.join(artifact_dir, "long_tcp2_stats.json"))
    short_ok = count_lines(os.path.join(artifact_dir, "short_conn.log"), "OK")
    short_fail = count_lines(os.path.join(artifact_dir, "short_conn.log"), "FAIL")
    udp_ok = count_lines(os.path.join(artifact_dir, "udp.log"), "OK")
    udp_fail = count_lines(os.path.join(artifact_dir, "udp.log"), "FAIL")
    ping_ok = count_lines(os.path.join(artifact_dir, "ping.log"), "OK")
    ping_fail = count_lines(os.path.join(artifact_dir, "ping.log"), "FAIL")
    long_iterations = long_stats.get("iterations", 0) + long2_stats.get("iterations", 0)
    long_errors = long_stats.get("errors", 0) + long2_stats.get("errors", 0)

    conns_by_peer = latest_connections_by_peer(metrics)
    totals_by_peer = {
        peer: {port: item["rx_bytes"] + item["tx_bytes"] for port, item in conns.items()}
        for peer, conns in conns_by_peer.items()
    }
    cv_by_peer = {
        peer: cv_percent(list(totals.values()))
        for peer, totals in totals_by_peer.items()
    }
    max_rss_growth_pct = float(os.environ.get("STABILITY_MAX_RSS_GROWTH_PCT", "10.0"))
    max_rss_growth_mib = float(os.environ.get("STABILITY_MAX_RSS_GROWTH_MIB", "2.0"))
    rss_warmup_seconds = float(os.environ.get("STABILITY_RSS_WARMUP_SECONDS", "10.0"))
    enforce_rss = os.environ.get("STABILITY_ENFORCE_RSS", "0") == "1"
    client_rss = rss_growth(metrics, "client", rss_warmup_seconds)
    server_rss = rss_growth(metrics, "server", rss_warmup_seconds)
    client2_rss = rss_growth(metrics, "client2", rss_warmup_seconds)
    crashes = [
        row
        for row in metrics
        if not row.get("client", {}).get("alive")
        or not row.get("client2", {}).get("alive")
        or not row.get("server", {}).get("alive")
    ]
    available_cvs = [cv for cv in cv_by_peer.values() if cv is not None]
    no_crash_pass = not crashes
    short_pass = short_fail == 0 and short_ok > 0
    udp_pass = udp_fail == 0 and udp_ok > 0
    ping_pass = ping_fail == 0 and ping_ok > 0
    long_pass = (
        long_errors == 0
        and long_stats.get("iterations", 0) > 0
        and long2_stats.get("iterations", 0) > 0
    )
    cv_pass = bool(available_cvs) and all(cv < 5.0 for cv in available_cvs)
    mem_pass = all(
        rss_pass(rss, max_rss_growth_pct, max_rss_growth_mib)
        for rss in (client_rss, client2_rss, server_rss)
    )
    hard_pass = all([no_crash_pass, short_pass, udp_pass, ping_pass, long_pass, cv_pass]) and (
        mem_pass or not enforce_rss
    )

    report_path = os.path.join(artifact_dir, "stability_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Stability Test Report\n\n")
        f.write(f"- Artifact directory: `{artifact_dir}`\n")
        f.write(f"- Samples collected: {len(metrics)}\n")
        f.write(f"- Proxy crash samples: {len(crashes)}\n")
        f.write(f"- Long TCP iterations: {long_iterations}\n")
        f.write(f"- Long TCP errors: {long_errors}\n")
        f.write(f"- Short curl OK/FAIL: {short_ok}/{short_fail}\n")
        f.write(f"- UDP OK/FAIL: {udp_ok}/{udp_fail}\n")
        f.write(f"- Ping OK/FAIL: {ping_ok}/{ping_fail}\n")
        if not available_cvs:
            f.write("- QUIC balance CV: unavailable\n")
        else:
            worst_cv = max(available_cvs)
            f.write(f"- Worst per-peer QUIC balance CV: {worst_cv:.2f}%\n")
        if client_rss:
            f.write(f"- Client RSS MiB: {client_rss[0]:.1f} -> {client_rss[1]:.1f} ({client_rss[2]:+.2f}%)\n")
        if client2_rss:
            f.write(f"- Client2 RSS MiB: {client2_rss[0]:.1f} -> {client2_rss[1]:.1f} ({client2_rss[2]:+.2f}%)\n")
        if server_rss:
            f.write(f"- Server RSS MiB: {server_rss[0]:.1f} -> {server_rss[1]:.1f} ({server_rss[2]:+.2f}%)\n")
        f.write("\n## QUIC Physical Connections\n\n")
        if totals_by_peer:
            for peer in sorted(totals_by_peer):
                totals = totals_by_peer[peer]
                conns = conns_by_peer[peer]
                total_all = sum(totals.values())
                cv = cv_by_peer.get(peer)
                cv_text = "unavailable" if cv is None else f"{cv:.2f}%"
                f.write(f"- Peer {peer}: CV={cv_text}\n")
                for port in sorted(totals):
                    item = conns[port]
                    share = 0.0 if total_all == 0 else totals[port] / total_all * 100.0
                    f.write(
                        f"  - Port {port}: tx={item['tx_bytes']} rx={item['rx_bytes']} "
                        f"total={totals[port]} share={share:.2f}% active_streams={item['active_streams']}\n"
                    )
        else:
            f.write("- No per-connection QUIC telemetry was captured.\n")
        f.write("\n## Pass Criteria\n\n")
        f.write(f"- No proxy crash: {'PASS' if no_crash_pass else 'FAIL'}\n")
        f.write(f"- Short curl success: {'PASS' if short_pass else 'FAIL'}\n")
        f.write(f"- UDP success: {'PASS' if udp_pass else 'FAIL'}\n")
        f.write(f"- Ping success: {'PASS' if ping_pass else 'FAIL'}\n")
        f.write(f"- Long TCP success: {'PASS' if long_pass else 'FAIL'}\n")
        f.write(f"- Per-peer QUIC CV < 5%: {'PASS' if cv_pass else 'FAIL'}\n")
        rss_status = "PASS" if mem_pass else ("FAIL" if enforce_rss else "WARN")
        f.write(
            f"- RSS growth <= {max_rss_growth_pct:g}% or <= {max_rss_growth_mib:g} MiB: "
            f"{rss_status}\n"
        )
        f.write(f"- RSS hard gate enabled: {'yes' if enforce_rss else 'no'}\n")
        f.write(f"- RSS warmup baseline: {rss_warmup_seconds:g}s\n")
    print(report_path)
    return 0 if hard_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
