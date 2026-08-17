#!/usr/bin/env python3
import argparse
import json
import os
import socket
import struct
import threading
import time


class ExchangeLogger:
    def __init__(self, path, every):
        if every <= 0:
            raise RuntimeError("log sampling interval must be positive")
        self.path = path
        self.every = every
        self.counts = {}
        self.lock = threading.Lock()

    def record(self, protocol, peer, size):
        with self.lock:
            count = self.counts.get(protocol, 0) + 1
            self.counts[protocol] = count
            if count != 1 and count % self.every != 0:
                return
            with open(self.path, "a", encoding="utf-8") as output:
                output.write(
                    json.dumps(
                        {
                            "protocol": protocol,
                            "peer": peer[0],
                            "bytes": size,
                        }
                    )
                    + "\n"
                )


def echo_loop(sock, logger, protocol):
    while True:
        if sock.type == socket.SOCK_STREAM:
            connection, peer = sock.accept()
            threading.Thread(
                target=tcp_echo_connection,
                args=(connection, peer, logger, protocol),
                daemon=True,
            ).start()
        else:
            data, peer = sock.recvfrom(65535)
            if data:
                sock.sendto(data, peer)
            logger.record(protocol, peer, len(data))


def tcp_echo_connection(connection, peer, logger, protocol):
    with connection:
        while True:
            data = connection.recv(65535)
            if not data:
                return
            connection.sendall(data)
            logger.record(protocol, peer, len(data))


def dns_query_payload(identifier, qname):
    payload = bytearray()
    payload.extend(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in qname.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise RuntimeError(f"invalid DNS label in {qname!r}")
        payload.append(len(encoded))
        payload.extend(encoded)
    payload.append(0)
    payload.extend(struct.pack("!HH", 1, 1))
    return bytes(payload)


def parse_dns_question(payload):
    if len(payload) < 12:
        raise RuntimeError("DNS payload too short")
    identifier, _, qdcount, _, _, _ = struct.unpack("!HHHHHH", payload[:12])
    if qdcount != 1:
        raise RuntimeError(f"expected one DNS question, got {qdcount}")
    offset = 12
    labels = []
    while True:
        if offset >= len(payload):
            raise RuntimeError("truncated DNS question")
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise RuntimeError("compressed query names are not used by this helper")
        label = payload[offset : offset + length]
        if len(label) != length:
            raise RuntimeError("truncated DNS label")
        labels.append(label.decode("ascii").lower())
        offset += length
    if offset + 4 > len(payload):
        raise RuntimeError("truncated DNS qtype/qclass")
    qtype, qclass = struct.unpack("!HH", payload[offset : offset + 4])
    return identifier, ".".join(labels), qtype, qclass, offset + 4


def dns_response_payload(query, answer):
    identifier, _, qtype, qclass, question_end = parse_dns_question(query)
    if qtype != 1 or qclass != 1:
        header = struct.pack("!HHHHHH", identifier, 0x8182, 1, 0, 0, 0)
        return header + query[12:question_end]
    header = struct.pack("!HHHHHH", identifier, 0x8180, 1, 1, 0, 0)
    answer_record = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + socket.inet_aton(answer)
    )
    return header + query[12:question_end] + answer_record


def extract_first_a(payload):
    _, _, _, _, offset = parse_dns_question(payload)
    if len(payload) < 12:
        raise RuntimeError("DNS payload too short")
    _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
    if flags & 0x000F:
        raise RuntimeError(f"DNS error response rcode={flags & 0x000F}")
    for _ in range(ancount):
        if offset + 12 > len(payload):
            raise RuntimeError("truncated DNS answer")
        if payload[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(payload) and payload[offset] != 0:
                offset += 1 + payload[offset]
            offset += 1
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
        offset += 10
        rdata = payload[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            return socket.inet_ntoa(rdata)
    raise RuntimeError("DNS response did not contain an A answer")


def dns_rcode(payload):
    if len(payload) < 4:
        raise RuntimeError("DNS response too short for flags")
    return payload[3] & 0x0F


def address_family(address):
    return socket.AF_INET6 if ":" in address else socket.AF_INET


def peer_host_port(peer):
    return peer[0], peer[1]


def assert_dns_response_matches_query(query, response):
    query_id, query_name, query_type, query_class, _ = parse_dns_question(query)
    response_id, response_name, response_type, response_class, _ = parse_dns_question(response)
    if response_id != query_id:
        raise RuntimeError(f"unexpected DNS response id: {response_id} != {query_id}")
    if (response_name, response_type, response_class) != (
        query_name,
        query_type,
        query_class,
    ):
        raise RuntimeError(
            "unexpected DNS response question: "
            f"{response_name}/{response_type}/{response_class} != "
            f"{query_name}/{query_type}/{query_class}"
        )


def log_dns_query(log_path, tag, peer, qname):
    with open(log_path, "a", encoding="utf-8") as output:
        output.write(
            json.dumps(
                {
                    "protocol": "dns",
                    "tag": tag,
                    "peer": peer[0],
                    "port": peer[1],
                    "qname": qname,
                }
            )
            + "\n"
        )


def publish_ready(path):
    if path is None:
        return
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)


def dns_server(bind, port, answer, log_path, tag, ready_path):
    sock = socket.socket(address_family(bind), socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    publish_ready(ready_path)
    while True:
        query, peer = sock.recvfrom(4096)
        try:
            _, qname, _, _, _ = parse_dns_question(query)
            response = dns_response_payload(query, answer)
        except Exception:
            qname = "<malformed>"
            identifier = query[:2] if len(query) >= 2 else b"\0\0"
            response = identifier + b"\x81\x82\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sock.sendto(response, peer)
        log_dns_query(log_path, tag, peer, qname)


def dns_client(
    server,
    port,
    domain,
    expected_address,
    expected_rcode,
    expected_peer,
    timeout,
    retries,
):
    if expected_rcode is None and expected_address is None:
        raise RuntimeError("DNS client requires --expect-address or --expect-rcode")
    query = dns_query_payload(0x4E50, domain)
    errors = []
    for _ in range(retries):
        sock = socket.socket(address_family(server), socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        response = None
        try:
            sock.sendto(query, (server, port))
            response, peer = sock.recvfrom(4096)
            if peer_host_port(peer) != (expected_peer, port):
                raise RuntimeError(f"unexpected DNS response peer: {peer!r}")
            assert_dns_response_matches_query(query, response)
            if expected_rcode is not None:
                rcode = dns_rcode(response)
                if rcode != expected_rcode:
                    raise RuntimeError(f"unexpected DNS rcode: {rcode} != {expected_rcode}")
                return None
            answer = extract_first_a(response)
            if answer != expected_address:
                raise RuntimeError(f"unexpected DNS answer: {answer} != {expected_address}")
            return answer
        except Exception as error:
            response_summary = (
                f", response_len={len(response)}, response_hex={response.hex()}"
                if response is not None
                else ""
            )
            errors.append(f"{error}{response_summary}")
            time.sleep(0.1)
        finally:
            sock.close()
    raise RuntimeError(
        f"DNS query failed after {retries} attempts: {'; '.join(errors)}"
    )


def serve(log_path, log_every, bind_ipv4, ready_path):
    logger = ExchangeLogger(log_path, log_every)
    sockets = []
    for family, address, tcp_port, udp_port, suffix in [
        (socket.AF_INET, bind_ipv4, 8080, 8081, "4"),
        (socket.AF_INET6, "::", 8080, 8081, "6"),
    ]:
        tcp = socket.socket(family, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        tcp.bind((address, tcp_port))
        tcp.listen(16)
        udp = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        udp.bind((address, udp_port))
        sockets.extend([(tcp, f"tcp{suffix}"), (udp, f"udp{suffix}")])
    publish_ready(ready_path)
    for sock, protocol in sockets:
        threading.Thread(
            target=echo_loop, args=(sock, logger, protocol), daemon=True
        ).start()
    while True:
        time.sleep(3600)


def exchange(family, socket_type, address, port, payload):
    sock = socket.socket(family, socket_type)
    sock.settimeout(5)
    sock.connect((address, port))
    if socket_type == socket.SOCK_STREAM:
        sock.sendall(payload)
        received = receive_exact(sock, len(payload))
    else:
        sock.send(payload)
        received = sock.recv(65535)
    sock.close()
    if received != payload:
        raise RuntimeError(
            f"echo mismatch for {address}:{port}: {received!r} != {payload!r}"
        )


def receive_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError(f"connection closed with {remaining} bytes remaining")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def target_addresses(address=None):
    if address is not None:
        return [(address_family(address), address, "6" if ":" in address else "4")]
    return [
        (socket.AF_INET, "10.20.1.2", "4"),
        (socket.AF_INET6, "2001:db8:20::2", "6"),
    ]


def run_client(tag, payload_size, address=None):
    for family, target, suffix in target_addresses(address):
        family_payload_size = payload_size if family == socket.AF_INET else max(1, payload_size - 20)
        prefix = f"{tag}-{suffix}-".encode()
        payload = (
            prefix + bytes(range(251)) * ((family_payload_size // 251) + 1)
        )[
            :family_payload_size
        ]
        exchange(family, socket.SOCK_STREAM, target, 8080, payload)
        exchange(family, socket.SOCK_DGRAM, target, 8081, payload)


def load_worker(worker_id, duration, payload_size, window, results, errors):
    family, address, suffix = target_addresses()[worker_id % 2]
    socket_type, port, protocol = (
        (socket.SOCK_STREAM, 8080, "tcp")
        if (worker_id // 2) % 2 == 0
        else (socket.SOCK_DGRAM, 8081, "udp")
    )
    payload = (
        f"load-{protocol}{suffix}-{worker_id}-".encode()
        + bytes(range(251)) * ((payload_size // 251) + 1)
    )[:payload_size]
    exchanges = 0
    transferred = 0
    deadline = time.monotonic() + duration
    try:
        sock = socket.socket(family, socket_type)
        sock.settimeout(5)
        sock.connect((address, port))
        with sock:
            while time.monotonic() < deadline:
                if socket_type == socket.SOCK_STREAM:
                    expected = payload * window
                    sock.sendall(expected)
                    received = receive_exact(sock, len(expected))
                else:
                    for _ in range(window):
                        sock.send(payload)
                    received = b"".join(sock.recv(65535) for _ in range(window))
                    expected = payload * window
                if received != expected:
                    raise RuntimeError(
                        f"load echo mismatch for {protocol}{suffix}: "
                        f"{len(received)} != {len(expected)} bytes"
                    )
                exchanges += window
                transferred += len(payload) * window * 2
        results[worker_id] = (exchanges, transferred)
    except Exception as error:
        errors.append(f"worker {worker_id} {protocol}{suffix}: {error}")


def run_load(duration, concurrency, payload_size, window):
    if duration <= 0 or concurrency < 4 or payload_size <= 0 or window <= 0:
        raise RuntimeError(
            "load requires duration > 0, concurrency >= 4, payload size > 0, window > 0"
        )
    results = {}
    errors = []
    threads = [
        threading.Thread(
            target=load_worker,
            args=(worker_id, duration, payload_size, window, results, errors),
        )
        for worker_id in range(concurrency)
    ]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started
    if errors:
        raise RuntimeError("; ".join(errors))
    exchanges = sum(result[0] for result in results.values())
    transferred = sum(result[1] for result in results.values())
    if exchanges == 0:
        raise RuntimeError("load completed without a successful exchange")
    print(
        json.dumps(
            {
                "elapsed_seconds": elapsed,
                "exchanges": exchanges,
                "bytes": transferred,
                "mbit_per_second": transferred * 8 / elapsed / 1_000_000,
                "window": window,
                "load_model": "windowed_echo",
            },
            sort_keys=True,
        )
    )


def run_idle_client(idle_seconds):
    sockets = []
    for family, address in [
        (socket.AF_INET, "10.20.1.2"),
        (socket.AF_INET6, "2001:db8:20::2"),
    ]:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((address, 8080))
        sockets.append(sock)
    try:
        for phase in ("before", "after"):
            for index, sock in enumerate(sockets):
                payload = f"idle-{phase}-{index}".encode()
                sock.sendall(payload)
                received = receive_exact(sock, len(payload))
                if received != payload:
                    raise RuntimeError(f"idle echo mismatch: {received!r} != {payload!r}")
            if phase == "before":
                time.sleep(idle_seconds)
    finally:
        for sock in sockets:
            sock.close()


def run_udp_capacity(address, port, first_source_port, second_source_port):
    family = address_family(address)
    first = socket.socket(family, socket.SOCK_DGRAM)
    second = socket.socket(family, socket.SOCK_DGRAM)
    first.settimeout(5)
    second.settimeout(1)
    try:
        first.bind(("", first_source_port))
        second.bind(("", second_source_port))
        first.connect((address, port))
        second.connect((address, port))

        first_payload = b"capacity-established"
        first.send(first_payload)
        if first.recv(65535) != first_payload:
            raise RuntimeError("established UDP flow echo mismatch")

        second.send(b"capacity-rejected")
        try:
            second.recv(65535)
        except socket.timeout:
            pass
        else:
            raise RuntimeError("new UDP flow unexpectedly succeeded after NAT exhaustion")

        recovery_payload = b"capacity-established-still-alive"
        first.send(recovery_payload)
        if first.recv(65535) != recovery_payload:
            raise RuntimeError("established UDP flow failed after NAT exhaustion")
    finally:
        first.close()
        second.close()


def parse_mac(address):
    octets = address.split(":")
    if len(octets) != 6:
        raise RuntimeError(f"invalid MAC address: {address}")
    try:
        return bytes(int(octet, 16) for octet in octets)
    except ValueError as error:
        raise RuntimeError(f"invalid MAC address: {address}") from error


def internet_checksum(payload):
    if len(payload) % 2:
        payload += b"\0"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def send_malformed_frame(interface, source_mac, destination_mac, source_ip, destination_ip):
    source = socket.inet_aton(source_ip)
    destination = socket.inet_aton(destination_ip)
    truncated_tcp = struct.pack("!HHI", 49152, 8080, 1)
    total_length = 20 + len(truncated_tcp)
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x4E50,
        0x4000,
        64,
        socket.IPPROTO_TCP,
        0,
        source,
        destination,
    )
    ipv4_header = ipv4_header[:10] + struct.pack(
        "!H", internet_checksum(ipv4_header)
    ) + ipv4_header[12:]
    ethernet_header = (
        parse_mac(destination_mac)
        + parse_mac(source_mac)
        + struct.pack("!H", 0x0800)
    )
    frame = ethernet_header + ipv4_header + truncated_tcp
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        sock.bind((interface, 0))
        sent = sock.send(frame)
    finally:
        sock.close()
    if sent != len(frame):
        raise RuntimeError(f"short AF_PACKET send: {sent} != {len(frame)}")


def send_udp_frame(
    interface,
    source_mac,
    destination_mac,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
):
    source = socket.inet_aton(source_ip)
    destination = socket.inet_aton(destination_ip)
    payload = b"unknown-nat-tuple"
    udp = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        8 + len(payload),
        0,
    ) + payload
    total_length = 20 + len(udp)
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x4E51,
        0x4000,
        64,
        socket.IPPROTO_UDP,
        0,
        source,
        destination,
    )
    ipv4_header = ipv4_header[:10] + struct.pack(
        "!H", internet_checksum(ipv4_header)
    ) + ipv4_header[12:]
    ethernet_header = (
        parse_mac(destination_mac)
        + parse_mac(source_mac)
        + struct.pack("!H", 0x0800)
    )
    frame = ethernet_header + ipv4_header + udp
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        sock.bind((interface, 0))
        sent = sock.send(frame)
    finally:
        sock.close()
    if sent != len(frame):
        raise RuntimeError(f"short AF_PACKET send: {sent} != {len(frame)}")


def send_raw_frame(interface, frame):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        sock.bind((interface, 0))
        sent = sock.send(frame)
    finally:
        sock.close()
    if sent != len(frame):
        raise RuntimeError(f"short AF_PACKET send: {sent} != {len(frame)}")


def send_xdp_parser_drop(
    kind,
    interface,
    source_mac,
    destination_mac,
    source_ip,
    destination_ip,
):
    ethernet = (
        parse_mac(destination_mac)
        + parse_mac(source_mac)
        + struct.pack("!H", 0x86DD if ":" in destination_ip else 0x0800)
    )
    if kind == "truncated-ipv4":
        frame = ethernet
    elif kind == "ipv4-length":
        source = socket.inet_aton(source_ip)
        destination = socket.inet_aton(destination_ip)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            60,
            0x4E52,
            0x4000,
            64,
            socket.IPPROTO_TCP,
            0,
            source,
            destination,
        )
        frame = ethernet + header
    elif kind == "tunnel-udp-length":
        source = socket.inet_aton(source_ip)
        destination = socket.inet_aton(destination_ip)
        udp = struct.pack("!HHHH", 4433, 4433, 64, 0)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(udp),
            0x4E53,
            0x4000,
            64,
            socket.IPPROTO_UDP,
            0,
            source,
            destination,
        )
        header = header[:10] + struct.pack(
            "!H", internet_checksum(header)
        ) + header[12:]
        frame = ethernet + header + udp
    elif kind == "ipv6-extension":
        source = socket.inet_pton(socket.AF_INET6, source_ip)
        destination = socket.inet_pton(socket.AF_INET6, destination_ip)
        truncated_extension = b"\x06\x00"
        header = struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(truncated_extension),
            0,
            64,
            source,
            destination,
        )
        frame = ethernet + header + truncated_extension
    elif kind == "dns-ipv4-non-initial-fragment":
        source = socket.inet_aton(source_ip)
        destination = socket.inet_aton(destination_ip)
        fragment_payload = b"dns-fragment"
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(fragment_payload),
            0x4E55,
            1,
            64,
            socket.IPPROTO_UDP,
            0,
            source,
            destination,
        )
        header = header[:10] + struct.pack(
            "!H", internet_checksum(header)
        ) + header[12:]
        frame = ethernet + header + fragment_payload
    elif kind == "dns-ipv6-non-initial-fragment":
        source = socket.inet_pton(socket.AF_INET6, source_ip)
        destination = socket.inet_pton(socket.AF_INET6, destination_ip)
        fragment_payload = b"dns-fragment"
        fragment_header = struct.pack("!BBHI", socket.IPPROTO_UDP, 0, 8, 0x4E560001)
        header = struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(fragment_header) + len(fragment_payload),
            44,
            64,
            source,
            destination,
        )
        frame = ethernet + header + fragment_header + fragment_payload
    else:
        source = socket.inet_aton(source_ip)
        destination = socket.inet_aton(destination_ip)
        payload = b"\x40"
        udp = struct.pack(
            "!HHHH",
            4433,
            4433,
            8 + len(payload),
            0,
        ) + payload
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(udp),
            0x4E54,
            0x4000,
            64,
            socket.IPPROTO_UDP,
            0,
            source,
            destination,
        )
        header = header[:10] + struct.pack(
            "!H", internet_checksum(header)
        ) + header[12:]
        frame = ethernet + header + udp
    send_raw_frame(interface, frame)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    server = subparsers.add_parser("server")
    server.add_argument("--log", required=True)
    server.add_argument("--log-every", type=int, default=1)
    server.add_argument("--bind-ipv4", default="0.0.0.0")
    server.add_argument("--ready")
    client = subparsers.add_parser("client")
    client.add_argument("--tag", required=True)
    client.add_argument("--payload-size", type=int, default=32)
    client.add_argument("--address")
    load = subparsers.add_parser("load-client")
    load.add_argument("--duration", type=float, required=True)
    load.add_argument("--concurrency", type=int, default=8)
    load.add_argument("--payload-size", type=int, default=1200)
    load.add_argument("--window", type=int, default=32)
    idle = subparsers.add_parser("idle-client")
    idle.add_argument("--seconds", type=float, default=12)
    udp_capacity = subparsers.add_parser("udp-capacity")
    udp_capacity.add_argument("--address", required=True)
    udp_capacity.add_argument("--port", type=int, default=8081)
    udp_capacity.add_argument("--first-source-port", type=int, required=True)
    udp_capacity.add_argument("--second-source-port", type=int, required=True)
    dns_server_parser = subparsers.add_parser("dns-server")
    dns_server_parser.add_argument("--bind", required=True)
    dns_server_parser.add_argument("--port", type=int, required=True)
    dns_server_parser.add_argument("--answer", required=True)
    dns_server_parser.add_argument("--log", required=True)
    dns_server_parser.add_argument("--tag", required=True)
    dns_server_parser.add_argument("--ready")
    dns_client_parser = subparsers.add_parser("dns-client")
    dns_client_parser.add_argument("--server", required=True)
    dns_client_parser.add_argument("--port", type=int, default=53)
    dns_client_parser.add_argument("--domain", required=True)
    dns_client_parser.add_argument("--expect-address")
    dns_client_parser.add_argument("--expect-rcode", type=int)
    dns_client_parser.add_argument("--expect-peer", required=True)
    dns_client_parser.add_argument("--timeout", type=float, default=2.0)
    dns_client_parser.add_argument("--retries", type=int, default=10)
    malformed_frame = subparsers.add_parser("malformed-frame")
    malformed_frame.add_argument("--interface", required=True)
    malformed_frame.add_argument("--source-mac", required=True)
    malformed_frame.add_argument("--destination-mac", required=True)
    malformed_frame.add_argument("--source-ip", required=True)
    malformed_frame.add_argument("--destination-ip", required=True)
    udp_frame = subparsers.add_parser("udp-frame")
    udp_frame.add_argument("--interface", required=True)
    udp_frame.add_argument("--source-mac", required=True)
    udp_frame.add_argument("--destination-mac", required=True)
    udp_frame.add_argument("--source-ip", required=True)
    udp_frame.add_argument("--destination-ip", required=True)
    udp_frame.add_argument("--source-port", type=int, required=True)
    udp_frame.add_argument("--destination-port", type=int, required=True)
    parser_drop = subparsers.add_parser("xdp-parser-drop")
    parser_drop.add_argument(
        "--kind",
        choices=(
            "truncated-ipv4",
            "ipv4-length",
            "tunnel-udp-length",
            "ipv6-extension",
            "dns-ipv4-non-initial-fragment",
            "dns-ipv6-non-initial-fragment",
            "invalid-outer-quic",
        ),
        required=True,
    )
    parser_drop.add_argument("--interface", required=True)
    parser_drop.add_argument("--source-mac", required=True)
    parser_drop.add_argument("--destination-mac", required=True)
    parser_drop.add_argument("--source-ip", required=True)
    parser_drop.add_argument("--destination-ip", required=True)
    arguments = parser.parse_args()
    if arguments.command == "server":
        serve(
            arguments.log,
            arguments.log_every,
            arguments.bind_ipv4,
            arguments.ready,
        )
    elif arguments.command == "client":
        run_client(arguments.tag, arguments.payload_size, arguments.address)
    elif arguments.command == "load-client":
        run_load(
            arguments.duration,
            arguments.concurrency,
            arguments.payload_size,
            arguments.window,
        )
    elif arguments.command == "idle-client":
        run_idle_client(arguments.seconds)
    elif arguments.command == "udp-capacity":
        run_udp_capacity(
            arguments.address,
            arguments.port,
            arguments.first_source_port,
            arguments.second_source_port,
        )
    elif arguments.command == "dns-server":
        dns_server(
            arguments.bind,
            arguments.port,
            arguments.answer,
            arguments.log,
            arguments.tag,
            arguments.ready,
        )
    elif arguments.command == "dns-client":
        answer = dns_client(
            arguments.server,
            arguments.port,
            arguments.domain,
            arguments.expect_address,
            arguments.expect_rcode,
            arguments.expect_peer,
            arguments.timeout,
            arguments.retries,
        )
        if answer is not None:
            print(answer)
    elif arguments.command == "malformed-frame":
        send_malformed_frame(
            arguments.interface,
            arguments.source_mac,
            arguments.destination_mac,
            arguments.source_ip,
            arguments.destination_ip,
        )
    elif arguments.command == "udp-frame":
        send_udp_frame(
            arguments.interface,
            arguments.source_mac,
            arguments.destination_mac,
            arguments.source_ip,
            arguments.destination_ip,
            arguments.source_port,
            arguments.destination_port,
        )
    else:
        send_xdp_parser_drop(
            arguments.kind,
            arguments.interface,
            arguments.source_mac,
            arguments.destination_mac,
            arguments.source_ip,
            arguments.destination_ip,
        )


if __name__ == "__main__":
    main()
