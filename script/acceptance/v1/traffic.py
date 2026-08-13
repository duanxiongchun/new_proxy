#!/usr/bin/env python3
import argparse
import json
import socket
import struct
import threading
import time


def echo_loop(sock, log_path, protocol):
    while True:
        if sock.type == socket.SOCK_STREAM:
            connection, peer = sock.accept()
            threading.Thread(
                target=tcp_echo_connection,
                args=(connection, peer, log_path, protocol),
                daemon=True,
            ).start()
        else:
            data, peer = sock.recvfrom(65535)
            if data:
                sock.sendto(data, peer)
            log_exchange(log_path, protocol, peer, len(data))


def tcp_echo_connection(connection, peer, log_path, protocol):
    with connection:
        while True:
            data = connection.recv(65535)
            if not data:
                return
            connection.sendall(data)
            log_exchange(log_path, protocol, peer, len(data))


def log_exchange(log_path, protocol, peer, size):
    with open(log_path, "a", encoding="utf-8") as output:
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


def dns_server(bind, port, answer, log_path, tag):
    sock = socket.socket(address_family(bind), socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
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
    last_error = None
    for _ in range(retries):
        sock = socket.socket(address_family(server), socket.SOCK_DGRAM)
        sock.settimeout(timeout)
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
                return
            answer = extract_first_a(response)
            if answer != expected_address:
                raise RuntimeError(f"unexpected DNS answer: {answer} != {expected_address}")
            return
        except Exception as error:
            last_error = error
            time.sleep(0.1)
        finally:
            sock.close()
    raise RuntimeError(f"DNS query failed after {retries} attempts: {last_error}")


def serve(log_path):
    sockets = []
    for family, address, tcp_port, udp_port, suffix in [
        (socket.AF_INET, "0.0.0.0", 8080, 8081, "4"),
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
    for sock, protocol in sockets:
        threading.Thread(
            target=echo_loop, args=(sock, log_path, protocol), daemon=True
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


def run_client(tag, payload_size):
    for family, address, suffix in [
        (socket.AF_INET, "10.20.1.2", "4"),
        (socket.AF_INET6, "2001:db8:20::2", "6"),
    ]:
        family_payload_size = payload_size if family == socket.AF_INET else max(1, payload_size - 20)
        prefix = f"{tag}-{suffix}-".encode()
        payload = (
            prefix + bytes(range(251)) * ((family_payload_size // 251) + 1)
        )[
            :family_payload_size
        ]
        exchange(family, socket.SOCK_STREAM, address, 8080, payload)
        exchange(family, socket.SOCK_DGRAM, address, 8081, payload)


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


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    server = subparsers.add_parser("server")
    server.add_argument("--log", required=True)
    client = subparsers.add_parser("client")
    client.add_argument("--tag", required=True)
    client.add_argument("--payload-size", type=int, default=32)
    idle = subparsers.add_parser("idle-client")
    idle.add_argument("--seconds", type=float, default=12)
    dns_server_parser = subparsers.add_parser("dns-server")
    dns_server_parser.add_argument("--bind", required=True)
    dns_server_parser.add_argument("--port", type=int, required=True)
    dns_server_parser.add_argument("--answer", required=True)
    dns_server_parser.add_argument("--log", required=True)
    dns_server_parser.add_argument("--tag", required=True)
    dns_client_parser = subparsers.add_parser("dns-client")
    dns_client_parser.add_argument("--server", required=True)
    dns_client_parser.add_argument("--port", type=int, default=53)
    dns_client_parser.add_argument("--domain", required=True)
    dns_client_parser.add_argument("--expect-address")
    dns_client_parser.add_argument("--expect-rcode", type=int)
    dns_client_parser.add_argument("--expect-peer", required=True)
    dns_client_parser.add_argument("--timeout", type=float, default=2.0)
    dns_client_parser.add_argument("--retries", type=int, default=10)
    arguments = parser.parse_args()
    if arguments.command == "server":
        serve(arguments.log)
    elif arguments.command == "client":
        run_client(arguments.tag, arguments.payload_size)
    elif arguments.command == "idle-client":
        run_idle_client(arguments.seconds)
    elif arguments.command == "dns-server":
        dns_server(
            arguments.bind,
            arguments.port,
            arguments.answer,
            arguments.log,
            arguments.tag,
        )
    else:
        dns_client(
            arguments.server,
            arguments.port,
            arguments.domain,
            arguments.expect_address,
            arguments.expect_rcode,
            arguments.expect_peer,
            arguments.timeout,
            arguments.retries,
        )


if __name__ == "__main__":
    main()
