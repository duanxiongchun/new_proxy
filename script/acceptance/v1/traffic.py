#!/usr/bin/env python3
import argparse
import json
import socket
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
    arguments = parser.parse_args()
    if arguments.command == "server":
        serve(arguments.log)
    elif arguments.command == "client":
        run_client(arguments.tag, arguments.payload_size)
    else:
        run_idle_client(arguments.seconds)


if __name__ == "__main__":
    main()
