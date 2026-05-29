#!/usr/bin/env python3
import argparse
import socket
import threading


HTTP_BODY = b"new-proxy-stability\n" * 64
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"Content-Length: " + str(len(HTTP_BODY)).encode() + b"\r\n"
    b"\r\n" + HTTP_BODY
)


def tcp_worker(conn):
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            if data.startswith(b"GET ") or data.startswith(b"HEAD "):
                conn.sendall(HTTP_RESPONSE)
                return
            conn.sendall(b"OK" + data[:1022])


def run_tcp(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1024)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=tcp_worker, args=(conn,), daemon=True).start()


def run_udp(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    while True:
        data, addr = sock.recvfrom(65536)
        if data:
            sock.sendto(b"OK", addr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--tcp-port", type=int, default=8080)
    parser.add_argument("--udp-port", type=int, default=8081)
    args = parser.parse_args()

    threading.Thread(target=run_udp, args=(args.host, args.udp_port), daemon=True).start()
    run_tcp(args.host, args.tcp_port)


if __name__ == "__main__":
    main()
