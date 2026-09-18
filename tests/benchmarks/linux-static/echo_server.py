#!/usr/bin/env python3
import pathlib
import socketserver
import struct
import sys
import threading


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                return
            self.request.sendall(chunk)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, socket = self.request
        response = dns_response(packet)
        if response is not None:
            socket.sendto(response, self.client_address)


class DnsServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def dns_response(query: bytes) -> bytes | None:
    if len(query) < 12:
        return None
    offset = 12
    while offset < len(query):
        length = query[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(query):
            return None
        offset += length
    if offset + 4 > len(query):
        return None
    question = query[12 : offset + 4]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    return query[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} port-file")
    port_file = pathlib.Path(sys.argv[1])
    with EchoServer(("127.0.0.1", 0), EchoHandler) as echo, DnsServer(
        ("127.0.0.1", 0), DnsHandler
    ) as dns:
        port_file.write_text(
            f"{echo.server_address[1]} {dns.server_address[1]}\n", encoding="ascii"
        )
        dns_thread = threading.Thread(target=dns.serve_forever, daemon=True)
        dns_thread.start()
        try:
            echo.serve_forever()
        finally:
            dns.shutdown()
            dns_thread.join()


if __name__ == "__main__":
    main()
