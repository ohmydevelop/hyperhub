#!/usr/bin/env python3
"""Local HTTP credential fixture for the Linux ptrace backend.

Server mode accepts one request and succeeds only when HyperHub replaced the
placeholder Authorization header. Client mode deliberately connects to
localhost so the kernel sees an IP while the HTTP Host header carries the route
hostname and path.
"""

import http.client
import http.server
import pathlib
import ssl
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    expected = ""

    def do_GET(self):
        authorized = (
            self.path == "/probe"
            and self.headers.get("Authorization") == f"Bearer {self.expected}"
        )
        body = b"ok" if authorized else b"unauthorized"
        self.send_response(200 if authorized else 401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def serve(port_file: str, expected: str, cert_file=None, key_file=None) -> int:
    Handler.expected = expected
    port_path = pathlib.Path(port_file)
    try:
        requested_port = int(port_path.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        requested_port = 0
    server = http.server.HTTPServer(("127.0.0.1", requested_port), Handler)
    if cert_file and key_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    port_path.write_text(str(server.server_port), encoding="utf-8")
    try:
        server.handle_request()
    except ssl.SSLError:
        return 2
    finally:
        server.server_close()
    return 0


def probe(host: str, port: int, tls=False) -> int:
    connection = (
        http.client.HTTPSConnection(host, port, timeout=10, context=ssl.create_default_context())
        if tls
        else http.client.HTTPConnection(host, port, timeout=10)
    )
    connection.request(
        "GET",
        "/probe",
        headers={"Authorization": "Bearer placeholder-token"},
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return 0 if response.status == 200 and body == b"ok" else 1


def main() -> int:
    if len(sys.argv) == 6 and sys.argv[1] == "--tls-server":
        return serve(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    if len(sys.argv) == 4 and sys.argv[1] == "--server":
        return serve(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 4 and sys.argv[1] == "--tls-client":
        return probe(sys.argv[2], int(sys.argv[3]), tls=True)
    if len(sys.argv) == 3:
        return probe(sys.argv[1], int(sys.argv[2]))
    print(
        f"usage: {sys.argv[0]} [--server PORT_FILE SECRET | --tls-server PORT_FILE SECRET CERT KEY | --tls-client HOST PORT | HOST PORT]",
        file=sys.stderr,
    )
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
