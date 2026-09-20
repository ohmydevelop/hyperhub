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


def serve(port_file: str, expected: str) -> int:
    Handler.expected = expected
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    pathlib.Path(port_file).write_text(str(server.server_port), encoding="utf-8")
    server.handle_request()
    server.server_close()
    return 0


def probe(host: str, port: int) -> int:
    connection = http.client.HTTPConnection(host, port, timeout=10)
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
    if len(sys.argv) == 4 and sys.argv[1] == "--server":
        return serve(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 3:
        return probe(sys.argv[1], int(sys.argv[2]))
    print(f"usage: {sys.argv[0]} [--server PORT_FILE SECRET | HOST PORT]", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
