#!/usr/bin/env python3
"""Deterministic local System One-compatible mock for smart-protection benchmarks."""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def response_for(behavior):
    if behavior == "malformed":
        return {"answers": {}}
    if behavior == "low_confidence":
        return {
            "answers": {
                "risk_level": {"choice": "critical_danger", "confidence": 0.20},
                "is_destructive": {"noul": 0.96, "confidence": 0.20},
                "blast_radius": {"score": 4.0, "confidence": 0.20},
            }
        }
    if behavior == "deny":
        return {
            "answers": {
                "risk_level": {"choice": "critical_danger", "confidence": 0.94},
                "is_destructive": {"noul": 0.96, "confidence": 0.97},
                "blast_radius": {"score": 4.0, "confidence": 0.91},
            }
        }
    return {
        "answers": {
            "risk_level": {"choice": "safe", "confidence": 0.92},
            "is_destructive": {"noul": 0.01, "confidence": 0.99},
            "blast_radius": {"score": 0.2, "confidence": 0.90},
        }
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        state = payload.get("state", "")
        behavior = "deny" if '"mock_behavior":"deny"' in state else "safe"
        for candidate in ("malformed", "low_confidence", "timeout"):
            if f'"mock_behavior":"{candidate}"' in state:
                behavior = candidate
                break
        if behavior == "timeout":
            time.sleep(1.0)
        body = json.dumps(response_for(behavior), separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"READY {server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
