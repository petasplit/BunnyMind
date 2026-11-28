#!/usr/bin/env python3
"""Loopback-only deterministic BunnyMind test service.

This is a harmless owned-resource fixture. Never bind it to an external
interface or use it as evidence of any live vulnerability.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = b"BUNNY-OWNED-SUCCESS"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/candidate-good":
            code, payload = 200, b"test-owned resource: " + MARKER + b"\n"
        elif self.path == "/candidate-bad":
            code, payload = 200, b"ordinary response with no marker\n"
        elif self.path == "/control":
            code, payload = 403, b"negative control denied\n"
        elif self.path == "/health":
            code, payload = 200, b"ok\n"
        else:
            code, payload = 404, b"not found\n"
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        # No URLs, cookies, or query strings from requests are logged.
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18786)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("fixture port must be 1024..65535")
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        print("BunnyMind harmless test fixture at http://127.0.0.1:%d" % args.port, flush=True)
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
