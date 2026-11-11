"""Local web UI for the resolver.

    python web.py [port]   ->  http://127.0.0.1:8053
"""
import json
import sys
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import dnsresolver

INDEX = Path(__file__).with_name("index.html")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            return self._send(INDEX.read_bytes(), "text/html; charset=utf-8")
        if url.path != "/api/resolve":
            return self.send_error(404)
        params = parse_qs(url.query)
        steps, start = [], time.perf_counter()
        body = {"status": "ERROR", "answers": []}
        try:
            result = dnsresolver.resolve(params.get("name", [""])[0], params.get("type", ["A"])[0], steps=steps)
            body = {"status": result.status, "answers": [asdict(r) for r in result.answers]}
        except dnsresolver.DNSError as exc:
            body["error"] = str(exc)
        body["steps"] = steps  # on failure this still shows how far the walk got
        body["total_ms"] = round((time.perf_counter() - start) * 1000, 1)
        self._send(json.dumps(body).encode(), "application/json")

    def _send(self, payload, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8053
    # loopback only: binding to 0.0.0.0 would turn this into an open resolver for the network
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"DNS resolver UI: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
