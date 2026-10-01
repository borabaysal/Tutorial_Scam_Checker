"""Minimal stdlib web app: one page, one JSON endpoint.

    python -m scamcheck.web            # http://127.0.0.1:8765
    SCAMCHECK_HOST=0.0.0.0 SCAMCHECK_PORT=8080 python -m scamcheck.web
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .checker import MAX_INPUT_CHARS, check

STATIC = Path(__file__).parent / "static"
RATE_LIMIT_PER_MIN = int(os.environ.get("SCAMCHECK_RATE_LIMIT", "20"))
_hits: dict[str, list[float]] = {}
_lock = threading.Lock()


def _allowed(ip: str) -> bool:
    now = time.time()
    with _lock:
        recent = [t for t in _hits.get(ip, []) if now - t < 60]
        if len(recent) >= RATE_LIMIT_PER_MIN:
            _hits[ip] = recent
            return False
        recent.append(now)
        _hits[ip] = recent
        return True


class Handler(BaseHTTPRequestHandler):
    server_version = "ScamCheck/0.1"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        routes = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "application/javascript; charset=utf-8")}
        if self.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if self.path not in routes:
            return self._send(404, b"not found", "text/plain")
        name, ctype = routes[self.path]
        self._send(200, (STATIC / name).read_bytes(), ctype)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/check":
            return self._send(404, b"not found", "text/plain")
        if not _allowed(self.client_address[0]):
            return self._send(429, json.dumps({"error": "rate limited, try again in a minute"}).encode(), "application/json")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_INPUT_CHARS * 2:
            return self._send(413, json.dumps({"error": "input empty or too large"}).encode(), "application/json")
        try:
            payload = json.loads(self.rfile.read(length))
            text = str(payload.get("input", ""))
            use_llm = bool(payload.get("llm", True))
        except (ValueError, AttributeError):
            return self._send(400, json.dumps({"error": "invalid JSON"}).encode(), "application/json")
        if not text.strip():
            return self._send(400, json.dumps({"error": "paste Solidity code or a YouTube link"}).encode(), "application/json")
        report = check(text, use_llm=use_llm)
        self._send(200, json.dumps(report).encode(), "application/json")

    def log_message(self, fmt, *args):  # quieter logs, no request bodies
        print(f"{self.address_string()} {fmt % args}")


def main() -> None:
    host = os.environ.get("SCAMCHECK_HOST", "127.0.0.1")
    port = int(os.environ.get("SCAMCHECK_PORT", "8765"))
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"Tutorial Scam Checker on http://{host}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
