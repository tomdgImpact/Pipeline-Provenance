"""A loopback collector standing in for the attacker's server.

It records what it receives so the demonstration can assert both halves: that
the naive pipeline delivered a secret, and that the hardened one delivered
nothing. Asserting only the second half would pass on a demonstration whose
attack never worked in the first place.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

MAX_BODY_BYTES = 64 * 1024


@dataclass
class Collector:
    """An in-memory collector bound to loopback for the life of one run."""

    received: list[dict[str, Any]] = field(default_factory=list)
    _server: HTTPServer | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("collector is not running")
        host, port = self._server.server_address[:2]
        # server_address is typed loosely; loopback is always a str here, and
        # formatting bytes into a URL would silently produce b'127.0.0.1'.
        return f"http://{host!s:s}:{port}/collect"

    def start(self) -> None:
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = min(int(self.headers.get("content-length", 0)), MAX_BODY_BYTES)
                body = self.rfile.read(length)
                try:
                    collector.received.append(json.loads(body))
                except json.JSONDecodeError:
                    collector.received.append({"raw": body.decode("utf-8", "replace")})
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args: Any) -> None:
                """Silent: the collector's output is the assertion, not the log."""

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> Collector:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
