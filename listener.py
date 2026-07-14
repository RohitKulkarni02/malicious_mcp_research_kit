#!/usr/bin/env python3
"""
Local HTTP exfil listener for MCP security research.

Logs incoming requests (path, query parameters, headers) to stdout and
optionally to a log file. Serves a tiny 1x1 GIF so markdown image fetches
complete successfully.

"""

from __future__ import annotations

import argparse
import base64
import json
import logging
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

# 1x1 transparent GIF
_TINY_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)

logger = logging.getLogger("listener")


def _decode_exfil_param(value: str) -> str | None:
    """Best-effort decode of base64url payloads from case tools."""

    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def format_request_record(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    parsed = urlparse(handler.path)
    query = {k: v if len(v) > 1 else v[0] for k, v in parse_qs(parsed.query).items()}

    decoded_payload = None
    if "d" in query and isinstance(query["d"], str):
        decoded_payload = _decode_exfil_param(query["d"])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": handler.command,
        "path": parsed.path,
        "query": query,
        "decoded_payload": decoded_payload,
        "client": handler.client_address[0],
        "headers": {k: v for k, v in handler.headers.items()},
    }


class ExfilListenerHandler(BaseHTTPRequestHandler):
    """Log all requests and return a harmless image response."""

    log_file: str | None = None

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr logging; we emit structured records instead.
        return

    def _handle(self) -> None:
        record = format_request_record(self)
        line = json.dumps(record, ensure_ascii=True)

        print(line, flush=True)
        logger.info("request %s %s", record["method"], record["path"])

        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

        if record["decoded_payload"]:
            print(
                f"[EXFIL] decoded payload: {record['decoded_payload']}",
                flush=True,
            )

        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(_TINY_GIF)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(_TINY_GIF)

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        record = format_request_record(self)
        print(json.dumps(record, ensure_ascii=True), flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(_TINY_GIF)))
        self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        record = format_request_record(self)
        record["body"] = body
        print(json.dumps(record, ensure_ascii=True), flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        payload = json.dumps({"status": "logged"}).encode("utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Local MCP exfil listener")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=9999, help="Bind port")
    parser.add_argument(
        "--log-file",
        default=None,
        help="Optional path to append JSON log lines",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    ExfilListenerHandler.log_file = args.log_file
    server = ThreadingHTTPServer((args.host, args.port), ExfilListenerHandler)

    print(f"Exfil listener running at http://{args.host}:{args.port}/", flush=True)
    print("Waiting for requests... (Ctrl+C to stop)", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down listener.", flush=True)
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
