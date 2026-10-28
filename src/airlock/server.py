"""The SOC console server — standard library only.

    python -m airlock.server            # http://127.0.0.1:8765
    python -m airlock.server --classifier   # also ask the local Ollama model

Each request to /api/run?scenario=<id> runs that scenario twice on fresh tools —
once unguarded (the counterfactual), once through Airlock — and streams the
result as Server-Sent Events, paced so a human can follow it. Runs share no
state, so concurrent viewers never see each other's events.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import time
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from airlock.demo import POLICY, SCENARIOS, run

CONSOLE_DIR = (Path(__file__).resolve().parents[2] / "console").resolve()

_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; "
                               "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _scenario_items(sid: str, classifier) -> list[dict]:
    """Everything the console shows for one scenario, in order."""
    unguarded, _ = run(sid, with_airlock=False)
    items: list[dict] = [{"type": "counterfactual", "leaks": unguarded.leaks()}]

    def say(text: str) -> None:
        items.append({"type": "agent", "text": text})

    def on_event(ev) -> None:
        items.append({"type": "verdict", **asdict(ev)})

    guarded, gw = run(sid, with_airlock=True, on_event=on_event, say=say,
                      classifier=classifier)
    head = gw.audit.entries[-1].hash if gw.audit.entries else ""
    items.append({
        "type": "done",
        "leaks": guarded.leaks(),
        "audit": {"entries": len(gw.audit.entries), "head": head,
                  "verified": gw.audit.verify()},
    })
    return items


class Handler(BaseHTTPRequestHandler):
    classifier = None
    pace = 0.9

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in _HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj) -> None:
        self._send(HTTPStatus.OK, json.dumps(obj).encode(), "application/json")

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        if url.path == "/api/scenarios":
            return self._json({
                "scenarios": [{"id": s.id, "title": s.title, "attack": s.attack}
                              for s in SCENARIOS.values()],
                "policy": {
                    "org_domain": POLICY.org_domain,
                    "recipients": sorted(POLICY.allowlist_recipients),
                    "domains": sorted(POLICY.allowlist_domains),
                    "pii_threshold": POLICY.pii_egress_threshold,
                },
                "classifier": self.classifier is not None,
            })
        if url.path == "/api/run":
            sid = parse_qs(url.query).get("scenario", [""])[0]
            if sid not in SCENARIOS:
                return self._send(HTTPStatus.NOT_FOUND, b"unknown scenario", "text/plain")
            return self._stream(_scenario_items(sid, self.classifier))
        return self._static(url.path)

    def _stream(self, items: list[dict]) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        for k, v in _HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            for item in items:
                self.wfile.write(f"data: {json.dumps(item)}\n\n".encode())
                self.wfile.flush()
                if item["type"] in ("agent", "verdict"):
                    time.sleep(self.pace)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the viewer left mid-run

    def _static(self, path: str) -> None:
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (CONSOLE_DIR / rel).resolve()
        if not target.is_relative_to(CONSOLE_DIR) or not target.is_file():
            return self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(HTTPStatus.OK, target.read_bytes(), ctype)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Airlock SOC console")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--pace", type=float, default=0.9,
                    help="seconds between streamed events (default 0.9)")
    ap.add_argument("--classifier", action="store_true",
                    help="also ask the local Ollama model (qwen2.5:7b) about inbound content")
    args = ap.parse_args(argv)
    if args.classifier:
        from airlock.classifier import ollama_classifier
        Handler.classifier = staticmethod(ollama_classifier())
    Handler.pace = args.pace
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Airlock console on http://127.0.0.1:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
