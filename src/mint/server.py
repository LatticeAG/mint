"""Local simulation HTTP server: POST /v1/commands plus the §8.5 read
routes. A development harness, not the production edge."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .jsonutil import jcs_text


def make_handler(engine):
    class H(BaseHTTPRequestHandler):
        def _send(self, code: int, obj: dict,
                  extra_headers: dict | None = None):
            body = jcs_text(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # quiet
            pass

        def do_POST(self):
            if self.path == "/v1/commands":
                n = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(n)
                headers = {k: v for k, v in self.headers.items()}
                code, resp = engine.execute(headers, body)
                self._send(code, resp)
                return
            self._send(404, {"error": {"code": "NOT_FOUND",
                                      "message": "unknown route",
                                      "retryable": False,
                                      "details": {}}})

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path == "/v1/health":
                    return self._send(200, engine.get_health())
                if u.path.startswith("/v1/tasks/"):
                    return self._send(200, engine.get_task(
                        u.path.rsplit("/", 1)[-1]))
                if u.path.startswith("/v1/accounts/"):
                    actor = u.path.rsplit("/", 1)[-1]
                    return self._send(200, engine.get_account(
                        actor, q.get("asset", ["SIMUSD"])[0]))
                if u.path.startswith("/v1/clearings/"):
                    parts = u.path.split("/")
                    return self._send(200, engine.get_clearing(
                        parts[-2], int(parts[-1])))
                if u.path.startswith("/v1/cases/"):
                    return self._send(200, engine.get_case(
                        u.path.rsplit("/", 1)[-1]))
                if u.path.startswith("/v1/artifacts/"):
                    return self._send(200, engine.get_artifact(
                        u.path.split("/")[-1]))
                if u.path == "/v1/log":
                    return self._send(200, engine.get_log(
                        int(q.get("after", [0])[0]),
                        int(q.get("limit", [1000])[0]),
                        q.get("checkpoint", [None])[0]))
                if u.path.startswith("/v1/checkpoints/"):
                    cp = engine.get_checkpoint(
                        u.path.rsplit("/", 1)[-1])
                    sigs = jcs_text(cp.pop("signatures"))
                    return self._send(200, cp, {
                        "Mint-Witness-Signatures": sigs})
                if u.path == "/v1/proofs":
                    return self._send(200, engine.get_proof(
                        q["checkpoint"][0], int(q["seq"][0])))
            except Exception as e:
                from .errors import MintError
                if isinstance(e, MintError):
                    return self._send(e.http, e.body())
                return self._send(500, {"error": {"code": "INTERNAL",
                                                  "message": str(e),
                                                  "retryable": False,
                                                  "details": {}}})
            self._send(404, {"error": {"code": "NOT_FOUND",
                                      "message": "unknown route",
                                      "retryable": False,
                                      "details": {}}})

    return H


def serve(engine, listen: str) -> ThreadingHTTPServer:
    host, port = listen.rsplit(":", 1)
    httpd = ThreadingHTTPServer((host, int(port)), make_handler(engine))
    return httpd
