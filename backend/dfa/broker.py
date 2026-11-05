"""Sandbox broker: the only Drone Firmware Analyzer process with Docker access.

The API server and the worker never get the Docker socket. Instead the worker
sends small JSON job requests over a Unix socket::

    POST /v1/jobs {"profile": "analyze|fwanalyzer|cwe_checker|ghidra", "scan_id": "<uuid>", "params": {...}}
    GET  /v1/capabilities
    GET  /v1/health

The broker validates the request against the fixed profiles in
``dfa.containers`` (image, entry point, mounts, hardening flags and limits are
not caller-controlled), runs the container and returns exit code and output.
A compromised worker can therefore only start the same network-less,
read-only, capability-free sandbox jobs on its own scan directories - not
arbitrary (e.g. privileged) containers.

Run:  python -m dfa.broker --socket /run/dfa/broker.sock [--group dfa] [--mode 660]
Optional shared secret: DFA_BROKER_TOKEN (sent by the worker as a bearer token).
"""
from __future__ import annotations

import argparse
import grp
import hmac
import json
import logging
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from .config import Settings
from .containers import PROFILES, DockerJobExecutor, JobRejected

log = logging.getLogger("dfa.broker")
MAX_BODY = 64 * 1024


class BrokerHandler(BaseHTTPRequestHandler):
    server_version = "dfa-broker/1"
    executor: DockerJobExecutor
    token: str | None

    def log_message(self, fmt: str, *args) -> None:  # noqa: D401 - quieter, no client address on UDS
        log.info("%s", fmt % args)

    def address_string(self) -> str:
        return "unix"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not self.token:
            return True
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, f"Bearer {self.token}")

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/v1/health":
            return self._send(200, {"status": "ok"})
        if self.path == "/v1/capabilities":
            caps = self.executor.capabilities()
            caps["broker"] = True
            return self._send(200, caps)
        return self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path != "/v1/jobs":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self._send(400, {"error": "missing or oversized request body"})
        try:
            req = json.loads(self.rfile.read(length))
            profile, scan_id, params = req["profile"], req["scan_id"], req.get("params") or {}
            if profile not in PROFILES or not isinstance(params, dict):
                raise JobRejected("unknown profile or malformed params")
            log.info("job %s for scan %s", profile, scan_id)
            res = self.executor.run(profile, scan_id, params)
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": f"malformed request: {exc}"})
        except JobRejected as exc:
            log.warning("rejected job: %s", exc)
            return self._send(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            log.exception("job failed")
            return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})
        res.runner = "broker"
        return self._send(200, res.to_dict())


class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(socket_path: Path, settings: Settings, mode: int = 0o660, group: str | None = None,
          token: str | None = None) -> ThreadingUnixServer:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
    handler = type("Handler", (BrokerHandler,), {"executor": DockerJobExecutor(settings), "token": token})
    server = ThreadingUnixServer(str(socket_path), handler)
    os.chmod(socket_path, mode)
    if group:
        os.chown(socket_path, -1, int(group) if group.isdigit() else grp.getgrnam(group).gr_gid)
    return server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Drone Firmware Analyzer sandbox broker")
    ap.add_argument("--socket", default=os.environ.get("DFA_BROKER_SOCKET", "/run/dfa/broker.sock"))
    ap.add_argument("--group", default=os.environ.get("DFA_BROKER_GROUP"),
                    help="group (name or numeric GID) allowed to use the socket")
    ap.add_argument("--mode", default="660", help="socket permissions (octal)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings()
    settings.broker_socket = None  # the broker itself always executes directly
    server = serve(Path(args.socket), settings, int(args.mode, 8), args.group, os.environ.get("DFA_BROKER_TOKEN"))
    log.info("broker listening on %s (profiles: %s)", args.socket, ", ".join(sorted(PROFILES)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
