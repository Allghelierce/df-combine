"""Mutation fuzzing of the whole chain an upload goes through: the API upload, the worker (the analysis runs in the
local sandbox, a subprocess with resource limits), ingestion of the manifest into the database, and every view and
export of the result: scan detail, findings, artifacts, packages, the JSON/PDF/SARIF reports and the CycloneDX SBOM.

Seeds and mutations are scripts/fuzz_extract.py's. For every input the scan must complete (not fail) and every route
must answer 200 with a body of its declared type. External tools (cwe_checker, Ghidra, FACT) are configured away, as
in the API tests. Usage (from the repository root; inputs per seed, optional seed names):

    .venv/bin/python scripts/fuzz_pipeline.py 40 /tmp/fuzz-pipeline-out [seed ...]
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path

import fuzz_extract as fx  # noqa: I001 - sets up sys.path for dfa

from dfa.config import Settings

PASSWORD = "fuzz-pipeline-password-1"  # noqa: S105 - throwaway admin of a temporary database
ROUTES = {"": "application/json", "/findings": "application/json", "/artifacts": "application/json",
          "/packages": "application/json", "/report.json": "application/json", "/report.pdf": "application/pdf",
          "/report.sarif": "application/sarif+json", "/sbom.cdx.json": "application/vnd.cyclonedx+json"}


def check_scan(client, settings, name: str, data: bytes) -> tuple[str | None, str]:
    from dfa.worker import claim_next, run_one
    r = client.post("/api/scans", files={"file": (f"{name}.bin", data, "application/octet-stream")})
    if r.status_code != 201:
        return f"upload {r.status_code}", r.text[:200]
    sid = r.json()["id"]
    try:
        while (claimed := claim_next("fuzz-worker")):
            run_one(claimed, settings)
        detail = client.get(f"/api/scans/{sid}").json()
        if detail["status"] != "completed":
            return f"scan {detail['status']}", str(detail.get("error"))[:300]
        for route, ctype in ROUTES.items():
            resp = client.get(f"/api/scans/{sid}{route}")
            if resp.status_code != 200:
                return f"GET {route or '/'} {resp.status_code}", resp.text[:200]
            if not resp.headers.get("content-type", "").startswith(ctype):
                return f"GET {route or '/'} content-type", resp.headers.get("content-type", "")
            if ctype.endswith("json"):
                json.loads(resp.content)  # well-formed (no NaN, no lone surrogates)
            elif not resp.content.startswith(b"%PDF"):
                return f"GET {route} not a PDF", resp.content[:40].hex()
        return None, detail["status"]
    finally:
        client.delete(f"/api/scans/{sid}")


def main(argv: list[str]) -> int:
    per_seed, out, only = int(argv[0]), Path(argv[1]).resolve(), set(argv[2:])
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="dfa-fuzz-pipeline-"))
    settings = Settings(data_dir=tmp / "data", sandbox_mode="local", fact_url=None,
                        cwe_checker_image="dfa-test/nonexistent-cwe-checker:none",
                        ghidra_image="dfa-test/nonexistent-ghidra:none", worker_mode="external", max_upload_mb=64,
                        upload_rate_per_hour=1_000_000, min_free_disk_mb=0)
    settings.bootstrap_admin, settings.bootstrap_admin_password = "admin", PASSWORD
    from fastapi.testclient import TestClient

    from dfa.main import create_app
    failed = 0
    try:
        with TestClient(create_app(settings, start_worker=False)) as client:
            r = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
            r.raise_for_status()
            client.headers["X-DFA-CSRF"] = "1"
            for name, (seed, hot) in fx.build_seeds(tmp / "seeds").items():
                if only and name not in only:
                    continue
                errs, t0 = Counter(), time.monotonic()
                for i in range(per_seed):
                    data = seed if i == 0 else fx.mutate(seed, [h for h in hot if 0 <= h < len(seed)])
                    if not data:
                        continue  # the API refuses empty uploads (400), as it should
                    try:
                        key, detail = check_scan(client, settings, name, data)
                    except Exception as exc:  # noqa: BLE001
                        tb = traceback.extract_tb(exc.__traceback__)[-1]
                        key, detail = f"{type(exc).__name__} @ {Path(tb.filename).name}:{tb.lineno}", str(exc)[:200]
                    if key:
                        errs[key] += 1
                        if errs[key] <= 2:
                            rep = out / f"repro_{name}_{len(errs)}_{errs[key]}.bin"
                            rep.write_bytes(data)
                            print(f"  {name}: {key} ({detail}) -> {rep.name}", flush=True)
                print(f"{name:22s} {per_seed:5d} scans in {time.monotonic() - t0:6.0f}s, unexpected: "
                      f"{dict(errs) or 'none'}", flush=True)
                failed += bool(errs)
    finally:
        fx._rmtree(tmp)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
