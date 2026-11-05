"""Runs the untrusted-input analysis stage in an isolated environment.

Preferred: a throw-away Docker container with no network, a read-only root
filesystem, all capabilities dropped, ``no-new-privileges``, memory/CPU/PID
limits and the firmware mounted read-only.

Fallback (``sandbox_mode=local``, or ``auto`` when Docker is unavailable and
``allow_unsandboxed`` is true): a separate Python subprocess with rlimits
(address space, CPU time, file size, open files) and a wall-clock timeout.
This fallback is clearly reported as *not container-isolated*.
"""
from __future__ import annotations

import json
import os
import re
import resource
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import safefs
from .config import BACKEND_DIR, Settings
from .core.findings import Classification, Confidence, Severity
from .core.text import clean_strings


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxResult:
    manifest: dict
    isolation: str
    duration_s: float
    log_tail: str


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, timeout=10)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def docker_image_present(image: str) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def resolve_mode(settings: Settings) -> tuple[str, str]:
    """Return (mode, explanation). Modes: broker | docker | local."""
    from .containers import BrokerRunner

    mode = settings.sandbox_mode
    if mode == "local":
        return "local", "configured for local subprocess isolation (rlimits only, no container)"
    if settings.broker_socket:
        caps = BrokerRunner(settings).capabilities()
        refused = (caps.get("daemon") or {}).get("problems") or []
        if caps.get("images", {}).get(settings.sandbox_image) and not refused:
            rt = caps.get("runtime", "runc")
            return "broker", (f"Docker container '{settings.sandbox_image}' started by the sandbox broker "
                              f"(runtime {rt}; network disabled, read-only rootfs; worker has no Docker access)")
        problem = caps.get("error") or ("the broker refuses jobs: " + "; ".join(refused) if refused else
                                        f"broker reports image '{settings.sandbox_image}' missing")
        if mode in ("docker", "broker") or not settings.allow_unsandboxed:
            raise SandboxError(f"sandbox broker unusable: {problem}")
        return "local", f"sandbox broker unusable ({problem}) - fell back to local subprocess with rlimits"
    if mode == "broker":
        raise SandboxError("sandbox_mode=broker but DFA_BROKER_SOCKET is not configured")
    if docker_available() and docker_image_present(settings.sandbox_image):
        from .containers import DockerJobExecutor
        refused = DockerJobExecutor(settings).daemon_status()["problems"]
        if refused:
            raise SandboxError("Docker cannot sandbox analysis safely: " + "; ".join(refused))
        rt = f", runtime {settings.sandbox_runtime}" if settings.sandbox_runtime else ""
        return "docker", (f"Docker container '{settings.sandbox_image}' (network disabled, read-only rootfs{rt}; "
                          "worker uses Docker directly)")
    if mode == "docker":
        raise SandboxError(f"sandbox_mode=docker but Docker or image '{settings.sandbox_image}' is unavailable")
    if not settings.allow_unsandboxed:
        raise SandboxError("Docker sandbox unavailable and unsandboxed fallback is disabled")
    return "local", "Docker sandbox unavailable - fell back to local subprocess with rlimits (no container isolation)"


def reset_workdir(scan_id: str, settings: Settings) -> Path:
    """Fresh, empty work directory for a scan. With container isolation the broker (or Docker executor)
    creates it, because only the broker may write the work root (see docs/SECURITY.md)."""
    work = settings.work_root / scan_id
    mode, _ = resolve_mode(settings)
    if mode in ("docker", "broker"):
        from .containers import get_runner
        get_runner(settings).workdir(scan_id, "reset")
    else:
        if work.exists() or work.is_symlink():
            shutil.rmtree(work) if work.is_dir() and not work.is_symlink() else work.unlink()
        work.mkdir(parents=True)
    return work


def remove_workdir(scan_id: str, settings: Settings) -> None:
    mode, _ = resolve_mode(settings)
    if mode in ("docker", "broker"):
        from .containers import get_runner
        get_runner(settings).workdir(scan_id, "remove")
    else:
        shutil.rmtree(settings.work_root / scan_id, ignore_errors=True)


def scan_id_for(input_path: Path, work_dir: Path, settings: Settings) -> str:
    """Container jobs address scans by id; the paths must follow the standard data-dir layout."""
    scan_id = work_dir.name
    if (work_dir.resolve() != (settings.work_root / scan_id).resolve()
            or input_path.resolve() != (settings.uploads_dir / f"{scan_id}.bin").resolve()):
        raise SandboxError("container sandbox requires <data>/uploads/<id>.bin and <data>/work/<id>")
    return scan_id


def _mem_bytes(spec: str) -> int:
    spec = spec.strip().lower()
    mult = {"k": 1024, "m": 1024**2, "g": 1024**3}.get(spec[-1:], 1)
    return int(float(spec.rstrip("kmg")) * mult)


# Shape of the manifest the worker relies on (it is produced by the sandbox, so it is checked, not trusted).
MANIFEST_SCHEMA: dict[str, type | dict] = {
    "identification": dict, "components": list, "findings": list, "scanner_runs": list,
    "inventory": {"categories": dict},
    "extraction": {"artifacts": list, "filesystems": list, "warnings": list, "limits_hit": list, "stats": dict,
                   "link_count": int, "rootfs": object},
}


def _check_shape(obj: dict, schema: dict, where: str = "") -> None:
    for key, kind in schema.items():
        if key not in obj:
            raise ValueError(f"manifest lacks '{where}{key}'")
        if isinstance(kind, dict):
            if not isinstance(obj[key], dict):
                raise ValueError(f"manifest '{where}{key}' is not an object")
            _check_shape(obj[key], kind, f"{where}{key}.")
        elif not isinstance(obj[key], kind):
            raise ValueError(f"manifest '{where}{key}' is not a {kind.__name__}")
    if not where:
        for i, a in enumerate(obj["extraction"]["artifacts"][:200_000]):
            if not (isinstance(a, dict) and isinstance(a.get("id"), int) and isinstance(a.get("path"), str)
                    and isinstance(a.get("name"), str) and isinstance(a.get("format"), str)):
                raise ValueError(f"manifest artifact #{i} is malformed")
        for r in obj["scanner_runs"]:
            if not (isinstance(r, dict) and isinstance(r.get("name"), str) and isinstance(r.get("status"), str)
                    and isinstance(r.get("findings"), int)):
                raise ValueError("manifest scanner run entry is malformed")
        for i, f in enumerate(obj["findings"]):
            if not _finding_ok(f):
                raise ValueError(f"manifest finding #{i} is malformed")


_FINDING_TEXT = ("title", "description", "source_tool", "rule_id", "affected_component", "remediation")
_FINDING_ENUMS = {"severity": {s.value for s in Severity}, "classification": {c.value for c in Classification},
                  "confidence": {c.value for c in Confidence}}


def _str_list(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _finding_ok(f: object) -> bool:
    """Exactly the types the worker, the database and the UI rely on (no lists posing as strings, no dicts as
    references, no unknown severities)."""
    if not (isinstance(f, dict) and all(isinstance(f.get(k), str) for k in _FINDING_TEXT)):
        return False
    if any(not isinstance(f.get(k), str) or f.get(k) not in allowed for k, allowed in _FINDING_ENUMS.items()):
        return False
    if not (_str_list(f.get("references", [])) and _str_list(f.get("tags", []))):
        return False
    if any(f.get(k) is not None and not isinstance(f.get(k), str) for k in ("cwe", "package")):
        return False
    ev = f.get("evidence", [])
    return isinstance(ev, list) and all(
        isinstance(e, dict) and set(e) <= {"kind", "value", "location"} and isinstance(e.get("kind"), str)
        and isinstance(e.get("value"), str) and (e.get("location") is None or isinstance(e.get("location"), str))
        for e in ev)


# A lone surrogate reaches a parsed string only as a \uD800-\uDFFF escape or as its (CESU-8) bytes.
_MAYBE_SURROGATE = re.compile(rb"\\u[dD][89a-fA-F]|\xed[\xa0-\xbf]")


def load_manifest(base: Path, name: str, settings: Settings) -> dict:
    """Parse a sandbox-produced manifest: size-limited, no links followed, shape checked.
    Raises FileNotFoundError, OSError, ValueError or RecursionError (deeply nested JSON)."""
    raw = safefs.read_bytes(base, name, settings.max_manifest_mb * 1024 * 1024)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("manifest is not a JSON object")
    if _MAYBE_SURROGATE.search(raw):  # lone surrogates cannot be stored or served: show them as \xNN
        clean_strings(data)
    if "fatal_error" not in data:
        _check_shape(data, MANIFEST_SCHEMA)
    return data


PROGRESS_LINES_PER_POLL = 20


def _pump_progress(work_dir: Path, progress: Callable[[str], None] | None, seen: int) -> int:
    if not progress:
        return seen
    try:  # written by the sandbox while it runs: never follow a link or block on a FIFO
        lines = safefs.read_text(work_dir, "progress.log", 8 * 1024 * 1024).splitlines()
    except OSError:
        return seen
    for ln in lines[seen:][-PROGRESS_LINES_PER_POLL:]:  # a flood of lines cannot turn into a flood of events
        progress(ln.split(" ", 1)[-1][:500])
    return len(lines)


def run_analysis(input_path: Path, original_name: str, work_dir: Path, settings: Settings,
                 progress: Callable[[str], None] | None = None) -> SandboxResult:
    mode, explanation = resolve_mode(settings)
    if not work_dir.is_dir():
        work_dir.mkdir(parents=True)
    os.chmod(work_dir, 0o755)
    t0 = time.monotonic()
    if mode in ("docker", "broker"):
        from .containers import get_runner

        scan_id = scan_id_for(input_path, work_dir, settings)
        runner = get_runner(settings)
        holder: dict = {}

        def job() -> None:
            try:
                holder["res"] = runner.run("analyze", scan_id, {"name": original_name,
                                                                "limits": settings.limits_dict()})
            except Exception as exc:  # noqa: BLE001
                holder["exc"] = exc

        th = threading.Thread(target=job, daemon=True)
        th.start()
        seen = 0
        while th.is_alive():
            th.join(0.5)
            seen = _pump_progress(work_dir, progress, seen)
        _pump_progress(work_dir, progress, seen)
        if "exc" in holder:
            raise SandboxError(f"analysis sandbox could not run: {holder['exc']}")
        res = holder["res"]
        log_tail = (res.stdout + res.stderr)[-4000:]
        if res.killed_reason:
            raise SandboxError(f"analysis sandbox stopped: {res.killed_reason}")
        returncode = res.exit_code
    else:
        safe_name = "".join(c for c in original_name if c.isprintable())[:255] or "firmware"
        cmd = [sys.executable, "-m", "dfa.core.analyze", "--input", str(input_path), f"--name={safe_name}",
               "--work", str(work_dir), f"--limits={json.dumps(settings.limits_dict())}"]
        mem = _mem_bytes(settings.sandbox_memory)
        cpu = settings.sandbox_timeout_s
        fsize = settings.max_extract_file_mb * 1024 * 1024 + 1

        def preexec() -> None:  # pragma: no cover - runs in the child
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()

        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(BACKEND_DIR),
               "LANG": "C.UTF-8", "HOME": str(work_dir)}
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                preexec_fn=preexec, env=env, cwd=str(BACKEND_DIR))
        tail: list[str] = []

        def reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                tail.append(line.decode("utf-8", "replace"))
                del tail[:-50]

        th = threading.Thread(target=reader, daemon=True)
        th.start()
        seen = 0
        timed_out = False
        while proc.poll() is None:
            time.sleep(0.5)
            seen = _pump_progress(work_dir, progress, seen)
            if time.monotonic() - t0 > settings.sandbox_timeout_s:
                timed_out = True
                proc.kill()
                break
        proc.wait()
        th.join(timeout=5)
        log_tail = "".join(tail)[-4000:]
        if timed_out:
            raise SandboxError(f"analysis sandbox timed out after {settings.sandbox_timeout_s}s")
        returncode = proc.returncode
    try:
        manifest = load_manifest(work_dir, "manifest.json", settings)
    except FileNotFoundError:
        raise SandboxError(f"analysis sandbox exited with status {returncode} without a manifest. "
                           f"Output: {log_tail[-1500:]}") from None
    except (OSError, ValueError, RecursionError) as exc:
        raise SandboxError(f"unusable manifest from the analysis sandbox: {exc}") from None
    if "fatal_error" in manifest:
        raise SandboxError(f"analysis failed: {manifest['fatal_error']}")
    if returncode != 0:
        raise SandboxError(f"analysis sandbox exited with status {returncode}: {log_tail[-1500:]}")
    return SandboxResult(manifest=manifest, isolation=f"{mode}: {explanation}",
                         duration_s=round(time.monotonic() - t0, 2), log_tail=log_tail)
