"""Runs the untrusted-input analysis stage in an isolated environment.

Preferred: a throw-away Docker container with no network, a read-only root
filesystem, all capabilities dropped, ``no-new-privileges``, memory/CPU/PID
limits and the firmware mounted read-only.

Fallback (``sandbox_mode=local``, or ``auto`` when Docker is unavailable and
``allow_unsandboxed`` is true): a separate Python subprocess with rlimits
(address space, CPU time, file size, open files) and a wall-clock timeout.
On macOS, which rejects address-space limits, the memory limit is enforced by
watching the subprocess's resident size instead. This fallback is clearly
reported as *not container-isolated*.
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import BACKEND_DIR, Settings


class SandboxError(RuntimeError):
    pass


# macOS reserves hundreds of GB of virtual address space for every process (dyld shared cache etc.) and
# rejects any RLIMIT_AS below that with EINVAL ("current limit exceeds maximum limit"). There the local
# fallback enforces the memory limit by watching the child's resident size instead.
ADDRESS_SPACE_LIMIT = sys.platform != "darwin"


def _rss_bytes(pid: int) -> int:
    """Current resident size of ``pid`` in bytes, or 0 if it cannot be read."""
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=5,
                             stdin=subprocess.DEVNULL).stdout
        return int(out.strip() or 0) * 1024
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


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
    """Return (mode, explanation)."""
    mode = settings.sandbox_mode
    if mode == "local":
        return "local", "configured for local subprocess isolation (rlimits only, no container)"
    if docker_available() and docker_image_present(settings.sandbox_image):
        return "docker", f"Docker container '{settings.sandbox_image}' (network disabled, read-only rootfs)"
    if mode == "docker":
        raise SandboxError(f"sandbox_mode=docker but Docker or image '{settings.sandbox_image}' is unavailable")
    if not settings.allow_unsandboxed:
        raise SandboxError("Docker sandbox unavailable and unsandboxed fallback is disabled")
    return "local", "Docker sandbox unavailable - fell back to local subprocess with rlimits (no container isolation)"


SANDBOX_UID = 10001  # 'analyzer' user in docker/sandbox.Dockerfile


def container_user(*writable: Path) -> str:
    """User for sandbox containers. Never root: if the worker runs as root, hand the
    writable directories to the image's unprivileged 'analyzer' user."""
    if os.getuid() != 0:
        return f"{os.getuid()}:{os.getgid()}"
    for d in writable:
        for dirpath, _dirs, filenames in os.walk(d):
            os.chown(dirpath, SANDBOX_UID, SANDBOX_UID)
            for f in filenames:
                os.chown(os.path.join(dirpath, f), SANDBOX_UID, SANDBOX_UID, follow_symlinks=False)
    return f"{SANDBOX_UID}:{SANDBOX_UID}"


def _host_path(p: Path, settings: Settings) -> str:
    if settings.sandbox_host_data_dir:
        try:
            rel = p.resolve().relative_to(settings.data_dir.resolve())
        except ValueError:
            return str(p.resolve())
        return str(settings.sandbox_host_data_dir / rel)
    return str(p.resolve())


def _mem_bytes(spec: str) -> int:
    spec = spec.strip().lower()
    mult = {"k": 1024, "m": 1024**2, "g": 1024**3}.get(spec[-1:], 1)
    return int(float(spec.rstrip("kmg")) * mult)


def run_analysis(input_path: Path, original_name: str, work_dir: Path, settings: Settings,
                 progress: Callable[[str], None] | None = None) -> SandboxResult:
    mode, explanation = resolve_mode(settings)
    work_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(work_dir, 0o755)
    safe_name = "".join(c for c in original_name if c.isprintable())[:255] or "firmware"
    limits = json.dumps(settings.limits_dict())
    if mode == "docker":
        cmd = [
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--memory", settings.sandbox_memory, "--memory-swap", settings.sandbox_memory,
            "--cpus", settings.sandbox_cpus, "--pids-limit", str(settings.sandbox_pids),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", container_user(work_dir),
            "-v", f"{_host_path(input_path, settings)}:/in/firmware:ro",
            "-v", f"{_host_path(work_dir, settings)}:/work:rw",
            settings.sandbox_image,
            "python", "-m", "dfa.core.analyze", "--input", "/in/firmware", f"--name={safe_name}",
            "--work", "/work", "--limits", limits,
        ]
        preexec = None
        env = None
        mem, watch_memory = 0, False
    else:
        cmd = [sys.executable, "-m", "dfa.core.analyze", "--input", str(input_path), f"--name={safe_name}",
               "--work", str(work_dir), "--limits", limits]
        mem = _mem_bytes(settings.sandbox_memory)
        cpu = settings.sandbox_timeout_s
        fsize = settings.max_extract_file_mb * 1024 * 1024 + 1
        watch_memory = not ADDRESS_SPACE_LIMIT
        if watch_memory:
            explanation += "; memory limit enforced by a resident-size watchdog (macOS rejects RLIMIT_AS)"

        def preexec() -> None:  # pragma: no cover - runs in the child
            if not watch_memory:
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()

        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(BACKEND_DIR),
               "LANG": "C.UTF-8", "HOME": str(work_dir)}

    t0 = time.monotonic()
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
    progress_file = work_dir / "progress.log"
    seen = 0
    timed_out = over_memory = False
    peak_rss = 0

    def exited() -> bool:
        nonlocal peak_rss
        if not watch_memory:
            return proc.poll() is not None
        # Reap with wait4 to learn the child's peak resident size.
        try:
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
        except ChildProcessError:
            return proc.poll() is not None
        if pid == 0:
            return False
        proc.returncode = os.waitstatus_to_exitcode(status)
        peak_rss = usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)  # bytes on macOS, KiB elsewhere
        return True

    def kill() -> None:
        if not watch_memory:
            proc.kill()
            return
        try:  # not reaped yet, so the pid is still ours; Popen.kill() would reap it behind wait4's back
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    while not exited():
        time.sleep(0.5)
        if progress and progress_file.exists():
            lines = progress_file.read_text(errors="replace").splitlines()
            for ln in lines[seen:]:
                progress(ln.split(" ", 1)[-1])
            seen = len(lines)
        if watch_memory and not over_memory and _rss_bytes(proc.pid) > mem:
            over_memory = True
            kill()
            continue
        if time.monotonic() - t0 > settings.sandbox_timeout_s:
            timed_out = True
            kill()
            break
    proc.wait()
    th.join(timeout=5)
    log_tail = "".join(tail)[-4000:]
    if timed_out:
        raise SandboxError(f"analysis sandbox timed out after {settings.sandbox_timeout_s}s")
    if over_memory or (watch_memory and peak_rss > mem):
        raise SandboxError(f"analysis sandbox exceeded its memory limit of {settings.sandbox_memory} "
                           f"(peak resident size {peak_rss / 2**20:.0f} MiB)")
    manifest_path = work_dir / "manifest.json"
    if not manifest_path.exists():
        raise SandboxError(f"analysis sandbox exited with status {proc.returncode} without a manifest. "
                           f"Output: {log_tail[-1500:]}")
    manifest = json.loads(manifest_path.read_text())
    if "fatal_error" in manifest:
        raise SandboxError(f"analysis failed: {manifest['fatal_error']}")
    if proc.returncode != 0:
        raise SandboxError(f"analysis sandbox exited with status {proc.returncode}: {log_tail[-1500:]}")
    return SandboxResult(manifest=manifest, isolation=f"{mode}: {explanation}",
                         duration_s=round(time.monotonic() - t0, 2), log_tail=log_tail)
