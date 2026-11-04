"""Run external analysis tools inside the analysis sandbox when possible.

Tools that parse untrusted firmware content (e.g. FwAnalyzer and the
filesystem utilities it drives) are executed in the same throw-away,
network-less container as the extraction stage.  Host paths under the scan's
work directory are rewritten to ``/work`` and the original upload to
``/in/firmware``.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from functools import lru_cache
from pathlib import Path

from .config import Settings
from .sandbox import SandboxError, _host_path, container_user, resolve_mode


@lru_cache(maxsize=16)
def image_has_binary(image: str, binary: str) -> bool:
    try:
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c",
                            f"command -v {binary}"], capture_output=True, timeout=60)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


class ToolExecutor:
    def __init__(self, settings: Settings, work_dir: Path | None = None, input_path: Path | None = None) -> None:
        self.settings = settings
        self.work_dir = work_dir
        self.input_path = input_path
        try:
            self.mode, _ = resolve_mode(settings)
        except SandboxError:
            self.mode = "unavailable"

    def locate(self, binary: str, local_override: str | None = None) -> tuple[str | None, str]:
        """Return (how, detail): how is 'sandbox', 'local' or None."""
        if self.mode == "docker" and image_has_binary(self.settings.sandbox_image, binary):
            return "sandbox", f"inside sandbox image {self.settings.sandbox_image} (no network)"
        local = local_override or shutil.which(binary)
        if local:
            note = "on the worker host (NOT container-isolated)"
            return "local", f"{local} {note}"
        return None, f"'{binary}' not found in the sandbox image or on PATH"

    def _translate(self, arg: str) -> str:
        if self.input_path is not None and arg == str(self.input_path):
            return "/in/firmware"
        if self.work_dir is not None:
            w = str(self.work_dir)
            if arg == w or arg.startswith(w + os.sep):
                return "/work" + arg[len(w):]
        return arg

    def run(self, how: str, cmd: list[str], timeout: int, writable: list[Path] | None = None) -> tuple[int, str, str, float]:
        if how == "sandbox":
            assert self.work_dir is not None
            s = self.settings
            full = ["docker", "run", "--rm", "--network", "none", "--read-only",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
                    "--memory", s.sandbox_memory, "--memory-swap", s.sandbox_memory, "--cpus", s.sandbox_cpus,
                    "--pids-limit", str(s.sandbox_pids), "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--user", container_user(*(writable or [])),
                    "-v", f"{_host_path(self.work_dir, s)}:/work:rw"]
            if self.input_path is not None:
                full += ["-v", f"{_host_path(self.input_path, s)}:/in/firmware:ro"]
            full += [s.sandbox_image] + [self._translate(a) for a in cmd]
        else:
            full = cmd
        t0 = time.monotonic()
        p = subprocess.run(full, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return (p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"),
                round(time.monotonic() - t0, 2))
