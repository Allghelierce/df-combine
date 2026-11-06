"""Tool adapter interface.

Each external analysis tool is wrapped by an adapter that

1. reports whether the tool is installed/reachable (:meth:`status`),
2. decides whether it is applicable to *this* firmware (:meth:`plan`) - tools
   are not interchangeable: cwe_checker wants ELF binaries, FwAnalyzer wants
   Linux filesystem images/trees, and
3. runs it and normalises its native output into :class:`Finding` objects.

Adapters never raise for expected failures; they return an
:class:`AdapterResult` with ``status`` set to one of
``completed | failed | skipped | unavailable | timeout``.
"""
from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..core.findings import Finding


@dataclass
class ToolStatus:
    name: str
    display_name: str
    available: bool
    detail: str
    mode: str | None = None  # local | docker | remote
    version: str | None = None
    enabled: bool = True
    homepage: str | None = None
    inputs: str | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class AdapterContext:
    scan_id: str
    input_path: Path
    original_name: str
    work_dir: Path
    manifest: dict
    settings: Settings
    log: Callable[[str], None] = lambda msg: None

    def artifact_path(self, art: dict) -> Path:
        """Resolve a manifest path. The manifest is produced inside the sandbox, so it is not trusted."""
        if art["path"] == "<input>":
            return self.input_path
        p = (self.work_dir / art["path"]).resolve()
        if not p.is_relative_to(self.work_dir.resolve()):
            raise ValueError(f"manifest path escapes the work directory: {art['path']!r}")
        return p

    def tool_dir(self, tool: str) -> Path:
        d = self.work_dir / "tools" / tool
        d.mkdir(parents=True, exist_ok=True)
        return d


@dataclass
class AdapterResult:
    status: str
    message: str
    findings: list[Finding] = field(default_factory=list)
    raw_output_path: str | None = None
    details: dict = field(default_factory=dict)


class ToolAdapter:
    name = "base"
    display_name = "Base"
    homepage = ""
    inputs = ""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def enabled(self) -> bool:
        return True

    def status(self) -> ToolStatus:  # pragma: no cover - interface
        raise NotImplementedError

    def plan(self, ctx: AdapterContext) -> tuple[list, str]:
        """Return (targets, reason). Empty targets => not applicable, reason explains why."""
        raise NotImplementedError  # pragma: no cover

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:  # pragma: no cover
        raise NotImplementedError

    # ---- helpers --------------------------------------------------------
    def _status(self, available: bool, detail: str, **kw) -> ToolStatus:
        return ToolStatus(name=self.name, display_name=self.display_name, available=available, detail=detail,
                          enabled=self.enabled(), homepage=self.homepage, inputs=self.inputs, **kw)

    def execute(self, ctx: AdapterContext) -> AdapterResult:
        if not self.enabled():
            return AdapterResult("skipped", f"{self.display_name} is disabled in configuration")
        st = self.status()
        if not st.available:
            return AdapterResult("unavailable", st.detail, details={"status": st.to_dict()})
        try:
            targets, reason = self.plan(ctx)
        except Exception as exc:  # noqa: BLE001
            return AdapterResult("failed", f"planning failed: {type(exc).__name__}: {exc}")
        if not targets:
            return AdapterResult("skipped", f"Not applicable: {reason}")
        try:
            res = self.run(ctx, targets)
        except subprocess.TimeoutExpired as exc:
            return AdapterResult("timeout", f"{self.display_name} timed out after {exc.timeout}s")
        except Exception as exc:  # noqa: BLE001 - adapters must not crash the scan
            return AdapterResult("failed", f"{type(exc).__name__}: {exc}")
        res.details.setdefault("mode", st.mode)
        res.details.setdefault("version", st.version)
        return res


def run_cmd(cmd: list[str], timeout: int, cwd: Path | None = None) -> tuple[int, str, str, float]:
    t0 = time.monotonic()
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd, stdin=subprocess.DEVNULL)
    return (p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"),
            round(time.monotonic() - t0, 2))
