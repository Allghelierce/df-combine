"""FwAnalyzer adapter (https://github.com/cruise-automation/fwanalyzer).

Facts established from the upstream project and by running it:
* Input: a Linux filesystem image (ext2/3/4 via e2tools, SquashFS via
  squashfs-tools, UBIFS via ubi_reader, VFAT via mtools, cpio) or a
  directory (``dirfs``).  It does not understand MCU firmware such as PX4
  or ArduPilot flight controller images.
* Rules are a TOML config; output is a JSON report with ``offenders``,
  ``informational`` and ``data``.
* With stock (unpatched) e2tools the ext parser panics; upstream documents a
  patched e2tools fork.  When an image-level run fails we fall back to
  ``dirfs`` over our own extracted tree - in that mode file ownership/mode
  bits are NOT available (they are normalised during safe extraction), so
  permission checks are disabled and noted.
* The upstream repository is no longer actively developed.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from .base import AdapterContext, AdapterResult, ToolAdapter, run_cmd

FS_TYPES = {"ext": "extfs", "squashfs": "squashfs", "fat": "vfatfs", "cpio": "cpiofs"}
BAD_FILES = [
    ("/etc/ssh/ssh_host_*_key", S.high, "SSH host private key shipped in image"),
    ("/etc/dropbear/dropbear_*_host_key", S.high, "Dropbear host key shipped in image"),
    ("**/id_rsa", S.high, "SSH private key shipped in image"),
    ("**/id_ecdsa", S.high, "SSH private key shipped in image"),
    ("**/id_ed25519", S.high, "SSH private key shipped in image"),
    ("**/authorized_keys", S.medium, "Pre-installed SSH authorized_keys"),
    ("**/.bash_history", S.low, "Shell history left in image"),
    ("**/.ash_history", S.low, "Shell history left in image"),
    ("/usr/sbin/telnetd", S.medium, "Telnet daemon present"),
    ("/usr/sbin/utelnetd", S.medium, "Telnet daemon present"),
    ("/usr/bin/gdbserver", S.medium, "Debugger server present"),
    ("/usr/bin/strace", S.low, "Debugging tool present"),
]


class FwAnalyzerAdapter(ToolAdapter):
    name = "fwanalyzer"
    display_name = "FwAnalyzer (Cruise)"
    homepage = "https://github.com/cruise-automation/fwanalyzer"
    inputs = "Linux filesystem images (ext2/3/4, SquashFS, UBIFS, VFAT, cpio) or extracted directories"

    def enabled(self) -> bool:
        return self.settings.fwanalyzer_enabled

    def _bin(self) -> str | None:
        return self.settings.fwanalyzer_bin or shutil.which("fwanalyzer")

    def status(self):
        b = self._bin()
        if not b:
            return self._status(False, "fwanalyzer binary not found on PATH. Build it with "
                                       "'go install github.com/cruise-automation/fwanalyzer/cmd/fwanalyzer@latest' "
                                       "(see docs/TOOLS.md).")
        helpers = {t: bool(shutil.which(t)) for t in ("e2ls", "unsquashfs", "mcopy", "cpio")}
        missing = [t for t, ok in helpers.items() if not ok]
        detail = f"local binary {b}" + (f"; missing helper tools: {', '.join(missing)}" if missing else "")
        return self._status(True, detail, mode="local")

    def plan(self, ctx: AdapterContext):
        man = ctx.manifest.get("extraction", {})
        arts = {a["id"]: a for a in man.get("artifacts", [])}
        targets = []
        for fs in man.get("filesystems", []):
            fstype = FS_TYPES.get(fs["type"])
            art = arts.get(fs.get("image_artifact", fs["artifact_id"]))
            if not art:
                continue
            fallback = fs.get("root")
            if fstype and _looks_like_rootfs(ctx.work_dir / fs["root"]):
                targets.append({"kind": "image", "fstype": fstype, "artifact": art, "fallback_dir": fallback})
            elif fs["type"] in ("tar", "zip", "romfs") and _looks_like_rootfs(ctx.work_dir / fs["root"]):
                targets.append({"kind": "dir", "fstype": "dirfs", "artifact": art, "fallback_dir": fallback})
        if not targets:
            return [], ("no Linux root filesystem was found (FwAnalyzer analyses Linux filesystem images; it does "
                        "not apply to flight-controller MCU firmware such as PX4/ArduPilot binaries)")
        return targets[:4], f"{len(targets)} filesystem(s)"

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        b = self._bin()
        assert b
        findings: list[Finding] = []
        runs = []
        for i, t in enumerate(targets):
            art = t["artifact"]
            report, mode, note = None, t["fstype"], None
            if t["kind"] == "image":
                report, err = self._run_one(b, out_dir, i, t["fstype"], ctx.artifact_path(art),
                                            ctx.work_dir / t["fallback_dir"], perms=True)
                if report is None:
                    note = f"image mode ({t['fstype']}) failed: {err}; fell back to dirfs on extracted tree"
                    ctx.log(f"fwanalyzer: {note}")
            if report is None:
                mode = "dirfs"
                report, err = self._run_one(b, out_dir, i, "dirfs", ctx.work_dir / t["fallback_dir"],
                                            ctx.work_dir / t["fallback_dir"], perms=False)
                if report is None:
                    runs.append({"target": art["display_path"], "status": "failed", "error": err, "note": note})
                    continue
            fs = normalize(report, art["display_path"], perms=(mode != "dirfs"))
            findings += fs
            runs.append({"target": art["display_path"], "status": "completed", "mode": mode, "note": note,
                         "offenders": len(report.get("offenders", {}) or {}),
                         "informational": len(report.get("informational", {}) or {})})
        ok = sum(1 for r in runs if r["status"] == "completed")
        status = "completed" if ok else "failed"
        msg = f"analysed {ok}/{len(targets)} filesystem(s), {len(findings)} findings"
        notes = [r["note"] for r in runs if r.get("note")]
        if notes:
            msg += " - " + "; ".join(notes)
        if not ok:
            msg = "; ".join(r.get("error", "") for r in runs)[:800]
        return AdapterResult(status, msg, findings, str(out_dir), {"runs": runs})

    def _run_one(self, b: str, out_dir: Path, i: int, fstype: str, target: Path, tree: Path,
                 perms: bool) -> tuple[dict | None, str]:
        cfg = out_dir / f"config_{i}_{fstype}.toml"
        cfg.write_text(build_config(fstype, tree, perms))
        out = out_dir / f"report_{i}_{fstype}.json"
        rc, stdout, stderr, _ = run_cmd([b, "-cfg", str(cfg), "-in", str(target), "-out", str(out)],
                                        timeout=self.settings.fwanalyzer_timeout_s)
        (out_dir / f"stderr_{i}_{fstype}.log").write_text((stdout + stderr)[-20000:])
        if rc != 0 or not out.exists():
            first = (stderr or stdout).strip().splitlines()[:1]
            return None, f"exit code {rc}: {first[0][:200] if first else 'no output'}"
        try:
            return json.loads(out.read_text()), ""
        except json.JSONDecodeError as exc:
            return None, f"invalid JSON report: {exc}"


def _looks_like_rootfs(d: Path) -> bool:
    return d.is_dir() and (d / "etc").is_dir() and any((d / x).is_dir() for x in ("bin", "sbin", "usr", "lib"))


def _toml_str(s: str) -> str:
    return json.dumps(s)  # JSON string escaping is valid TOML basic-string escaping


def build_config(fstype: str, tree: Path, perms: bool) -> str:
    lines = ["[GlobalConfig]", f"FsType = {_toml_str(fstype)}", "DigestImage = true", "",
             "[GlobalFileChecks]", f"Suid = {'true' if perms else 'false'}", "SuidAllowedList = []",
             f"WorldWrite = {'true' if perms else 'false'}",
             "BadFiles = [" + ", ".join(_toml_str(p) for p, _, _ in BAD_FILES) + "]", ""]
    # FileContent checks only for files that exist (a missing file is reported as an offender).
    if (tree / "etc/shadow").is_file():
        lines += ['[FileContent."shadow_empty_password"]', 'File = "/etc/shadow"', 'RegEx = "^[^:]+::"',
                  "RegExLineByLine = true", "Match = true", 'Desc = "account with empty password"', ""]
    if (tree / "etc/ssh/sshd_config").is_file():
        lines += ['[FileContent."sshd_permit_empty"]', 'File = "/etc/ssh/sshd_config"',
                  'RegEx = "^\\\\s*PermitEmptyPasswords\\\\s+yes"', "RegExLineByLine = true", "Match = true",
                  'Desc = "sshd allows empty passwords"', ""]
    if (tree / "etc/inittab").is_file():
        lines += ['[FileContent."inittab_telnetd"]', 'File = "/etc/inittab"', 'RegEx = "^[^#]*telnetd"',
                  "RegExLineByLine = true", "Match = true", 'Desc = "telnetd started from inittab"', ""]
    return "\n".join(lines) + "\n"


def _classify(msg: str, path: str, perms: bool) -> tuple[str, S, str, str]:
    """Return (rule, severity, title, cwe) for an FwAnalyzer offender message."""
    m = msg.lower()
    if "suid" in m:
        return "fwa-suid", S.low, "setuid file not in allow-list", "CWE-250"
    if "worldwrite" in m:
        return "fwa-world-writable", S.medium, "World-writable file", "CWE-732"
    if "not allowed for pattern" in m or m.startswith("file not allowed"):
        for pat, sev, title in BAD_FILES:
            if pat in msg:
                return "fwa-bad-file", sev, title, "CWE-200"
        return "fwa-bad-file", S.medium, "Disallowed file present", "CWE-200"
    if "empty password" in m:
        return "fwa-empty-password", S.critical if "line: root::" in msg else S.high, "Account with empty password", "CWE-258"
    if "permitemptypasswords" in m or "sshd allows empty" in m:
        return "fwa-sshd-empty", S.high, "sshd allows empty passwords", "CWE-258"
    if "telnetd" in m:
        return "fwa-telnetd", S.high, "telnetd started from inittab", "CWE-319"
    if "uid" in m or "gid" in m:
        return "fwa-ownership", S.low, "Unexpected file ownership", "CWE-732"
    return "fwa-offender", S.low, "FwAnalyzer policy violation", None


def normalize(report: dict, target: str, perms: bool) -> list[Finding]:
    out = []
    groups: dict[tuple[str, str], list[tuple[str, str]]] = {}
    meta: dict[str, tuple[S, str, str | None]] = {}
    for path, msgs in (report.get("offenders") or {}).items():
        for msg in msgs if isinstance(msgs, list) else [msgs]:
            rule, sev, title, cwe = _classify(str(msg), path, perms)
            groups.setdefault((rule, title), []).append((path, str(msg)))
            meta[rule + title] = (sev, title, cwe)
    for (rule, title), items in groups.items():
        sev, _, cwe = meta[rule + title]
        if rule == "fwa-empty-password" and any("line: root::" in m for _, m in items):
            sev = S.critical
        out.append(Finding(
            title=f"[FwAnalyzer] {title}" + (f" ({len(items)})" if len(items) > 1 else ""),
            description=("FwAnalyzer reported a policy violation for this filesystem. The rule set is generated by "
                         "Drone Firmware Analyzer (permission checks, disallowed files, insecure config content)."
                         + ("" if perms else " Run in directory mode: file ownership/permissions were not available.")),
            severity=sev, classification=C.detected, confidence=K.high, source_tool="fwanalyzer", rule_id=rule,
            affected_component=target, remediation=_REMEDIATION.get(rule, "Review the offending files."),
            evidence=[Evidence("tool_output", m[:240], p) for p, m in items[:25]], cwe=cwe, tags=["policy"]))
    info = report.get("informational") or {}
    if info:
        out.append(Finding(
            title=f"[FwAnalyzer] Informational results ({len(info)} paths)",
            description="FwAnalyzer produced informational (non-enforcing) results.", severity=S.info,
            classification=C.info, confidence=K.high, source_tool="fwanalyzer", rule_id="fwa-informational",
            affected_component=target, remediation="No action required.",
            evidence=[Evidence("tool_output", "; ".join(map(str, v))[:240] if isinstance(v, list) else str(v)[:240], p)
                      for p, v in list(info.items())[:25]]))
    return out


_REMEDIATION = {
    "fwa-suid": "Remove the setuid bit where not strictly required.",
    "fwa-world-writable": "Remove world-write permissions in the image build.",
    "fwa-bad-file": "Remove the file from the production image; generate keys per device at first boot.",
    "fwa-empty-password": "Lock the account or provision a unique per-device password.",
    "fwa-sshd-empty": "Set PermitEmptyPasswords no.",
    "fwa-telnetd": "Remove telnetd from inittab; use SSH with key authentication.",
}
