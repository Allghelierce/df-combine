"""ELF hardening, dangerous imports and suspicious strings in binaries."""
from __future__ import annotations

import re

from ..findings import Classification as C
from ..findings import Confidence as K
from ..findings import Evidence, Finding
from ..findings import Severity as S
from .base import ScanContext

TOOL = "builtin:binary"

SUSPICIOUS_STRINGS = [
    (re.compile(r"telnetd\s+-l\s*/bin/(?:ba|a)?sh"), "Embedded command spawning unauthenticated telnet shell",
     S.high, "bin-telnetd-shell", "CWE-306"),
    (re.compile(r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+"), "Reverse-shell style /dev/tcp connection string",
     S.medium, "bin-dev-tcp", "CWE-506"),
    (re.compile(r"\b(?:nc|netcat)\s+[^\n]{0,40}-e\s+/bin/(?:ba)?sh"), "Netcat bind/reverse shell command string",
     S.medium, "bin-netcat-shell", "CWE-506"),
    (re.compile(r"(?i)\bbackdoor\b"), "String referencing a 'backdoor'", S.low, "bin-backdoor-string", "CWE-506"),
]
URL_RE = re.compile(r"http://(?!localhost|127\.|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|ns\.adobe|purl\.org|"
                    r"www\.apache\.org|www\.gnu\.org|www\.openssl\.org|xml\.org)[A-Za-z0-9.\-]{4,}[^\s\"'<>]*")


def scan(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    no_nx, no_pie, no_relro, no_canary, gets_users, dangerous = [], [], [], [], [], []
    debug_bins = []
    for art in ctx.content_artifacts():
        info = ctx.elf.get(art.id)
        if info and info.get("os_hint") == "linux" and not info.get("is_kernel_module"):
            is_exec = info.get("interpreter") is not None
            if is_exec and info.get("nx") is False:
                no_nx.append(art)
            if is_exec and info.get("pie") is False:
                no_pie.append(art)
            if is_exec and info.get("relro") == "none":
                no_relro.append(art)
            if is_exec and not info.get("canary"):
                no_canary.append(art)
            if "gets" in info.get("dangerous_imports", []):
                gets_users.append(art)
            risky = ("strcpy", "strcat", "sprintf", "system", "popen", "vsprintf")
            other = [f for f in info.get("dangerous_imports", []) if f in risky]
            if other:
                dangerous.append((art, other))
            if info.get("has_debug_info"):
                debug_bins.append(art)
        if art.format in ("elf", "raw", "cortexm_raw") or (ctx.text(art) is not None and ctx.fs_path(art).endswith(".sh")):
            out += _strings(ctx, art)

    def agg(arts, title, desc, sev, cls, conf, rule, rem, cwe):
        if arts:
            out.append(Finding(
                title=f"{title} ({len(arts)} binar{'y' if len(arts) == 1 else 'ies'})", description=desc,
                severity=sev, classification=cls, confidence=conf, source_tool=TOOL, rule_id=rule,
                affected_component="Linux executables",
                remediation=rem, evidence=[Evidence("path", ctx.where(a)) for a in arts[:30]], cwe=cwe,
                tags=["hardening"]))

    agg(no_nx, "Executable stack (NX disabled)", "These Linux executables have no PT_GNU_STACK header or an "
        "executable stack, making memory-corruption bugs easier to exploit.", S.medium, C.detected, K.high,
        "elf-no-nx", "Build with -z noexecstack.", "CWE-693")
    agg(no_pie, "Executables built without PIE", "Non-PIE executables load at a fixed address, weakening ASLR.",
        S.low, C.detected, K.high, "elf-no-pie", "Build with -fPIE -pie.", "CWE-693")
    agg(no_relro, "Executables without RELRO", "No PT_GNU_RELRO segment: the GOT remains writable, a common "
        "target for exploitation.", S.low, C.detected, K.high, "elf-no-relro", "Link with -Wl,-z,relro,-z,now.",
        "CWE-693")
    agg(no_canary, "Executables without stack canaries", "No __stack_chk_fail reference was found. Heuristic: "
        "statically linked or stripped binaries can hide canary use.", S.low, C.suspicious, K.medium,
        "elf-no-canary", "Build with -fstack-protector-strong.", "CWE-693")
    agg(debug_bins, "Binaries ship with debug information", "DWARF debug sections are present; this eases "
        "reverse engineering of proprietary logic.", S.info, C.info, K.high, "elf-debug-info",
        "Strip release binaries.", "CWE-215")
    for art in gets_users:
        out.append(Finding(
            title="Binary imports gets()", description="gets() performs unbounded reads into a buffer and cannot "
            "be used safely. Its presence indicates a likely stack buffer overflow if reachable with external input.",
            severity=S.high, classification=C.detected, confidence=K.high, source_tool=TOOL, rule_id="elf-gets",
            affected_component=ctx.where(art), remediation="Replace gets() with fgets() or getline().",
            evidence=[Evidence("string", "imported symbol: gets", ctx.fs_path(art))], cwe="CWE-242",
            tags=["dangerous-function"]))
    if dangerous:
        out.append(Finding(
            title=f"Binaries import potentially dangerous functions ({len(dangerous)})",
            description="Imports of strcpy/strcat/sprintf/system/popen are common sources of buffer overflows "
                        "and command injection when used with untrusted input. Presence alone is not a vulnerability.",
            severity=S.low, classification=C.suspicious, confidence=K.low, source_tool=TOOL,
            rule_id="elf-dangerous-imports", affected_component="Linux executables",
            remediation="Review call sites; prefer bounded alternatives and avoid shelling out.",
            evidence=[Evidence("string", ", ".join(funcs), ctx.where(a)) for a, funcs in dangerous[:30]],
            cwe="CWE-676", tags=["dangerous-function"]))
    return out


def _strings(ctx: ScanContext, art) -> list[Finding]:
    out = []
    text = ctx.text(art)
    lines = [(i, s) for i, s in enumerate(text.splitlines())] if text is not None else ctx.strings(art)
    seen_rules = set()
    urls: list[str] = []
    for off, s in lines:
        for pat, title, sev, rule, cwe in SUSPICIOUS_STRINGS:
            if rule in seen_rules:
                continue
            m = pat.search(s)
            if m:
                seen_rules.add(rule)
                out.append(Finding(
                    title=title, description="A suspicious string was found in the binary. This is a pattern "
                    "match only; it may be dead code, documentation or a false positive.",
                    severity=sev, classification=C.suspicious, confidence=K.low, source_tool=TOOL, rule_id=rule,
                    affected_component=ctx.where(art), remediation="Review the code that references this string.",
                    evidence=[Evidence("string", m.group(0)[:160], f"{ctx.fs_path(art)} @ {off:#x}")], cwe=cwe,
                    tags=["suspicious-string"]))
        if len(urls) < 15:
            for m in URL_RE.finditer(s):
                u = m.group(0)[:160]
                if u not in urls:
                    urls.append(u)
    if urls:
        out.append(Finding(
            title=f"Cleartext HTTP endpoints referenced ({len(urls)})",
            description="Hard-coded http:// URLs suggest network communication without TLS (e.g. update checks, "
                        "telemetry, cloud APIs). Whether they are used at runtime was not verified.",
            severity=S.low, classification=C.suspicious, confidence=K.low, source_tool=TOOL, rule_id="cleartext-url",
            affected_component=ctx.where(art), remediation="Use HTTPS with certificate validation.",
            evidence=[Evidence("string", u, ctx.fs_path(art)) for u in urls], cwe="CWE-319", tags=["network"]))
    return out
