"""Insecure Linux service configuration (companion computers, Linux-based drones)."""
from __future__ import annotations

import re

from ..findings import Classification as C
from ..findings import Confidence as K
from ..findings import Evidence, Finding
from ..findings import Severity as S
from .base import ScanContext

TOOL = "builtin:config"

INIT_HINTS = ("/etc/inittab", "/etc/init.d/", "/etc/rc", "/etc/inetd.conf", "/etc/xinetd", "/lib/systemd/",
              "/etc/systemd/", "/usr/lib/systemd/", "/etc/profile", "/etc/rc.local", "/etc/sv/", "/etc/runit")


def _active_lines(text: str):
    for n, line in enumerate(text.splitlines()[:50_000], 1):
        s = line.strip()
        if s and not s.startswith("#"):
            yield n, s


def _is_init(path: str) -> bool:
    return any(h in path for h in INIT_HINTS) or path.endswith((".service", ".sh"))


def scan(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    world_writable, setuid = [], []
    for art in ctx.content_artifacts():
        path = ctx.fs_path(art)
        if art.mode is not None and art.origin in ("extracted",):
            if art.mode & 0o002:
                world_writable.append((art, art.mode))
            if art.mode & 0o4000:
                setuid.append((art, art.mode))
        text = ctx.text(art)
        if text is None:
            continue
        base = path.rsplit("/", 1)[-1]
        if base == "sshd_config":
            out += _sshd(ctx, art, text)
        if base == "sudoers" or "/etc/sudoers.d/" in path:
            for n, line in _active_lines(text):
                if re.search(r"NOPASSWD\s*:\s*ALL", line):
                    out.append(_f("Passwordless sudo for all commands", "A sudoers rule grants NOPASSWD: ALL; any "
                                  "compromise of that account yields root.", S.medium, C.detected, K.high,
                                  "sudo-nopasswd-all", ctx.where(art),
                                  "Restrict sudo rules to specific commands and require authentication.",
                                  [Evidence("config", line[:160], f"{path}:{n}")], "CWE-250"))
        if _is_init(path):
            out += _services(ctx, art, text)
    if world_writable:
        out.append(_f(f"{len(world_writable)} world-writable file(s) in firmware image",
                      "Files with the world-writable bit set in the original archive/filesystem metadata can be "
                      "modified by any local user/process (e.g. a compromised network service) to persist or "
                      "escalate privileges.", S.medium, C.detected, K.high, "world-writable-files",
                      "filesystem permissions", "Remove world-write permissions (chmod o-w) in the build.",
                      [Evidence("path", f"{ctx.fs_path(a)} (mode {m:04o})", ctx.where(a)) for a, m in world_writable[:25]],
                      "CWE-732"))
    if setuid:
        out.append(_f(f"{len(setuid)} setuid file(s) in firmware image",
                      "setuid binaries run with the owner's privileges. Each one is attack surface for local "
                      "privilege escalation; review whether it is required.", S.low, C.info, K.high,
                      "setuid-files", "filesystem permissions",
                      "Remove the setuid bit from binaries that do not need it.",
                      [Evidence("path", f"{ctx.fs_path(a)} (mode {m:04o})", ctx.where(a)) for a, m in setuid[:25]],
                      "CWE-250"))
    return out


def _f(title, desc, sev, cls, conf, rule, comp, rem, ev, cwe=None, tags=None) -> Finding:
    return Finding(title=title, description=desc, severity=sev, classification=cls, confidence=conf,
                   source_tool=TOOL, rule_id=rule, affected_component=comp, remediation=rem, evidence=ev,
                   cwe=cwe, tags=tags or ["configuration"])


def _sshd(ctx: ScanContext, art, text: str) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    opts: dict[str, tuple[int, str]] = {}
    for n, line in _active_lines(text):
        if line.lower().startswith("match "):
            break  # options after Match blocks are conditional
        parts = line.split(None, 1)
        if len(parts) == 2:
            opts.setdefault(parts[0].lower(), (n, parts[1].strip()))
    rules = [
        ("permitemptypasswords", "yes", "SSH allows empty passwords", S.high, "sshd-permit-empty-passwords",
         "PermitEmptyPasswords yes lets accounts without a password log in over SSH.", "CWE-258"),
        ("permitrootlogin", "yes", "SSH permits root login with password", S.medium, "sshd-permit-root-login",
         "PermitRootLogin yes allows direct root login, including password authentication.", "CWE-250"),
        ("protocol", "1", "SSH protocol version 1 enabled", S.high, "sshd-protocol-1",
         "SSHv1 is cryptographically broken.", "CWE-327"),
    ]
    for key, bad, title, sev, rule, desc, cwe in rules:
        if key in opts and opts[key][1].lower().startswith(bad):
            n, val = opts[key]
            out.append(_f(title, desc, sev, C.detected, K.high, rule, ctx.where(art),
                          f"Set '{key}' to a secure value in sshd_config.",
                          [Evidence("config", f"{key} {val}", f"{path}:{n}")], cwe))
    return out


SERVICE_RULES = [
    (re.compile(r"\btelnetd\b[^\n]*\s-l\s*/bin/(?:ba|a)?sh\b"), "Telnet service spawning a shell without login",
     S.critical, "telnetd-shell-no-auth",
     "telnetd is started with '-l /bin/sh', giving an unauthenticated root shell to anyone who can reach the port.",
     "CWE-306"),
    (re.compile(r"\b(?:u?telnetd)\b"), "Telnet service configured to start", S.high, "telnetd-enabled",
     "A telnet daemon is referenced by a startup/inetd configuration. Telnet sends credentials in clear text.",
     "CWE-319"),
    (re.compile(r"\bdropbear\b[^\n]*\s-B\b"), "Dropbear allows blank-password logins", S.high, "dropbear-blank-pw",
     "dropbear is started with -B (allow blank password logins).", "CWE-258"),
    (re.compile(r"(?:getty|agetty)[^\n]*(?:-a|--autologin)\s+root\b"), "Console auto-login as root", S.medium,
     "getty-autologin-root", "A getty is configured to log in as root without a password on a serial console. "
     "Physical access to the UART (common on flight controllers/companions) grants root.", "CWE-306"),
    (re.compile(r"^(?:tftp|ftp|shell|login|exec)\s+(?:stream|dgram)\s"), "Legacy cleartext inetd service enabled",
     S.medium, "inetd-legacy-service", "inetd.conf enables a legacy cleartext service (ftp/tftp/rsh/rlogin).",
     "CWE-319"),
    (re.compile(r"\b(?:adbd|gdbserver)\b"), "Debug service started at boot", S.medium, "debug-service-enabled",
     "adbd/gdbserver is started by a boot script; debug services expose powerful remote control interfaces.",
     "CWE-489"),
    (re.compile(r"\b(?:nc|netcat|ncat)\b[^\n]*\s-(?:e|c)\s"), "Netcat executes a program on connection", S.high,
     "netcat-exec", "A startup script runs netcat with -e/-c, a common backdoor / bind-shell pattern.", "CWE-506"),
]


STOP_RE = re.compile(r"\b(?:kill|killall|pkill|start-stop-daemon\s+--stop|stop|disable|rm|mask)\b[^\n]*"
                     r"\b(?:u?telnetd|dropbear|getty|adbd|gdbserver|tftp|ftp)\b")


def _services(ctx: ScanContext, art, text: str) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    hit_rules = set()
    for n, line in _active_lines(text):
        for pat, title, sev, rule, desc, cwe in SERVICE_RULES:
            if rule in hit_rules:
                continue
            if rule == "telnetd-enabled" and "telnetd-shell-no-auth" in hit_rules:
                continue
            if pat.search(line):
                if STOP_RE.search(line):
                    continue  # e.g. "killall telnetd" - stopping a service is not enabling it
                hit_rules.add(rule)
                out.append(_f(title, desc + " Static configuration only: whether the service actually runs "
                              "on the deployed device was not verified.", sev, C.suspicious, K.medium, rule,
                              ctx.where(art), "Remove the service from boot configuration or restrict it to an "
                              "authenticated, encrypted alternative (SSH with keys).",
                              [Evidence("config", line[:200], f"{path}:{n}")], cwe, ["configuration", "service"]))
    return out
