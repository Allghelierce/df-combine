"""Drone-specific checks: PX4 / ArduPilot parameters, MAVLink exposure."""
from __future__ import annotations

import re

from ..findings import Classification as C
from ..findings import Confidence as K
from ..findings import Evidence, Finding
from ..findings import Severity as S
from .base import ScanContext

TOOL = "builtin:drone"

# PX4 circuit breakers: setting the magic value DISABLES the check.
PX4_CBRK = {
    "CBRK_IO_SAFETY": (22027, "Safety switch disabled via circuit breaker", S.medium,
                       "Motors/actuators can be armed without pressing the hardware safety switch."),
    "CBRK_SUPPLY_CHK": (894281, "Power supply check disabled via circuit breaker", S.low,
                        "Arming is allowed without valid power supply checks."),
    "CBRK_USB_CHK": (197848, "USB connection arming check disabled", S.low,
                     "The vehicle may arm/fly while connected over USB."),
    "CBRK_AIRSPD_CHK": (162128, "Airspeed sensor check disabled", S.low,
                        "Arming is allowed without airspeed sensor validation (fixed-wing safety)."),
}

ARDUPILOT_PARAMS = {
    "ARMING_CHECK": ("0", "All ArduPilot pre-arm checks disabled", S.medium,
                     "ARMING_CHECK=0 disables every pre-arm safety check (sensors, GPS, failsafes, RC)."),
    "BRD_SAFETYENABLE": ("0", "Hardware safety switch disabled", S.low,
                         "BRD_SAFETYENABLE=0 removes the requirement to press the safety switch before arming."),
    "BRD_SAFETY_DEFLT": ("0", "Hardware safety switch disabled by default", S.low,
                         "BRD_SAFETY_DEFLT=0 disables the safety switch at boot."),
}

SIM_AIRFRAME = re.compile(r"(_sih\b|\.hil$|_hil\b|sitl|_sim\b|\bsih_)", re.I)
PX4_PARAM_RE = re.compile(r"^\s*param\s+(?:set|set-default)\s+([A-Z0-9_]+)\s+(-?[\w.]+)")
AP_PARAM_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]{2,16})\s*[,= \t]\s*(-?[\d.]+)\s*$")


def _f(title, desc, sev, cls, conf, rule, comp, rem, ev, cwe=None, tags=None) -> Finding:
    return Finding(title=title, description=desc, severity=sev, classification=cls, confidence=conf,
                   source_tool=TOOL, rule_id=rule, affected_component=comp, remediation=rem, evidence=ev,
                   cwe=cwe, tags=tags or ["drone"])


def scan(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    for art in ctx.content_artifacts():
        text = ctx.text(art)
        path = ctx.fs_path(art)
        base = path.rsplit("/", 1)[-1].lower()
        if text is None:
            continue
        if "param set" in text:
            out += _px4_params(ctx, art, text)
        if base.endswith((".parm", ".param", ".params")) or _looks_like_param_file(text):
            out += _ap_params(ctx, art, text)
        if base in ("main.conf", "mavlink-router.conf") or "mavlink-router" in path or "[UdpEndpoint" in text:
            out += _mavlink_router(ctx, art, text)
        out += _mavlink_cli(ctx, art, text)
    return out


KNOWN_AP_PREFIXES = ("ARMING_", "BRD_", "SERIAL", "SYSID_", "FS_", "FENCE_", "GPS_", "BATT_", "COMPASS_",
                     "INS_", "LOG_", "RC", "SERVO", "FRAME_", "MOT_", "EK3_", "AHRS_", "WPNAV_", "RTL_")


def _looks_like_param_file(text: str) -> bool:
    """Content heuristic for parameter files without a telling name (e.g. carved from ROMFS)."""
    hits = 0
    for line in text.splitlines()[:400]:
        m = AP_PARAM_RE.match(line)
        if m and m.group(1).startswith(KNOWN_AP_PREFIXES):
            hits += 1
            if hits >= 2:
                return True
    return False


def _px4_params(ctx, art, text) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    for n, line in enumerate(text.splitlines(), 1):
        m = PX4_PARAM_RE.match(line)
        if not m:
            continue
        name, val = m.group(1), m.group(2)
        if name in PX4_CBRK:
            magic, title, sev, desc = PX4_CBRK[name]
            try:
                is_magic = int(float(val)) == magic
            except ValueError:
                is_magic = False
            simulated = bool(SIM_AIRFRAME.search(path.rsplit("/", 1)[-1]))
            if is_magic and simulated:
                out.append(_f(title + " (simulation airframe)", desc + " The file is a simulation/hardware-in-the-"
                              "loop airframe (SIH/HIL/SITL), where disabling this check is expected; it does not "
                              "affect real vehicles unless this airframe is selected on hardware.", S.info, C.info,
                              K.high, f"px4-{name.lower()}-sim", ctx.where(art),
                              "No action needed unless the simulation airframe can be selected on real hardware.",
                              [Evidence("config", line.strip()[:200], f"{path}:{n}")], "CWE-1188",
                              ["drone", "px4", "safety", "simulation"]))
            elif is_magic:
                out.append(_f(title, desc + " This is set in a startup script shipped with the firmware, so it "
                              "applies to every vehicle using this build/airframe.", sev, C.detected, K.high,
                              f"px4-{name.lower()}", ctx.where(art),
                              f"Remove 'param set {name} {val}' unless the airframe genuinely requires it.",
                              [Evidence("config", line.strip()[:200], f"{path}:{n}")], "CWE-1188",
                              ["drone", "px4", "safety"]))
        if name == "MAV_BROADCAST" and val == "1":
            out.append(_f("MAVLink broadcast enabled", "MAV_BROADCAST=1 makes PX4 broadcast MAVLink "
                          "heartbeats/telemetry to the whole network segment.", S.low, C.detected, K.high,
                          "px4-mav-broadcast", ctx.where(art), "Disable broadcast and use explicit GCS endpoints.",
                          [Evidence("config", line.strip(), f"{path}:{n}")], "CWE-319", ["drone", "px4", "mavlink"]))
    return out


def _ap_params(ctx, art, text) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    for n, line in enumerate(text.splitlines(), 1):
        m = AP_PARAM_RE.match(line)
        if not m:
            continue
        name, val = m.group(1), m.group(2)
        if name in ARDUPILOT_PARAMS:
            bad, title, sev, desc = ARDUPILOT_PARAMS[name]
            try:
                matches = float(val) == float(bad)
            except ValueError:
                matches = False
            if matches:
                out.append(_f(title, desc + " Set in a default parameter file embedded in the firmware.", sev,
                              C.detected, K.high, f"ardupilot-{name.lower()}", ctx.where(art),
                              f"Do not ship {name}={val} as a default; leave the safety default enabled.",
                              [Evidence("config", line.strip(), f"{path}:{n}")], "CWE-1188",
                              ["drone", "ardupilot", "safety"]))
    return out


def _mavlink_router(ctx, art, text) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    section = ""
    sect_vals: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if s.startswith("["):
            section = s.strip("[]").strip()
            sect_vals.setdefault(section, {})
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            sect_vals.setdefault(section, {})[k.strip().lower()] = v.strip()
    general = sect_vals.get("General", {})
    port = general.get("tcpserverport")
    if port and port != "0":
        out.append(_f("MAVLink TCP server exposed (mavlink-router)",
                      f"mavlink-router listens for MAVLink over TCP on port {port} on all interfaces. MAVLink "
                      "has no authentication unless MAVLink 2 message signing is enforced end-to-end, which "
                      "cannot be confirmed from static configuration. A network attacker could send commands "
                      "(arm, mode change, mission upload) to the flight controller.",
                      S.medium, C.suspicious, K.medium, "mavlink-router-tcp-server", ctx.where(art),
                      "Disable TcpServerPort or bind MAVLink to a protected interface/VPN; enable MAVLink 2 signing.",
                      [Evidence("config", f"[General] TcpServerPort={port}", path)], "CWE-306",
                      ["drone", "mavlink", "network"]))
    for sect, vals in sect_vals.items():
        if sect.startswith("UdpEndpoint") and vals.get("mode", "").lower() == "server" and \
                vals.get("address", "0.0.0.0") in ("0.0.0.0", "::"):
            out.append(_f("MAVLink UDP endpoint listening on all interfaces",
                          f"mavlink-router endpoint [{sect}] listens on {vals.get('address', '0.0.0.0')}:"
                          f"{vals.get('port', '?')} for unauthenticated MAVLink traffic.", S.medium, C.suspicious,
                          K.medium, "mavlink-router-udp-server", ctx.where(art),
                          "Restrict the listening address to a trusted interface; enable MAVLink 2 signing.",
                          [Evidence("config", f"[{sect}] Mode=Server Address={vals.get('address', '0.0.0.0')}", path)],
                          "CWE-306", ["drone", "mavlink", "network"]))
    return out


MAVPROXY_RE = re.compile(r"mavproxy(?:\.py)?\b[^\n]*--out[= ]\s*(udpbcast:[^\s]+|tcpin:0\.0\.0\.0:[0-9]+)")


def _mavlink_cli(ctx, art, text) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    for n, line in enumerate(text.splitlines()[:20_000], 1):
        if line.lstrip().startswith("#"):
            continue
        m = MAVPROXY_RE.search(line)
        if m:
            out.append(_f("MAVProxy exposes MAVLink to the network",
                          f"MAVProxy is started with output '{m.group(1)}', exposing unauthenticated MAVLink "
                          "control to the network segment.", S.medium, C.suspicious, K.medium,
                          "mavproxy-network-output", ctx.where(art),
                          "Use unicast endpoints to trusted GCS hosts, a VPN, and MAVLink 2 signing.",
                          [Evidence("config", line.strip()[:200], f"{path}:{n}")], "CWE-306",
                          ["drone", "mavlink", "network"]))
            break
    return out
