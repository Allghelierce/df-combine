"""Software component fingerprinting and version-based (unverified) outdated checks."""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..findings import Classification as C
from ..findings import Confidence as K
from ..findings import Evidence, Finding
from ..findings import Severity as S
from .base import ScanContext

TOOL = "builtin:components"
KB_PATH = Path(__file__).resolve().parent.parent / "data" / "component_kb.json"

FINGERPRINTS: list[tuple[str, re.Pattern]] = [
    ("busybox", re.compile(r"BusyBox v(\d+\.\d+(?:\.\d+)?)")),
    ("openssl", re.compile(r"\bOpenSSL (\d+\.\d+\.\d+[a-z]{0,2})\b")),
    ("openssh", re.compile(r"\bOpenSSH_(\d+\.\d+(?:p\d+)?)")),
    ("dropbear", re.compile(r"\b[Dd]ropbear(?:[ _]sshd?)?[ _]v?(20\d\d\.\d+)")),
    ("linux", re.compile(r"\bLinux version (\d+\.\d+(?:\.\d+)?)")),
    ("dnsmasq", re.compile(r"\bdnsmasq-(\d+\.\d+)")),
    ("lighttpd", re.compile(r"\blighttpd/(\d+\.\d+\.\d+)")),
    ("libcurl", re.compile(r"\blibcurl/(\d+\.\d+\.\d+)")),
    ("glibc", re.compile(r"GNU C Library[^\n]{0,60}?version (\d+\.\d+)")),
    ("uclibc", re.compile(r"\buClibc(?:-ng)?[ -](\d+\.\d+\.\d+)")),
    ("zlib", re.compile(r"\b(?:de|in)flate (\d+\.\d+\.\d+(?:\.\d+)?) Copyright")),
    ("mbedtls", re.compile(r"\b[Mm]bed ?TLS (\d+\.\d+\.\d+)")),
    ("hostapd", re.compile(r"\bhostapd v(\d+\.\d+(?:\.\d+)?)")),
    ("wpa_supplicant", re.compile(r"\bwpa_supplicant v(\d+\.\d+(?:\.\d+)?)")),
    ("u-boot", re.compile(r"\bU-Boot (20\d\d\.\d\d(?:\.\d+)?)")),
    ("nuttx", re.compile(r"\bNuttX[- ](?:version )?(\d+\.\d+(?:\.\d+)?)")),
    ("chibios", re.compile(r"\bChibiOS/RT (\d+\.\d+\.\d+)")),
    ("freertos", re.compile(r"\bFreeRTOS (?:Kernel )?V(\d+\.\d+\.\d+)")),
    ("sqlite", re.compile(r"\bSQLite version (\d+\.\d+\.\d+)")),
    ("mavlink-router", re.compile(r"\bmavlink-routerd? version (\d+(?:\.\d+)*)")),
    ("zephyr", re.compile(r"Booting Zephyr OS (?:build |version )?(?:zephyr-)?v?(\d+\.\d+\.\d+)")),
]


DOC_PATHS = re.compile(r"(/share/(doc|man|info|locale|common-licenses)/|/(copyright|changelog[^/]*|NEWS|"
                       r"README[^/]*|LICEN[SC]E[^/]*|COPYING[^/]*)$)", re.I)


@dataclass
class Component:
    name: str
    version: str
    sources: list[str] = field(default_factory=list)
    method: str = "string-match"
    variant: str | None = None  # e.g. the ArduPilot vehicle, which selects the upstream release tags

    def to_dict(self) -> dict:
        return asdict(self)


def merge(comps: list[Component], comp: Component) -> None:
    """Add ``comp`` unless the same name/version is already listed (then only merge its sources)."""
    for c in comps:
        if (c.name, c.version) == (comp.name, comp.version):
            c.sources.extend(s for s in comp.sources if s not in c.sources and len(c.sources) < 5)
            return
    comps.append(comp)


def parse_version(v: str) -> tuple:
    parts: list = []
    for tok in re.findall(r"\d+|[a-z]+", v.lower()):
        if tok.isdigit():
            parts.append((1, int(tok)))
        elif tok in ("rc", "beta", "alpha", "pre", "dev"):
            parts.append((0, tok))  # pre-releases sort before releases
        elif len(tok) <= 2:
            parts.append((1, sum((ord(c) - 96) * 27 ** i for i, c in enumerate(reversed(tok)))))
        else:
            parts.append((1, 0))
    parts.append((0, "~"))  # end marker: sorts after pre-release tags, before any further number
    return tuple(parts)


def version_in_range(v: str, entry: dict) -> bool:
    pv = parse_version(v)
    if "min" in entry and pv < parse_version(entry["min"]):
        return False
    if "max_exclusive" in entry and not pv < parse_version(entry["max_exclusive"]):
        return False
    if "max_inclusive" in entry and pv > parse_version(entry["max_inclusive"]):
        return False
    return True


def load_kb() -> dict:
    kb = json.loads(KB_PATH.read_text())
    extra = os.environ.get("DFA_COMPONENT_KB")
    if extra and Path(extra).is_file():
        kb["entries"] = kb["entries"] + json.loads(Path(extra).read_text()).get("entries", [])
    return kb


def fingerprint(ctx: ScanContext) -> list[Component]:
    found: dict[tuple[str, str], Component] = {}
    for art in ctx.content_artifacts():
        fsp = ctx.fs_path(art)
        if DOC_PATHS.search(fsp):
            continue  # licences/changelogs mention arbitrary versions ("version 2.23" in glibc's copyright)
        if art.format in ("text",):
            text = ctx.text(art) or ""
            lines = text.splitlines()[:20_000]
        elif art.format in ("elf", "raw", "cortexm_raw") or art.name.endswith((".so", ".ko")):
            lines = [s for _, s in ctx.strings(art)]
        else:
            continue
        for line in lines:
            if len(line) > 600:
                line = line[:600]
            for name, pat in FINGERPRINTS:
                m = pat.search(line)
                if m:
                    key = (name, m.group(1))
                    comp = found.setdefault(key, Component(name=name, version=m.group(1)))
                    if len(comp.sources) < 5 and ctx.where(art) not in comp.sources:
                        comp.sources.append(ctx.where(art))
    # Drop zlib/openssl duplicates that are clearly test strings (e.g. version "0.0.0").
    return sorted((c for c in found.values() if not c.version.startswith("0.0")), key=lambda c: (c.name, c.version))


def assess(components: list[Component], kb: dict | None = None) -> list[Finding]:
    kb = kb or load_kb()
    out = []
    by_entry: dict[int, list[Component]] = defaultdict(list)
    entries = kb["entries"]
    for comp in components:
        for i, e in enumerate(entries):
            if e["component"] == comp.name and version_in_range(comp.version, e):
                by_entry[i].append(comp)
    for i, comps in by_entry.items():
        e = entries[i]
        for comp in comps:
            out.append(Finding(
                title=f"{e['title']} - {comp.name} {comp.version}",
                description=(e["description"] + f" Detected version string '{comp.version}' "
                             f"(knowledge base as of {kb.get('as_of', 'unknown')}). Version-based match only: "
                             "the fix may have been backported, so this is not a confirmed vulnerability."),
                severity=S(e["severity"]), classification=C.unverified, confidence=K.medium, source_tool=TOOL,
                rule_id=f"outdated-{comp.name}", affected_component=f"{comp.name} {comp.version}",
                remediation=f"Upgrade {comp.name} to a maintained release or confirm vendor backports.",
                evidence=[Evidence("string", f"{comp.name} version {comp.version}", src) for src in comp.sources[:5]],
                cwe="CWE-1104", references=list(e.get("references", [])) + list(e.get("cves", [])),
                tags=["outdated-component"] + list(e.get("cves", []))))
    return out
