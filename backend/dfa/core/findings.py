"""Shared, tool-independent finding schema.

All scanners and tool adapters must emit :class:`Finding` objects.  The
``classification`` field is what separates evidence-backed results from
heuristics; nothing in this code base is allowed to label a finding as an
exploitable/confirmed vulnerability.

classification:
    detected    - deterministic evidence of an insecure state was found in the
                  image (e.g. a PEM private key, an empty root password hash, a
                  config file that sets PermitEmptyPasswords yes).  The evidence
                  is factual; exploitability is NOT verified.
    suspicious  - a heuristic or pattern match (e.g. a string that looks like a
                  password assignment).  May be a false positive.
    unverified  - a claim that needs manual verification, typically a
                  version-based "known vulnerable" match (distro backports are
                  possible) or a static-analysis warning from cwe_checker/FACT.
    info        - inventory / context, not a weakness on its own.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self.value)


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class Classification(str, Enum):
    detected = "detected"
    suspicious = "suspicious"
    unverified = "unverified"
    info = "info"


CLASSIFICATION_LABELS = {
    "detected": "Detected weakness (evidence present, exploitability not verified)",
    "suspicious": "Suspicious pattern (heuristic, may be a false positive)",
    "unverified": "Unverified finding (requires manual verification)",
    "info": "Informational",
}


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


@dataclass
class Evidence:
    kind: str  # "string" | "path" | "offset" | "tool_output" | "config" | "address"
    value: str
    location: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    classification: Classification
    confidence: Confidence
    source_tool: str
    rule_id: str
    affected_component: str
    remediation: str
    evidence: list[Evidence] = field(default_factory=list)
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    package: str | None = None  # installed package that owns the affected file ("openssh-server 1:8.4p1-5")

    @property
    def fingerprint(self) -> str:
        key = "|".join(
            [
                self.source_tool,
                self.rule_id,
                self.affected_component,
                ";".join(sorted(e.value for e in self.evidence))[:2000],
            ]
        )
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "description": self.description,
            "severity": Severity(self.severity).value,
            "classification": Classification(self.classification).value,
            "confidence": Confidence(self.confidence).value,
            "source_tool": self.source_tool,
            "rule_id": self.rule_id,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "evidence": [e.to_dict() for e in self.evidence],
            "cwe": self.cwe,
            "references": list(self.references),
            "tags": list(self.tags),
            "package": self.package,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(
            title=d["title"],
            description=d["description"],
            severity=Severity(d["severity"]),
            classification=Classification(d["classification"]),
            confidence=Confidence(d["confidence"]),
            source_tool=d["source_tool"],
            rule_id=d["rule_id"],
            affected_component=d["affected_component"],
            remediation=d["remediation"],
            evidence=[Evidence(**e) for e in d.get("evidence", [])],
            cwe=d.get("cwe"),
            references=list(d.get("references", [])),
            tags=list(d.get("tags", [])),
            package=d.get("package"),
        )


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint, f)
    return sorted(seen.values(), key=lambda f: (Severity(f.severity).rank, f.title))


def redact(secret: str, keep: int = 2) -> str:
    """Redact a secret for display: keep a short prefix and the length."""
    secret = secret.strip()
    if len(secret) <= keep:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * min(len(secret) - keep, 12)} (len={len(secret)})"


# External-tool rule -> built-in rule ids (``*`` suffix = prefix match) describing the same issue.
CORRELATIONS: dict[tuple[str, str], tuple[str, ...]] = {
    ("fwanalyzer", "fwa-empty-password"): ("empty-password",),
    ("fwanalyzer", "fwa-world-writable"): ("world-writable-files",),
    ("fwanalyzer", "fwa-suid"): ("setuid-files",),
    ("fwanalyzer", "fwa-telnetd"): ("telnetd-shell-no-auth", "telnetd-enabled"),
    ("fwanalyzer", "fwa-sshd-empty"): ("sshd-permit-empty-passwords",),
    ("fwanalyzer", "fwa-bad-file"): ("ssh-host-key", "pem-private-key", "ssh-authorized-keys"),
    ("fwanalyzer", "fwa-px4-cbrk"): ("px4-cbrk_*",),
    ("fwanalyzer", "fwa-px4-mav-broadcast"): ("px4-mav-broadcast",),
    ("fwanalyzer", "fwa-ap-safety"): ("ardupilot-*",),
    ("ghidra", "ghidra-call-gets"): ("elf-gets",),
}


def _rule_matches(rule_id: str, patterns: tuple[str, ...]) -> bool:
    return any(rule_id.startswith(p[:-1]) if p.endswith("*") else rule_id == p for p in patterns)


def _paths(f: Finding) -> set[str]:
    out = set()
    for e in f.evidence:
        for v in (e.location or "", e.value):
            if v.startswith("/"):
                out.add(v.split(" ", 1)[0].split(":", 1)[0])
    tail = f.affected_component.rsplit(" > ", 1)[-1]
    if tail.startswith("/"):
        out.add(tail)
    return out


def correlate(findings: list[Finding]) -> list[Finding]:
    """Merge external-tool findings that duplicate built-in findings on the same files.

    Every built-in finding whose file is also reported by the external tool is credited
    (tag ``corroborated-by:<tool>``, evidence appended, confidence raised to high). The external
    finding is dropped only if *all* of its files were matched, so nothing reported solely by the
    external tool is lost. This avoids double counting while keeping provenance from every tool.
    """
    builtin = [f for f in findings if f.source_tool.startswith("builtin:")]
    keep: list[Finding] = []
    for f in findings:
        targets = CORRELATIONS.get((f.source_tool, f.rule_id))
        if not targets:
            keep.append(f)
            continue
        fpaths = _paths(f)
        matched_paths: set[str] = set()
        matched_any = False
        for b in builtin:
            if not _rule_matches(b.rule_id, targets):
                continue
            same_scope = b.affected_component.startswith(f.affected_component) or \
                b.affected_component in ("filesystem permissions", "Linux executables") or \
                f.affected_component.startswith(b.affected_component)
            if not same_scope:
                continue
            common = fpaths & _paths(b) if fpaths else set()
            if common or b.affected_component in ("filesystem permissions",) or not fpaths:
                matched_any = True
                matched_paths |= common
                tag = f"corroborated-by:{f.source_tool}"
                if tag not in b.tags:
                    b.tags.append(tag)
                    b.confidence = Confidence.high
                    b.evidence.extend(Evidence("tool_output", f"[{f.source_tool}] {e.value}", e.location)
                                      for e in f.evidence if not fpaths or (e.location or "") in common or
                                      (e.value.split(" ", 1)[0] in common))
                if Severity(f.severity).rank < Severity(b.severity).rank:
                    b.severity = f.severity
        if not matched_any or (fpaths and fpaths - matched_paths):
            keep.append(f)
    return keep


def aggregate(findings: list[Finding], threshold: int = 3) -> list[Finding]:
    """Collapse >= ``threshold`` findings of the same tool/rule/title (one per file) into one finding.

    The merged finding keeps every location as evidence and names the common container, so a rule
    that fires in 40 airframe files is reported once with 40 locations instead of 40 times.
    """
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.source_tool, f.rule_id, f.title), []).append(f)
    out: list[Finding] = []
    for (_tool, _rule, title), items in groups.items():
        if len(items) < threshold:
            out.extend(items)
            continue
        parts = [i.affected_component.split(" > ") for i in items]
        common: list[str] = []
        for level in zip(*parts, strict=False):
            if len(set(level)) == 1:
                common.append(level[0])
            else:
                break
        first = items[0]
        evidence: list[Evidence] = []
        for i in items:
            loc = i.affected_component.split(" > ")[len(common):]
            for e in i.evidence[:2]:
                evidence.append(Evidence(e.kind, e.value, e.location or " > ".join(loc)))
        tags = sorted({t for i in items for t in i.tags})
        pkgs = {i.package for i in items}
        out.append(Finding(
            title=f"{title} ({len(items)} files)", description=first.description,
            severity=min((i.severity for i in items), key=lambda s: Severity(s).rank),
            classification=first.classification, confidence=first.confidence, source_tool=first.source_tool,
            rule_id=first.rule_id, affected_component=(" > ".join(common) or "multiple files") + f" ({len(items)} files)",
            remediation=first.remediation, evidence=evidence[:60], cwe=first.cwe, references=first.references,
            tags=tags + ["aggregated"], package=pkgs.pop() if len(pkgs) == 1 else None))
    return out


def attribute_packages(findings: list[Finding], inventory: dict | None) -> int:
    """Name the installed package that owns each finding's file (from dpkg/apk/opkg file lists).

    Ownership comes from the package manager's own records, so a finding in /usr/sbin/sshd is tied to
    e.g. 'openssh-server 1:8.4p1-5+deb11u1' and can be triaged together with that package's advisories.
    """
    inv = inventory or {}
    owners: dict[str, str] = inv.get("owners") or {}
    if not owners:
        return 0
    versions = {p["name"]: p["version"] for p in inv.get("packages", [])}
    n = 0
    for f in findings:
        if f.package:
            continue
        cands = [f.affected_component] + [e.location for e in f.evidence if e.location]
        cands += [e.value for e in f.evidence if e.kind == "path"]
        for c in cands:
            name = owners.get(c)
            if name:
                f.package = f"{name} {versions.get(name, '')}".strip()
                f.tags.append(f"package:{name}")
                n += 1
                break
    return n
