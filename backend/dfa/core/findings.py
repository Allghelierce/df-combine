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


# External-tool rule -> built-in rule ids describing the same issue.
CORRELATIONS: dict[tuple[str, str], tuple[str, ...]] = {
    ("fwanalyzer", "fwa-empty-password"): ("empty-password",),
    ("fwanalyzer", "fwa-world-writable"): ("world-writable-files",),
    ("fwanalyzer", "fwa-suid"): ("setuid-files",),
    ("fwanalyzer", "fwa-telnetd"): ("telnetd-shell-no-auth", "telnetd-enabled"),
    ("fwanalyzer", "fwa-sshd-empty"): ("sshd-permit-empty-passwords",),
    ("fwanalyzer", "fwa-bad-file"): ("ssh-host-key", "pem-private-key", "ssh-authorized-keys"),
}


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
    """Merge external-tool findings that duplicate a built-in finding on the same file.

    The built-in finding is kept, credited with the corroborating tool (tag
    ``corroborated-by:<tool>``), gains the tool's evidence and is raised to high
    confidence.  This avoids double counting the same weakness in severity
    totals while keeping provenance from every tool.
    """
    builtin = [f for f in findings if f.source_tool.startswith("builtin:")]
    keep: list[Finding] = []
    for f in findings:
        targets = CORRELATIONS.get((f.source_tool, f.rule_id))
        if not targets:
            keep.append(f)
            continue
        fpaths = _paths(f)
        match = None
        for b in builtin:
            if b.rule_id not in targets:
                continue
            same_fs = b.affected_component.startswith(f.affected_component) or b.affected_component in (
                "filesystem permissions",)
            if same_fs and (fpaths & _paths(b) or b.affected_component == "filesystem permissions"):
                match = b
                break
        if match is None:
            keep.append(f)
            continue
        tag = f"corroborated-by:{f.source_tool}"
        if tag not in match.tags:
            match.tags.append(tag)
        match.confidence = Confidence.high
        match.evidence.extend(Evidence("tool_output", f"[{f.source_tool}] {e.value}", e.location)
                              for e in f.evidence[:5])
        if Severity(f.severity).rank < Severity(match.severity).rank:
            match.severity = f.severity
    return keep
