"""SARIF 2.1.0 export, so findings can be loaded into code-scanning dashboards and CI tooling.

Firmware findings have no source lines; each result points at the affected file inside the firmware
(its display path) as a logical location and carries the evidence class, confidence and owning package
as properties. SARIF ``level`` follows severity; ``kind`` is "review" for anything that is not
directly evidenced (static-analysis warnings, version matches), matching how the findings are classified.
"""
from __future__ import annotations

from .. import __version__
from ..models import Scan

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def sarif(scan: Scan) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in sorted(scan.findings, key=lambda x: (x.severity_rank, x.title)):
        rid = f"{f.source_tool}/{f.rule_id}"
        if rid not in rules:
            rule = {"id": rid, "name": f.rule_id, "shortDescription": {"text": f.title[:200]},
                    "properties": {"tool": f.source_tool}}
            if f.cwe and f.cwe.startswith("CWE-"):
                rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{f.cwe[4:]}.html"
                rule["properties"]["tags"] = [f.cwe]
            rules[rid] = rule
        component = f.affected_component
        results.append({
            "ruleId": rid,
            "ruleIndex": list(rules).index(rid),
            "level": LEVEL.get(f.severity, "warning"),
            "kind": "fail" if f.classification == "detected" else "review",
            "message": {"text": f"{f.title}\n\n{f.description}\n\nRemediation: {f.remediation}"},
            "locations": [{"logicalLocations": [{"fullyQualifiedName": component, "kind": "module"}],
                           "physicalLocation": {"artifactLocation": {"uri": _uri(component)}}}],
            "partialFingerprints": {"dfaFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity, "security-severity": SCORE.get(f.severity, "5.0"),
                           "classification": f.classification, "confidence": f.confidence,
                           "package": f.package, "cwe": f.cwe, "references": (f.references or [])[:20],
                           "evidence": [f"{e.get('kind')}: {e.get('value')}" + (f" @ {e['location']}" if e.get("location")
                                                                                 else "")
                                        for e in (f.evidence or [])[:10]]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Drone Firmware Analyzer", "version": __version__,
                                "informationUri": "https://github.com/allghelierce/df-combine",
                                "rules": list(rules.values())}},
            "artifacts": [{"location": {"uri": scan.original_filename},
                           "hashes": {"sha-256": scan.sha256}, "length": scan.size}],
            "results": results,
            "properties": {"scan_id": scan.id, "firmware": scan.original_filename,
                           "platform": (scan.identification or {}).get("platform"),
                           "note": "Static analysis of firmware. 'detected' = concrete evidence present; "
                                   "'suspicious'/'unverified' need manual review. No finding is a confirmed "
                                   "exploitable vulnerability."},
        }],
    }


def _uri(component: str) -> str:
    """'fw.tar.gz > fw.tar > /usr/sbin/sshd' -> 'fw.tar.gz/fw.tar/usr/sbin/sshd' (relative, URI-safe)."""
    from urllib.parse import quote
    parts = [p.strip().strip("/") for p in component.split(" > ") if p.strip().strip("/")]
    return quote("/".join(parts) or "firmware", safe="/._-~")
