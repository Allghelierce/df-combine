"""Compare two scans (e.g. two releases of the same firmware).

Findings are matched on a version-independent key: source tool, rule id and
the in-filesystem path of the affected component (the archive/image file
names that wrap it usually change between releases).  Component versions are
compared by name.
"""
from __future__ import annotations

import re

from .models import Scan
from .reports.export import finding_to_dict, scan_to_dict

_VERSIONED_TITLE = re.compile(r"\s+-\s+\S+\s+\d[\w.\-]*$")


def finding_key(f) -> tuple[str, str, str]:
    comp = f.affected_component.rsplit(" > ", 1)[-1]
    if comp.startswith("/"):
        where = comp
    elif f.rule_id.startswith("outdated-"):
        where = f.rule_id  # "busybox 1.31.1" -> keyed by component, version change shows in components diff
    else:
        where = _VERSIONED_TITLE.sub("", f.title)
    return f.source_tool, f.rule_id, where


def compare(base: Scan, target: Scan) -> dict:
    bk = {finding_key(f): f for f in base.findings}
    tk = {finding_key(f): f for f in target.findings}
    new = [finding_to_dict(tk[k]) for k in tk.keys() - bk.keys()]
    resolved = [finding_to_dict(bk[k]) for k in bk.keys() - tk.keys()]
    unchanged = []
    severity_changed = []
    for k in tk.keys() & bk.keys():
        d = finding_to_dict(tk[k])
        if bk[k].severity != tk[k].severity:
            d["previous_severity"] = bk[k].severity
            severity_changed.append(d)
        else:
            unchanged.append(d)

    def comps(scan: Scan) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for c in scan.components or []:
            out.setdefault(c["name"], set()).add(c["version"])
        return out

    bc, tc = comps(base), comps(target)
    comp_changes = []
    for name in sorted(bc.keys() | tc.keys()):
        before, after = sorted(bc.get(name, set())), sorted(tc.get(name, set()))
        if before != after:
            kind = "added" if not before else "removed" if not after else "changed"
            comp_changes.append({"name": name, "before": before, "after": after, "change": kind})

    def order(items: list[dict]) -> list[dict]:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(items, key=lambda f: (rank[f["severity"]], f["title"]))

    return {
        "base": scan_to_dict(base, include_findings=False),
        "target": scan_to_dict(target, include_findings=False),
        "new": order(new), "resolved": order(resolved), "severity_changed": order(severity_changed),
        "unchanged": order(unchanged), "components": comp_changes,
        "summary": {"new": len(new), "resolved": len(resolved), "severity_changed": len(severity_changed),
                    "unchanged": len(unchanged), "component_changes": len(comp_changes)},
    }
