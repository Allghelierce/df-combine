"""Match identified components against the local CVE database and turn matches into findings.

Matching is version based. A vendor may have backported a fix without changing
the version string, so every result is classified ``unverified``.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from ..core.findings import SEVERITY_ORDER, Evidence, Finding
from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Severity as S
from ..core.scanners.components import parse_version
from .store import CveStore

TOOL = "cve_lookup"
CPE_MAP_PATH = Path(__file__).with_name("cpe_map.json")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z._+~-]{0,63}$")
EVIDENCE_CAP = 10
EMPTY = ("", "*", "-", None)
PLATFORM_COMPONENTS = {"PX4": "px4", "ArduPilot": "ardupilot", "Betaflight": "betaflight", "INAV": "inav"}
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
EDB_URL = "https://www.exploit-db.com/exploits/{}"

_pv = lru_cache(maxsize=200_000)(parse_version)


@lru_cache(maxsize=1)
def load_cpe_map() -> dict[str, dict]:
    return json.loads(CPE_MAP_PATH.read_text(encoding="utf-8"))["components"]


# --------------------------------------------------------------------------- version logic
def nvd_match(version: str, row) -> bool:
    """NVD cpeMatch row: a concrete version must be equal; '*'/'-' needs at least one range bound."""
    v = row["version"]
    bounds = (row["start_incl"], row["start_excl"], row["end_incl"], row["end_excl"])
    if v not in EMPTY:
        return _pv(v) == _pv(version)
    if not any(bounds):
        return False  # "all versions" - too broad to attribute to this component
    pv = _pv(version)
    si, se, ei, ee = bounds
    return not ((si and pv < _pv(si)) or (se and pv <= _pv(se)) or (ei and pv > _pv(ei))
                or (ee and pv >= _pv(ee)))


def _same_prefix(version: str, prefix: str) -> bool:
    want = prefix.split(".")
    return version.split(".")[:len(want)] == want


def in_cna_entry(version: str, e: dict) -> bool:
    """One CVE 5 version entry: exact ``v``, or ``v`` <= version < ``lt`` / <= ``le`` (``le`` may be 'X.Y.*')."""
    v, lt, le = e["v"], e.get("lt"), e.get("le")
    pv = _pv(version)
    if not lt and not le:
        return _pv(v) == pv
    if v not in ("0", "*") and pv < _pv(v):
        return False
    if lt and lt != "*" and not pv < _pv(lt):
        return False
    if le and le != "*":
        if le.endswith(".*"):
            return _same_prefix(version, le[:-2])
        return pv <= _pv(le)
    return True


def cna_affects(version: str, default_status: str, entries: list[dict]) -> bool:
    """CVE 5 semantics: an explicit 'unaffected' range wins, then 'affected', then defaultStatus."""
    hit = False
    for e in entries:
        try:
            inside = in_cna_entry(version, e)
        except (KeyError, TypeError, ValueError):
            continue
        if inside:
            if e["s"] == "unaffected":
                return False
            hit = True
    return hit or default_status == "affected"


# --------------------------------------------------------------------------- lookup
def component_inputs(manifest: dict) -> list[dict]:
    """Components to look up: manifest components plus the identified platform. Untrusted input, bounded."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(name, version, method) -> None:
        name, version = str(name or "").strip().lower(), str(version or "").strip()
        if version[:1] in ("v", "V") and version[1:2].isdigit():
            version = version[1:]
        if NAME_RE.match(name) and VERSION_RE.match(version) and (name, version) not in seen:
            seen.add((name, version))
            out.append({"name": name, "version": version, "method": str(method or "string-match")[:32]})

    for c in (manifest.get("components") or [])[:500]:
        if isinstance(c, dict):
            add(c.get("name"), c.get("version"), c.get("method"))
    ident = manifest.get("identification") or {}
    plat = PLATFORM_COMPONENTS.get(str(ident.get("platform") or ""))
    if plat:
        add(plat, ident.get("platform_version"), "platform-identification")
    return out


def _sort_key(c: dict) -> tuple:
    return (not c["kev"], not c["exploits"], -(c["score"] or 0.0), c["id"])


def lookup(store: CveStore, components: list[dict], cpe_map: dict | None = None) -> dict:
    """Return the tool-run details contract (minus ``db``) for ``components``."""
    cpe_map = cpe_map if cpe_map is not None else load_cpe_map()
    results = []
    for comp in components:
        m = cpe_map.get(comp["name"]) or {}
        cpes, cnas = list(m.get("cpe", [])), [tuple(x) for x in m.get("cna", [])]
        hits: dict[str, str] = {}
        for vp in cpes:
            vendor, product = vp.split(":", 1)
            for row in store.cpe_rows(vendor, product):
                if row["cve_id"] not in hits and nvd_match(comp["version"], row):
                    hits[row["cve_id"]] = "nvd"
        for vendor, product in cnas:
            for row in store.cna_rows(vendor, product):
                cid = row["cve_id"]
                if cid in hits:
                    continue
                try:
                    entries = json.loads(row["versions"])
                except ValueError:
                    continue
                if cna_affects(comp["version"], row["default_status"], entries):
                    hits[cid] = "cna"
        results.append({**comp, "mapped": bool(cpes or cnas), "cpe": cpes, "hits": hits})

    all_ids = {cid for r in results for cid in r["hits"]}
    rows, kev, edb = store.cves(all_ids), store.kev(all_ids), store.exploits(all_ids)
    out_components = []
    for r in results:
        cves = []
        for cid, how in r.pop("hits").items():
            row = rows.get(cid)
            if row is None:
                continue
            k = kev.get(cid)
            cves.append({"id": cid, "score": row["score"], "severity": row["severity"],
                         "cvss_version": row["cvss_version"], "kev": k is not None,
                         "kev_added": k["date_added"] if k else None, "ransomware": bool(k and k["ransomware"]),
                         "exploits": edb.get(cid, [])[:20], "summary": row["summary"], "published": row["published"],
                         "cwe": row["cwe"], "match": how})
        cves.sort(key=_sort_key)
        out_components.append({**r, "cves": cves})

    unique: dict[str, dict] = {}
    for comp in out_components:
        for c in comp["cves"]:
            unique.setdefault(c["id"], c)
    totals = {"components": len(out_components), "cves": len(unique),
              **{s: sum(1 for c in unique.values() if c["severity"] == s) for s in ("critical", "high", "medium", "low")},
              "known_exploited": sum(1 for c in unique.values() if c["kev"]),
              "public_exploit": sum(1 for c in unique.values() if c["exploits"])}
    return {"totals": totals, "components": out_components}


# --------------------------------------------------------------------------- findings
def _counts_text(cves: list[dict]) -> str:
    parts = []
    for s in ("critical", "high", "medium", "low", "info"):
        n = sum(1 for c in cves if c["severity"] == s)
        if n:
            parts.append(f"{n} {s}")
    return ", ".join(parts)


def _cve_line(c: dict) -> str:
    score = f"CVSS {c['score']:.1f}" if c["score"] is not None else "no CVSS score published"
    flags = "".join([" [actively exploited]" if c["kev"] else "", " [public exploit]" if c["exploits"] else ""])
    return f"{c['id']} ({score}, {c['severity']}){flags}: {c['summary'][:160]}"


def build_findings(details: dict) -> list[Finding]:
    db = details.get("db") or {}
    as_of = (db.get("nvd_timestamp") or db.get("built_at") or "unknown")[:10]
    out: list[Finding] = []
    for comp in details.get("components", []):
        cves = comp["cves"]
        if not cves:
            continue
        name, version = comp["name"], comp["version"]
        n = len(cves)
        worst = min(cves, key=lambda c: SEVERITY_ORDER.index(c["severity"]))["severity"]
        kev_n = sum(1 for c in cves if c["kev"])
        edb_n = sum(1 for c in cves if c["exploits"])
        cna_n = sum(1 for c in cves if c["match"] == "cna")
        desc = (f"{n} published CVE{'s' if n != 1 else ''} list {name} {version} as affected (NVD data as of "
                f"{as_of}). {kev_n} {'is' if kev_n == 1 else 'are'} on CISA's Known Exploited Vulnerabilities list "
                f"and {edb_n} {'has' if edb_n == 1 else 'have'} a public exploit in Exploit-DB. ")
        if cna_n:
            desc += (f"{cna_n} were matched on version ranges published by the vendor because NVD has not analysed "
                     "them yet. ")
        desc += ("This is a version-based match only: vendors often backport fixes without changing the version "
                 "string, so each CVE needs confirmation.")
        evidence = [Evidence("cve", _cve_line(c)) for c in cves[:EVIDENCE_CAP]]
        if n > EVIDENCE_CAP:
            evidence.append(Evidence("cve", f"...and {n - EVIDENCE_CAP} more (full list in the Vulnerabilities tab "
                                            "and the JSON report)"))
        out.append(Finding(
            title=f"{name} {version}: {n} known CVE{'s' if n != 1 else ''} ({_counts_text(cves)})",
            description=desc, severity=S(worst), classification=C.unverified,
            confidence=K.low if cna_n == n else K.medium, source_tool=TOOL, rule_id=f"cve-component-{name}",
            affected_component=f"{name} {version}",
            remediation=(f"Upgrade {name} to a release that fixes these CVEs, or confirm with the vendor that the "
                         "fixes were backported."),
            evidence=evidence, cwe="CWE-1104", references=[NVD_URL.format(c["id"]) for c in cves[:EVIDENCE_CAP]],
            tags=["cve-lookup", "outdated-component"] + [c["id"] for c in cves[:EVIDENCE_CAP]]))

        for c in cves:
            if not (c["kev"] or c["exploits"]):
                continue
            sev = c["severity"]
            if c["kev"] and SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index("high"):
                sev = "high"
            what = "actively exploited" if c["kev"] else "public exploit available"
            text = c["summary"]
            if c["score"] is not None:
                text += f" CVSS {c['score']:.1f} (v{c['cvss_version']})."
            if c["kev"]:
                text += (f" CISA lists this CVE as exploited in the wild (added {c['kev_added']})"
                         + (", including in ransomware campaigns." if c["ransomware"] else "."))
            if c["exploits"]:
                text += f" Exploit-DB has {len(c['exploits'])} public exploit(s)."
            text += f" Matched on {name} {version} by version only; confirm the vulnerable code is present."
            ev = [Evidence("cve", f"{c['id']} matched {name} {version} "
                                  f"({'NVD' if c['match'] == 'nvd' else 'vendor-published'} version data)")]
            if c["kev"]:
                ev.append(Evidence("reference", f"CISA KEV, added {c['kev_added']}"))
            ev += [Evidence("reference", f"Exploit-DB {e}", EDB_URL.format(e)) for e in c["exploits"][:5]]
            out.append(Finding(
                title=f"{c['id']} in {name} {version} — {what}", description=text, severity=S(sev),
                classification=C.unverified, confidence=K.low if c["match"] == "cna" else K.medium, source_tool=TOOL,
                rule_id=f"cve-{c['id']}", affected_component=f"{name} {version}",
                remediation=f"Prioritise this CVE: upgrade {name} or confirm a vendor backport.",
                evidence=ev, cwe=c.get("cwe") or "CWE-1104",
                references=[NVD_URL.format(c["id"])] + [EDB_URL.format(e) for e in c["exploits"][:5]],
                tags=["cve-lookup", "known-exploited" if c["kev"] else "public-exploit", c["id"]]))
    return out


def supersede_kb(findings: list[Finding], details: dict) -> list[Finding]:
    """Drop built-in knowledge-base findings whose CVEs the lookup already reports for the same component."""
    covered = {f"{c['name']} {c['version']}": {x["id"] for x in c["cves"]} for c in details.get("components", [])}
    keep = []
    for f in findings:
        if f.source_tool == "builtin:components":
            ids = {t for t in f.tags if t.startswith("CVE-")}
            if ids and ids <= covered.get(f.affected_component, set()):
                continue
        keep.append(f)
    return keep
