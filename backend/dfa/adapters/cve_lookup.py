"""CVE lookup against the local CVE database (see :mod:`dfa.cve`).

* Input: the component names/versions the built-in scanners identified, plus
  the identified flight-controller platform and version. The firmware itself
  is not read and nothing is sent off the host.
* Data: NVD (fkie-cad mirror), CISA KEV and Exploit-DB, built locally with
  ``make cve-db``. Without the database the tool reports ``unavailable`` and the
  small built-in knowledge base is still applied.
* Results are version-based matches and are always classified ``unverified``.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from ..cve.match import build_findings, component_inputs, lookup
from ..cve.store import CveDbError, CveStore
from .base import AdapterContext, AdapterResult, ToolAdapter, ToolStatus

SUMMARY_CAP = 200  # per-CVE summary length kept in the tool-run details


def _age_days(meta: dict) -> int | None:
    for key in ("nvd_timestamp", "built_at"):
        try:
            ts = datetime.fromisoformat(meta.get(key, ""))
        except ValueError:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - ts).days)
    return None


class CveLookupAdapter(ToolAdapter):
    name = "cve_lookup"
    display_name = "CVE lookup"
    homepage = "https://nvd.nist.gov/"
    inputs = "Identified software components and platform versions (no firmware data leaves the host)"

    def enabled(self) -> bool:
        return self.settings.cve_lookup_enabled

    def db_info(self, meta: dict) -> dict:
        age = _age_days(meta)
        return {"built_at": meta.get("built_at", ""), "nvd_timestamp": meta.get("nvd_timestamp", ""),
                "cve_count": int(meta.get("cve_count") or 0), "age_days": age,
                "stale": age is not None and age > self.settings.cve_db_max_age_days}

    def _stale_note(self, info: dict) -> str:
        return (f"; CVE database is out of date ({info['age_days']} days old), refresh it with `make cve-db`"
                if info["stale"] else "")

    def status(self) -> ToolStatus:
        path = self.settings.cve_db_file
        if not path.is_file():
            return self._status(False, f"CVE database not installed. Run `make cve-db` to build it (expected at {path})",
                                mode="local")
        try:
            with CveStore(path) as st:
                info = self.db_info(st.meta())
        except CveDbError as exc:
            # Present but unusable: reported as a failed run (with the reason) rather than silently skipped.
            return self._status(True, f"CVE database at {path} is unusable: {exc}", mode="local")
        return self._status(True, f"{info['cve_count']:,} CVEs, NVD data from {info['nvd_timestamp'][:10]}"
                                  + self._stale_note(info), mode="local", version=info["nvd_timestamp"][:10] or None)

    def plan(self, ctx: AdapterContext) -> tuple[list, str]:
        comps = component_inputs(ctx.manifest)
        return comps, "no software components or platform versions with a version string were identified"

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        with CveStore(self.settings.cve_db_file) as st:
            details = lookup(st, targets)
            details["db"] = self.db_info(st.meta())
        for comp in details["components"]:
            for c in comp["cves"]:
                if len(c["summary"]) > SUMMARY_CAP:
                    c["summary"] = c["summary"][:SUMMARY_CAP - 3].rstrip() + "..."
        findings = build_findings(details)
        raw = ctx.tool_dir(self.name) / "cve_lookup.json"
        raw.write_text(json.dumps(details, indent=1))
        t = details["totals"]
        with_cves = sum(1 for c in details["components"] if c["cves"])
        unmapped = [f"{c['name']} {c['version']}" for c in details["components"] if not c["mapped"]]
        msg = (f"{t['cves']:,} CVEs matched in {with_cves} of {t['components']} components "
               f"({t['known_exploited']} actively exploited, {t['public_exploit']} with a public exploit)")
        if unmapped:
            msg += f"; no CVE mapping for {', '.join(unmapped[:8])}" + (" and more" if len(unmapped) > 8 else "")
        msg += self._stale_note(details["db"])
        return AdapterResult("completed", msg, findings, raw_output_path=str(raw), details=details)
