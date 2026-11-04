"""FACT adapter (Firmware Analysis and Comparison Tool, https://github.com/fkie-cad/FACT_core).

Facts established from the upstream project:
* FACT is a full platform (web UI + backend + database + many plugin
  containers), not a CLI. Minimum 4 cores / 8 GB RAM / 10 GB disk; the
  installer targets Debian/Ubuntu; the Docker variant is unmaintained.
  It is therefore integrated as an *external service* via its REST API.
* Upload: ``PUT /rest/firmware`` with JSON {binary (base64), device_name,
  device_part, device_class, file_name, version, vendor, release_date, tags,
  requested_analysis_systems}; returns {"uid": ...}.
* Results: ``GET /rest/firmware/<uid>?summary=true`` -> {"firmware":
  {"meta_data", "analysis": {plugin: {..., "summary": [...]}}}}.
* Status: ``GET /rest/status`` (system_status incl. backend analysis state).
* FACT unpacks the firmware itself and runs its own plugins (crypto_material,
  users_and_passwords, cve_lookup, software_components, cwe_checker, ...).

This adapter has been validated against recorded/synthetic API responses in
the test-suite, not against a live FACT deployment.
"""
from __future__ import annotations

import base64
import json
import time

import httpx

from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from .base import AdapterContext, AdapterResult, ToolAdapter

REQUESTED_PLUGINS = ["crypto_material", "users_and_passwords", "software_components", "cve_lookup",
                     "known_vulnerabilities", "exploit_mitigations", "cwe_checker", "elf_analysis"]

PLUGIN_MAP = {
    # plugin: (severity, classification, title prefix, cwe)
    "crypto_material": (S.high, C.detected, "Cryptographic material", "CWE-321"),
    "users_and_passwords": (S.high, C.detected, "Credentials", "CWE-798"),
    "known_vulnerabilities": (S.high, C.unverified, "Known vulnerability signature", None),
    "cve_lookup": (S.medium, C.unverified, "CVE match (version-based)", "CWE-1104"),
    "cwe_checker": (S.low, C.unverified, "cwe_checker warning", None),
    "exploit_mitigations": (S.low, C.detected, "Exploit mitigation", "CWE-693"),
}


class FactAdapter(ToolAdapter):
    name = "fact"
    display_name = "FACT (FKIE)"
    homepage = "https://github.com/fkie-cad/FACT_core"
    inputs = "Original firmware upload (FACT performs its own unpacking); requires a running FACT instance"

    def _client(self) -> httpx.Client:
        headers = {"Accept": "application/json"}
        if self.settings.fact_api_key:
            headers["Authorization"] = self.settings.fact_api_key
        return httpx.Client(base_url=self.settings.fact_url.rstrip("/"), headers=headers, timeout=60,
                            verify=self.settings.fact_verify_tls)

    def status(self):
        if not self.settings.fact_url:
            return self._status(False, "Not configured: set DFA_FACT_URL to a running FACT instance "
                                       "(FACT is a separate platform; see docs/TOOLS.md).", mode="remote")
        try:
            with self._client() as c:
                r = c.get("/rest/status")
            if r.status_code == 200:
                return self._status(True, f"FACT reachable at {self.settings.fact_url}", mode="remote")
            return self._status(False, f"FACT at {self.settings.fact_url} returned HTTP {r.status_code}", mode="remote")
        except httpx.HTTPError as exc:
            return self._status(False, f"FACT at {self.settings.fact_url} unreachable: {exc}", mode="remote")

    def plan(self, ctx: AdapterContext):
        size = ctx.input_path.stat().st_size
        if size > self.settings.fact_max_upload_mb * 1024 * 1024:
            return [], f"firmware is larger than DFA_FACT_MAX_UPLOAD_MB ({self.settings.fact_max_upload_mb} MiB)"
        return [{"path": ctx.input_path}], "original upload"

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        ident = ctx.manifest.get("identification", {})
        payload = {
            "binary": base64.b64encode(ctx.input_path.read_bytes()).decode(),
            "file_name": ctx.original_name[:200], "device_name": f"dfa-{ctx.scan_id[:8]}",
            "device_part": "complete", "device_class": "UAV/drone", "vendor": ident.get("platform") or "unknown",
            "version": str(ident.get("platform_version") or "unknown"), "release_date": "1970-01-01",
            "tags": "drone-firmware-analyzer", "requested_analysis_systems": REQUESTED_PLUGINS,
        }
        with self._client() as c:
            r = c.put("/rest/firmware", json=payload)
            if r.status_code not in (200, 201):
                return AdapterResult("failed", f"FACT upload failed: HTTP {r.status_code} {r.text[:300]}")
            uid = r.json().get("uid")
            if not uid:
                return AdapterResult("failed", f"FACT upload returned no uid: {r.text[:300]}")
            ctx.log(f"FACT: submitted as {uid}, waiting for analysis")
            deadline = time.monotonic() + self.settings.fact_timeout_s
            fw = None
            while time.monotonic() < deadline:
                if not self._in_progress(c, uid):
                    fr = c.get(f"/rest/firmware/{uid}", params={"summary": "true"})
                    if fr.status_code == 200:
                        fw = fr.json().get("firmware")
                        break
                time.sleep(self.settings.fact_poll_s)
            if fw is None:
                return AdapterResult("timeout", f"FACT analysis of {uid} did not finish within "
                                                f"{self.settings.fact_timeout_s}s", details={"uid": uid})
        (out_dir / "firmware.json").write_text(json.dumps(fw, indent=1)[:50_000_000])
        findings = normalize(fw, ctx.original_name)
        return AdapterResult("completed", f"FACT analysis {uid}: {len(findings)} findings", findings,
                             str(out_dir), {"uid": uid, "fact_url": self.settings.fact_url})

    @staticmethod
    def _in_progress(c: httpx.Client, uid: str) -> bool:
        try:
            r = c.get("/rest/status")
            data = r.json()
        except (httpx.HTTPError, ValueError):
            return True
        analysis = (data.get("system_status", {}).get("backend", {}) or {}).get("analysis", {}) or {}
        current = analysis.get("current_analyses") or {}
        return uid in current


def normalize(fw: dict, name: str) -> list[Finding]:
    out: list[Finding] = []
    analysis = (fw or {}).get("analysis", {}) or {}
    for plugin, result in analysis.items():
        if plugin not in PLUGIN_MAP or not isinstance(result, dict):
            continue
        summary = result.get("summary")
        if not summary:
            continue
        items = list(summary.items()) if isinstance(summary, dict) else [(s, []) for s in summary]
        sev, cls, prefix, cwe = PLUGIN_MAP[plugin]
        for label, uids in items[:200]:
            label_s = str(label)
            if plugin == "exploit_mitigations" and "enabled" in label_s.lower():
                continue  # only report missing mitigations
            s = sev
            if plugin == "cve_lookup":
                low = label_s.lower()
                s = S.high if "critical" in low or "high" in low else S.medium
            out.append(Finding(
                title=f"[FACT] {prefix}: {label_s[:160]}",
                description=(f"FACT plugin '{plugin}' reported '{label_s}'. "
                             + ("Version/signature based result - requires manual verification."
                                if cls == C.unverified else "Reported by FACT's analysis of the firmware contents.")),
                severity=s, classification=cls, confidence=K.medium, source_tool="fact", rule_id=f"fact-{plugin}",
                affected_component=name if not uids else f"{name} ({len(uids)} FACT object(s))",
                remediation="Review the corresponding FACT analysis page for affected files.",
                evidence=[Evidence("tool_output", label_s[:240], f"FACT uid {u}") for u in list(uids)[:10]]
                or [Evidence("tool_output", label_s[:240])],
                cwe=cwe, tags=["fact", plugin]))
    return out
