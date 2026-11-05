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
import re
import time
from pathlib import Path

import httpx

from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from .base import AdapterContext, AdapterResult, ToolAdapter

FACT_OPAQUE_CONTAINERS = {"px4", "apj", "fw_json", "ihex", "dfu"}
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
        # No keep-alive: FACT's uWSGI closes idle connections while we poll, and a reused stale connection
        # surfaces as "connection reset by peer" on the next request. Connection failures are retried.
        transport = httpx.HTTPTransport(retries=2, verify=self.settings.fact_verify_tls,
                                        limits=httpx.Limits(max_keepalive_connections=0))
        return httpx.Client(base_url=self.settings.fact_url.rstrip("/"), headers=headers, timeout=60,
                            transport=transport)

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
        limit = self.settings.fact_max_upload_mb * 1024 * 1024
        size = ctx.input_path.stat().st_size
        if size > limit:
            return [], f"firmware is larger than DFA_FACT_MAX_UPLOAD_MB ({self.settings.fact_max_upload_mb} MiB)"
        targets = [{"path": ctx.input_path, "label": "original upload", "part": "complete"}]
        arts = ctx.manifest.get("extraction", {}).get("artifacts", [])
        root = arts[0] if arts else {}
        if root.get("format") in FACT_OPAQUE_CONTAINERS:
            # FACT's extractor cannot open these drone containers (verified for .px4: FACT saw 1 JSON file),
            # so the decoded firmware image(s) are submitted as well.
            for a in arts:
                if a.get("parent_id") == root.get("id") and a.get("format") in ("cortexm_raw", "elf", "raw") \
                        and 0 < a.get("size", 0) <= limit:
                    targets.append({"path": ctx.artifact_path(a), "label": f"decoded image {a['name']}",
                                    "part": "application image (decoded by Drone Firmware Analyzer)"})
        return targets, f"{len(targets)} submission(s)"

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        ident = ctx.manifest.get("identification", {})
        findings: list[Finding] = []
        components: list[dict] = []
        submissions = []
        failed = 0
        with self._client() as c:
            for i, t in enumerate(targets):
                payload = {
                    "binary": base64.b64encode(Path(t["path"]).read_bytes()).decode(),
                    "file_name": (ctx.original_name if i == 0 else Path(t["path"]).name)[:200],
                    "device_name": f"dfa-{ctx.scan_id[:8]}", "device_part": t["part"], "device_class": "UAV/drone",
                    "vendor": ident.get("platform") or "unknown", "version": str(ident.get("platform_version") or "unknown"),
                    "release_date": "1970-01-01", "tags": "drone-firmware-analyzer",
                    "requested_analysis_systems": REQUESTED_PLUGINS,
                }
                r = self._put_once_more_on_reset(c, payload)
                if r.status_code not in (200, 201) or not r.json().get("uid"):
                    failed += 1
                    submissions.append({"target": t["label"], "status": "failed",
                                        "error": f"HTTP {r.status_code} {r.text[:200]}"})
                    continue
                uid = r.json()["uid"]
                ctx.log(f"FACT: submitted {t['label']} as {uid}; waiting for unpacking and analysis")
                fw = self._wait(c, uid)
                if fw is None:
                    failed += 1
                    submissions.append({"target": t["label"], "uid": uid, "status": "timeout"})
                    continue
                (out_dir / f"firmware_{i}.json").write_text(json.dumps(fw, indent=1)[:50_000_000])
                meta = fw.get("meta_data", {}) or {}
                fs = normalize(fw, ctx.original_name if i == 0 else f"{ctx.original_name} > {Path(t['path']).name}")
                findings += fs
                components += fact_components(fw, t["label"])
                analysis = fw.get("analysis", {}) or {}
                file_types = sorted((analysis.get("file_type", {}) or {}).get("summary", {}) or {})
                unpack = sorted((analysis.get("unpacker", {}) or {}).get("summary", {}) or {})
                with_results = sorted(p for p, r in analysis.items()
                                      if isinstance(r, dict) and r.get("summary") and p not in ("file_type", "unpacker"))
                submissions.append({"target": t["label"], "uid": uid, "status": "completed",
                                    "files_analysed": 1 + int(meta.get("number_of_included_files") or 0),
                                    "file_types": file_types[:15], "unpacker": unpack, "findings": len(fs),
                                    "plugins_with_results": with_results})
        ok = len(targets) - failed
        def describe(s: dict) -> str:
            if s["status"] != "completed":
                return s["status"] + (f" ({s.get('error', '')})" if s.get("error") else "")
            text = (f"FACT analysed {s['files_analysed']} file(s) [{', '.join(s['file_types'][:4]) or 'no type'}], "
                    f"unpacker: {', '.join(s['unpacker']) or 'n/a'}, {s['findings']} finding(s)")
            if not s["plugins_with_results"]:
                text += "; no FACT plug-in produced results for this input"
            return text

        msg = "; ".join(f"{s['target']}: {describe(s)}" for s in submissions)
        return AdapterResult("completed" if ok else ("timeout" if any(s["status"] == "timeout" for s in submissions)
                                                     else "failed"),
                             msg, findings, str(out_dir), {"submissions": submissions, "fact_url": self.settings.fact_url,
                                                           "components": components})

    @staticmethod
    def _put_once_more_on_reset(c: httpx.Client, payload: dict) -> httpx.Response:
        """FACT derives the UID from the content, so repeating an upload after a dropped connection is safe."""
        try:
            return c.put("/rest/firmware", json=payload)
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.WriteError):
            time.sleep(2)
            return c.put("/rest/firmware", json=payload)

    def _wait(self, c: httpx.Client, uid: str) -> dict | None:
        deadline = time.monotonic() + self.settings.fact_timeout_s
        while time.monotonic() < deadline:
            time.sleep(self.settings.fact_poll_s)
            if self._in_progress(c, uid):
                continue
            fr = c.get(f"/rest/firmware/{uid}", params={"summary": "true"})
            if fr.status_code == 200:
                fw = fr.json().get("firmware") or {}
                if "unpacker" in (fw.get("analysis") or {}):
                    return fw
        return None

    @staticmethod
    def _in_progress(c: httpx.Client, uid: str) -> bool:
        """Real FACT status: system_status.backend.{analysis.current_analyses, unpacking.unpacking_queue}."""
        try:
            r = c.get("/rest/status")
            data = r.json()
        except (httpx.HTTPError, ValueError):
            return True
        backend = data.get("system_status", {}).get("backend", {}) or {}
        analysis = backend.get("analysis", {}) or {}
        if uid in (analysis.get("recently_finished_analyses") or {}):
            return False
        if uid in (analysis.get("current_analyses") or {}):
            return True
        queued = (backend.get("unpacking", {}) or {}).get("unpacking_queue", 0) or 0
        return bool(queued) or bool(analysis.get("analysis_main_scheduler", 0))


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


_VERSIONED = re.compile(r"^(?P<name>.+?)\s+(?P<version>\d+(?:\.\d+)+[\w.\-]*)$")


def fact_components(fw: dict, label: str) -> list[dict]:
    """Software components identified by FACT's software_components plugin (YARA signatures)."""
    summary = ((fw or {}).get("analysis", {}).get("software_components", {}) or {}).get("summary") or {}
    out = []
    for item in summary:
        m = _VERSIONED.match(str(item))
        name, version = (m.group("name"), m.group("version")) if m else (str(item), "")
        out.append({"name": name.lower().replace(" ", "-")[:64], "version": version, "sources": [f"FACT ({label})"],
                    "method": "fact:software_components"})
    return out
