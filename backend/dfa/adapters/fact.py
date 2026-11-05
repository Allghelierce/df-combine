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

CLOCK_SKEW_S = 60  # tolerated difference between our clock and the FACT host's

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
                    "requested_analysis_systems": list(self.settings.fact_plugins),
                }
                submitted = time.time()
                r = self._put_once_more_on_reset(c, payload)
                if r.status_code not in (200, 201) or not r.json().get("uid"):
                    failed += 1
                    submissions.append({"target": t["label"], "status": "failed",
                                        "error": f"HTTP {r.status_code} {r.text[:200]}"})
                    continue
                uid = r.json()["uid"]
                ctx.log(f"FACT: submitted {t['label']} as {uid}; waiting for unpacking and analysis")
                state, fw = self._wait(c, uid, submitted)
                entry: dict = {"target": t["label"], "uid": uid, "status": state}
                if fw:
                    (out_dir / f"firmware_{i}.json").write_text(json.dumps(fw, indent=1)[:50_000_000])
                    meta = fw.get("meta_data", {}) or {}
                    creds = self._credential_details(c, fw)
                    fs = normalize(fw, ctx.original_name if i == 0 else f"{ctx.original_name} > {Path(t['path']).name}",
                                   creds)
                    findings += fs
                    components += fact_components(fw, t["label"])
                    analysis = fw.get("analysis", {}) or {}
                    entry.update({
                        "files_analysed": 1 + int(meta.get("number_of_included_files") or 0),
                        "file_types": sorted((analysis.get("file_type", {}) or {}).get("summary", {}) or {})[:15],
                        "unpacker": sorted((analysis.get("unpacker", {}) or {}).get("summary", {}) or {}),
                        "findings": len(fs), "partial": state != "completed",
                        "plugins_with_results": sorted(p for p, r in analysis.items() if isinstance(r, dict)
                                                       and r.get("summary") and p not in ("file_type", "unpacker"))})
                if state != "completed":
                    failed += 1
                submissions.append(entry)
        ok = len(targets) - failed
        def describe(s: dict) -> str:
            if s["status"] == "timeout":
                head = f"FACT did not finish within {self.settings.fact_timeout_s}s"
            elif s["status"] == "cancelled":
                head = "the analysis was cancelled in FACT"
            elif s["status"] != "completed":
                return s["status"] + (f" ({s.get('error', '')})" if s.get("error") else "")
            else:
                head = ""
            if "files_analysed" not in s:
                return head or s["status"]
            text = (f"FACT analysed {s['files_analysed']} file(s) [{', '.join(s['file_types'][:4]) or 'no type'}], "
                    f"unpacker: {', '.join(s['unpacker']) or 'n/a'}, {s['findings']} finding(s)")
            if s.get("partial"):
                text = f"{head}; partial results so far: {text}"
            if not s["plugins_with_results"]:
                text += "; no FACT plug-in produced results for this input"
            return text

        msg = "; ".join(f"{s['target']}: {describe(s)}" for s in submissions)
        return AdapterResult("completed" if ok else ("timeout" if any(s["status"] == "timeout" for s in submissions)
                                                     else "failed"),
                             msg, findings, str(out_dir), {"submissions": submissions, "fact_url": self.settings.fact_url,
                                                           "components": components})

    @staticmethod
    def _credential_details(c: httpx.Client, fw: dict, limit: int = 25) -> list[dict] | None:
        """Full users_and_passwords results of the files the summary points to (the summary alone does not
        say whether an account has a password). None if they cannot be retrieved."""
        summary = (((fw or {}).get("analysis") or {}).get("users_and_passwords") or {}).get("summary") or {}
        uids = sorted({u for v in summary.values() for u in v}) if isinstance(summary, dict) else []
        entries: list[dict] = []
        try:
            for uid in uids[:limit]:
                r = c.get(f"/rest/file_object/{uid}")
                if r.status_code != 200:
                    return None
                fo = r.json().get("file_object") or {}
                result = (((fo.get("analysis") or {}).get("users_and_passwords") or {}).get("result")) or {}
                path = (fo.get("meta_data") or {}).get("hid")
                for kind in ("unix", "http", "mosquitto"):
                    for e in result.get(kind) or []:
                        if isinstance(e, dict):
                            entries.append({**e, "path": path, "type": e.get("type") or kind})
        except (httpx.HTTPError, ValueError):
            return None
        return entries

    @staticmethod
    def _put_once_more_on_reset(c: httpx.Client, payload: dict) -> httpx.Response:
        """FACT derives the UID from the content, so repeating an upload after a dropped connection is safe."""
        try:
            return c.put("/rest/firmware", json=payload)
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.WriteError):
            time.sleep(2)
            return c.put("/rest/firmware", json=payload)

    def _wait(self, c: httpx.Client, uid: str, submitted: float = 0.0) -> tuple[str, dict | None]:
        """Poll until FACT finishes. Returns ('completed' | 'cancelled' | 'timeout', firmware summary or None);
        on timeout or cancellation the summary holds whatever FACT had analysed by then."""
        deadline = time.monotonic() + self.settings.fact_timeout_s
        while time.monotonic() < deadline:
            time.sleep(self.settings.fact_poll_s)
            state = self._state(c, uid, submitted)
            if state == "running":
                continue
            fw = self._fetch(c, uid)
            if state == "cancelled":
                return "cancelled", fw
            if fw and "unpacker" in (fw.get("analysis") or {}):
                return "completed", fw
        return "timeout", self._fetch(c, uid)

    @staticmethod
    def _fetch(c: httpx.Client, uid: str) -> dict | None:
        try:
            fr = c.get(f"/rest/firmware/{uid}", params={"summary": "true"})
        except httpx.HTTPError:
            return None
        if fr.status_code != 200:
            return None
        try:
            return fr.json().get("firmware") or None
        except ValueError:
            return None

    @staticmethod
    def _state(c: httpx.Client, uid: str, since: float = 0.0) -> str:
        """'running' | 'finished' | 'cancelled' | 'unknown' from FACT's status endpoint
        (system_status.backend.analysis.{current_analyses, recently_finished_analyses,
        recently_canceled_analyses}, unpacking.unpacking_queue).

        FACT UIDs are content hashes, so a re-submitted file has the same UID as an earlier run: finished
        and cancelled entries only count if FACT stamped them (time_finished) after our submission."""
        try:
            r = c.get("/rest/status")
            data = r.json()
        except (httpx.HTTPError, ValueError):
            return "running"
        backend = data.get("system_status", {}).get("backend", {}) or {}
        analysis = backend.get("analysis", {}) or {}
        if uid in (analysis.get("current_analyses") or {}):
            return "running"

        def ours(entries: dict) -> bool:
            entry = (entries or {}).get(uid)
            return isinstance(entry, dict) and float(entry.get("time_finished") or 0) >= since - CLOCK_SKEW_S

        if ours(analysis.get("recently_canceled_analyses")):
            return "cancelled"
        if ours(analysis.get("recently_finished_analyses")):
            return "finished"
        queued = (backend.get("unpacking", {}) or {}).get("unpacking_queue", 0) or 0
        return "running" if queued or analysis.get("analysis_main_scheduler", 0) else "unknown"


# FACT/checksec labels that describe a missing or weakening property. Everything else (mitigations that are
# enabled, 'PIE/DSO present', stripped symbols, the rarely used CLANGCFI/SAFESTACK) is not a weakness.
MITIGATION_WEAK = {
    "NX disabled": (S.medium, "the stack/heap is executable (NX disabled)"),
    "CANARY disabled": (S.low, "built without stack canaries"),
    "PIE disabled": (S.low, "not position independent, so ASLR does not apply to the executable"),
    "RELRO disabled": (S.low, "built without RELRO (writable relocation tables)"),
    "RPATH enabled": (S.low, "an RPATH is set (library search path that can enable library hijacking)"),
    "RUNPATH enabled": (S.low, "a RUNPATH is set (library search path that can enable library hijacking)"),
}
_REAL_HASH = re.compile(r"^(\$[0-9a-z]+\$.+|[./0-9A-Za-z]{13})$")


def credential_findings(entries: list[dict] | None, name: str, listed: int) -> list[Finding]:
    """FACT users_and_passwords entries (full per-file results). The plug-in's summary lists every account
    line ('root:unix'), including shadowed ('x') and locked ('*', '!') ones, so only entries with an actual
    password hash, a cracked password or an empty password field are findings."""
    if entries is None:
        if not listed:
            return []
        return [Finding(
            title=f"[FACT] {listed} account entr{'y' if listed == 1 else 'ies'} in password files",
            description="FACT listed account entries, but their password fields could not be retrieved, so "
                        "it is unknown whether any has a password set. The built-in shadow/passwd checks apply.",
            severity=S.info, classification=C.info, confidence=K.low, source_tool="fact",
            rule_id="fact-users_and_passwords", affected_component=name,
            remediation="Review the password files in FACT.", tags=["fact", "users_and_passwords"])]
    out = []
    for e in entries:
        user, pw, hsh, path = e.get("username", "?"), e.get("password"), e.get("password_hash") or "", e.get("path")
        loc = f"{path} ({e.get('type', 'unix')})" if path else e.get("type", "unix")
        if pw:
            title, sev = f"[FACT] Password of '{user}' recovered from its hash", S.high
            desc = ("FACT cracked the password hash of this account with a wordlist: the password is weak and "
                    "identical on every device built from this image.")
            ev = f"{user}:{pw[:1]}{'*' * max(len(pw) - 1, 3)} (len={len(pw)})"
        elif _REAL_HASH.match(hsh):
            title, sev = f"[FACT] Password hash for '{user}' stored in the image", S.medium
            desc = ("The image ships a password hash for this account; every device shares it and it can be "
                    "attacked offline. FACT could not crack it with its wordlist.")
            ev = f"{user}:{hsh[:3]}...{hsh[-4:]}"
        elif hsh == "" and e.get("type", "unix") in ("unix", "http"):
            title, sev = f"[FACT] Account '{user}' has an empty password field", S.high
            desc = "An empty password field allows logging in to this account without a password."
            ev = f"{user}:<empty>"
        else:
            continue  # 'x' (shadowed), '*', '!', '!!': no usable credential
        out.append(Finding(
            title=title, description=desc, severity=sev, classification=C.detected, confidence=K.medium,
            source_tool="fact", rule_id="fact-users_and_passwords", affected_component=f"{name} > {path or 'password file'}",
            remediation="Remove default passwords from the image; provision per-device credentials or disable "
                        "password login for the account.",
            evidence=[Evidence("config", ev, loc)], cwe="CWE-798", tags=["fact", "users_and_passwords", "credentials"]))
    return out


def normalize(fw: dict, name: str, credentials: list[dict] | None = None) -> list[Finding]:
    out: list[Finding] = []
    analysis = (fw or {}).get("analysis", {}) or {}
    for plugin, result in analysis.items():
        if plugin not in PLUGIN_MAP or not isinstance(result, dict):
            continue
        summary = result.get("summary")
        if not summary:
            continue
        items = list(summary.items()) if isinstance(summary, dict) else [(s, []) for s in summary]
        if plugin == "users_and_passwords":
            out += credential_findings(credentials, name, len(items))
            continue
        sev, cls, prefix, cwe = PLUGIN_MAP[plugin]
        for label, uids in items[:200]:
            label_s = str(label)
            s, c, why = sev, cls, ""
            if plugin == "exploit_mitigations":
                if label_s not in MITIGATION_WEAK:
                    continue
                s, why = MITIGATION_WEAK[label_s]
            elif plugin == "crypto_material" and "private" not in label_s.lower():
                s, c = S.info, C.info  # certificates and public keys are not secrets
                why = "public key material or a certificate (not a secret)"
            elif plugin == "cve_lookup":
                low = label_s.lower()
                s = S.high if "critical" in low or "high" in low else S.medium
            out.append(Finding(
                title=f"[FACT] {prefix}: {label_s[:160]}",
                description=(f"FACT plugin '{plugin}' reported '{label_s}'" + (f": {why}." if why else ". ")
                             + ("Version/signature based result - requires manual verification."
                                if c == C.unverified else "Reported by FACT's analysis of the firmware contents.")),
                severity=s, classification=c, confidence=K.medium, source_tool="fact", rule_id=f"fact-{plugin}",
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
