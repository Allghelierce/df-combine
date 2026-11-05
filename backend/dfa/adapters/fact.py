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

Validated against a live FACT_core instance (see docs/TOOLS.md); the
test-suite replays responses in FACT's real result format.
"""
from __future__ import annotations

import base64
import io
import json
import re
import tarfile
import time
from pathlib import Path

import httpx

from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from ..core.scanners.secrets import CRYPTO_LIBRARY
from .base import AdapterContext, AdapterResult, ToolAdapter

FACT_OPAQUE_CONTAINERS = {"px4", "apj", "fw_json", "ihex", "dfu"}
# Filesystems FACT's extractor has no unpacker for: the files Drone Firmware Analyzer extracted from them
# are submitted as a tar archive, so FACT's plug-ins see their contents.
FACT_UNSUPPORTED_FS = {"cromfs"}

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
        targets = [{"artifact": {"path": "<input>"}, "file_name": ctx.original_name, "label": "original upload",
                    "part": "complete"}]
        ex = ctx.manifest.get("extraction", {})
        arts = ex.get("artifacts", [])
        root = arts[0] if arts else {}
        if root.get("format") in FACT_OPAQUE_CONTAINERS:
            # FACT's extractor cannot open these drone containers (verified for .px4: FACT saw 1 JSON file),
            # so the decoded firmware image(s) are submitted as well.
            for a in arts:
                if a.get("parent_id") == root.get("id") and a.get("format") in ("cortexm_raw", "elf", "raw") \
                        and 0 < a.get("size", 0) <= limit:
                    targets.append({"artifact": a, "file_name": Path(a["path"]).name,
                                    "label": f"decoded image {a['name']}",
                                    "part": "application image (decoded by Drone Firmware Analyzer)"})
        for fs in ex.get("filesystems", []):
            if fs.get("type") not in FACT_UNSUPPORTED_FS:
                continue
            members = [a for a in arts if a.get("parent_id") == fs.get("artifact_id") and a.get("origin") == "extracted"
                       and str(a.get("path", "")).startswith(str(fs.get("root", "")) + "/")]
            if members and sum(a.get("size", 0) for a in members) <= limit:
                targets.append({"tree": members, "file_name": f"{fs.get('name', 'filesystem')}.tar",
                                "label": f"files extracted from {fs['type']} {fs.get('name', '')}".strip(),
                                "part": f"{fs['type']} filesystem contents (extracted by Drone Firmware Analyzer; "
                                        "FACT has no unpacker for this format)"})
        return targets, f"{len(targets)} submission(s)"

    def _payload(self, ctx: AdapterContext, t: dict) -> bytes:
        limit = self.settings.fact_max_upload_mb * 1024 * 1024
        if "tree" not in t:
            return ctx.read_artifact(t["artifact"], limit)
        return tree_tar(ctx, t["tree"], limit)

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        ident = ctx.manifest.get("identification", {})
        findings: list[Finding] = []
        components: list[dict] = []
        submissions = []
        failed = 0
        with self._client() as c:
            for i, t in enumerate(targets):
                try:
                    data = self._payload(ctx, t)
                except (OSError, ValueError) as exc:  # e.g. a link or special file planted in the work directory
                    failed += 1
                    submissions.append({"target": t["label"], "status": "failed", "error": f"not submitted: {exc}"})
                    continue
                payload = {
                    "binary": base64.b64encode(data).decode(),
                    "file_name": t["file_name"][:200],
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
                    ctx.write_file(out_dir / f"firmware_{i}.json", json.dumps(fw, indent=1)[:50_000_000])
                    meta = fw.get("meta_data", {}) or {}
                    creds = self._credential_details(c, fw)
                    requested = set(self.settings.fact_plugins)
                    fs = normalize(fw, ctx.original_name if i == 0 else f"{ctx.original_name} > {t['file_name']}",
                                   creds, requested=requested,
                                   paths={**self._object_paths(c, fw, "crypto_material"),
                                          **self._object_paths(c, fw, "exploit_mitigations", MITIGATION_WEAK)})
                    findings += fs
                    components += fact_components(fw, t["label"])
                    analysis = fw.get("analysis", {}) or {}
                    entry.update({
                        # number_of_included_files counts direct children only (1 for a .tar.gz)
                        "files_analysed": int(meta.get("total_files_in_firmware") or 0)
                        or 1 + int(meta.get("number_of_included_files") or 0),
                        # FACT keeps results of earlier analyses of identical files (UIDs are content hashes);
                        # plug-ins not requested in this run are not reported
                        "not_requested": sorted(p for p, r in analysis.items() if p in PLUGIN_MAP and p not in requested
                                                and isinstance(r, dict) and r.get("summary")),
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
            if s.get("not_requested"):
                text += (f"; stored results of plug-ins not requested in this run were ignored "
                         f"({', '.join(s['not_requested'])})")
            return text

        msg = "; ".join(f"{s['target']}: {describe(s)}" for s in submissions)
        return AdapterResult("completed" if ok else ("timeout" if any(s["status"] == "timeout" for s in submissions)
                                                     else "failed"),
                             msg, findings, str(out_dir), {"submissions": submissions, "fact_url": self.settings.fact_url,
                                                           "components": components})

    @staticmethod
    def _object_paths(c: httpx.Client, fw: dict, plugin: str, labels=None, per_label: int = 10,
                      limit: int = 60) -> dict[str, str]:
        """uid -> path inside the firmware for the files a plug-in summary points to (best effort; only the
        summary labels that become findings when ``labels`` is given)."""
        summary = (((fw or {}).get("analysis") or {}).get(plugin) or {}).get("summary") or {}
        uids: list[str] = []
        if isinstance(summary, dict):
            for label, us in summary.items():
                if labels is None or label in labels:
                    uids += [u for u in list(us)[:per_label] if u not in uids]
        out: dict[str, str] = {}
        for uid in uids[:limit]:
            try:
                r = c.get(f"/rest/file_object/{uid}")
                hid = ((r.json().get("file_object") or {}).get("meta_data") or {}).get("hid") if r.status_code == 200 \
                    else None
            except (httpx.HTTPError, ValueError):
                break
            if isinstance(hid, str):
                out[uid] = hid[:512]
        return out

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


def tree_tar(ctx: AdapterContext, members: list[dict], limit: int) -> bytes:
    """A tar of the files extracted from one filesystem, laid out by their path inside it.

    Names and modes come from the (untrusted) manifest: names are reduced to safe relative paths and
    file contents are read through the work-directory checks (regular files only, size limited)."""
    buf = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for a in members:
            parts = [p for p in str(a.get("name", "")).split("/") if p not in ("", ".")]
            if not parts or ".." in parts or len("/".join(parts)) > 1024:
                continue
            data = ctx.read_artifact(a, max(0, limit - total))
            total += len(data)
            ti = tarfile.TarInfo("/".join(parts))
            ti.size, ti.mtime, ti.uid, ti.gid = len(data), 0, 0, 0
            mode = a.get("mode")
            ti.mode = (mode & 0o777) if isinstance(mode, int) else 0o644
            tar.addfile(ti, io.BytesIO(data))
    if buf.tell() > limit:
        raise ValueError(f"archive of extracted files exceeds DFA_FACT_MAX_UPLOAD_MB ({limit // (1024 * 1024)} MiB)")
    return buf.getvalue()


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


def normalize(fw: dict, name: str, credentials: list[dict] | None = None, requested: set[str] | None = None,
              paths: dict[str, str] | None = None) -> list[Finding]:
    """``requested``: plug-ins requested in this run (others may carry stored results of an earlier analysis of
    identical files and are skipped); ``paths``: uid -> path inside the firmware, where known."""
    out: list[Finding] = []
    paths = paths or {}
    analysis = (fw or {}).get("analysis", {}) or {}
    for plugin, result in analysis.items():
        if plugin not in PLUGIN_MAP or not isinstance(result, dict):
            continue
        if requested is not None and plugin not in requested:
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
            s, c, why, rule, title_prefix = sev, cls, "", f"fact-{plugin}", prefix
            locs = [paths.get(u) for u in list(uids)[:25]]
            if plugin == "exploit_mitigations":
                if label_s not in MITIGATION_WEAK:
                    continue
                s, why = MITIGATION_WEAK[label_s]
            elif plugin == "crypto_material" and "private" not in label_s.lower():
                s, c = S.info, C.info  # certificates and public keys are not secrets
                why = "public key material or a certificate (not a secret)"
            elif plugin == "crypto_material" and locs and all(p and CRYPTO_LIBRARY.search(p) for p in locs):
                # verified on Debian 11: FACT reports GnuTLS's built-in self-test keys in libgnutls.so as
                # SSLPrivateKey/SshRsaPrivateKeyBlock; such keys are public test vectors, not device secrets
                s, c, rule = S.info, C.info, "fact-crypto-library-key"
                title_prefix = "Key material inside a cryptographic library"
                why = ("found only inside cryptographic libraries, which ship public known-answer/self-test keys; "
                       "not a device secret")
            elif plugin == "cve_lookup":
                low = label_s.lower()
                s = S.high if "critical" in low or "high" in low else S.medium
            out.append(Finding(
                title=f"[FACT] {title_prefix}: {label_s[:160]}",
                description=(f"FACT plugin '{plugin}' reported '{label_s}'" + (f": {why}." if why else ". ")
                             + ("Version/signature based result - requires manual verification."
                                if c == C.unverified else "Reported by FACT's analysis of the firmware contents.")),
                severity=s, classification=c, confidence=K.medium, source_tool="fact", rule_id=rule,
                affected_component=name if not uids else f"{name} ({len(uids)} FACT object(s))",
                remediation=("No action required." if rule == "fact-crypto-library-key"
                             else "Review the corresponding FACT analysis page for affected files."),
                evidence=[Evidence("tool_output", label_s[:240],
                                   f"{paths[u]} (FACT uid {u})" if u in paths else f"FACT uid {u}")
                          for u in list(uids)[:10]] or [Evidence("tool_output", label_s[:240])],
                cwe=None if rule == "fact-crypto-library-key" else cwe, tags=["fact", plugin]))
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
