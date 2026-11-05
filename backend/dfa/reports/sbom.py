"""CycloneDX 1.5 SBOM export (JSON).

Components come from package-manager databases (exact name/version/purl), from version strings in
binaries and from tools (FACT software_components). Each component records how it was identified
(``dfa:method`` property) so consumers can weigh string-based identification accordingly.
Matched vulnerabilities are included in the ``vulnerabilities`` section with their source.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from .. import __version__
from ..models import Scan

# component name -> (CPE vendor, CPE product[, CPE part]) for components identified from version strings
CPE_MAP: dict[str, tuple[str, ...]] = {
    "openssl": ("openssl", "openssl"), "busybox": ("busybox", "busybox"), "linux": ("linux", "linux_kernel", "o"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"), "dnsmasq": ("thekelleys", "dnsmasq"),
    "openssh": ("openbsd", "openssh"), "zlib": ("zlib", "zlib"), "glibc": ("gnu", "glibc"),
    "uclibc": ("uclibc-ng_project", "uclibc-ng"), "mbedtls": ("arm", "mbed_tls"), "lighttpd": ("lighttpd", "lighttpd"),
    "libcurl": ("haxx", "libcurl"), "hostapd": ("w1.fi", "hostapd"), "wpa_supplicant": ("w1.fi", "wpa_supplicant"),
    "sqlite": ("sqlite", "sqlite"), "u-boot": ("denx", "u-boot"), "nuttx": ("apache", "nuttx", "o"),
    "px4": ("dronecode", "px4_drone_autopilot"), "ardupilot": ("ardupilot", "ardupilot"),
    "freertos": ("amazon", "freertos"), "chibios": ("chibios", "chibios\\/rt"),
    "esp-idf": ("espressif", "esp-idf"), "zephyr": ("zephyrproject", "zephyr", "o"),
}
# component name -> purl for upstream projects identified from version strings / descriptors
PURL_MAP = {"esp-idf": "pkg:github/espressif/esp-idf", "zephyr": "pkg:github/zephyrproject-rtos/zephyr",
            "freertos": "pkg:github/freertos/freertos-kernel", "ardupilot": "pkg:github/ardupilot/ardupilot",
            "px4": "pkg:github/px4/px4-autopilot", "nuttx": "pkg:github/apache/nuttx"}


def _cpe(name: str, version: str) -> str | None:
    vp = CPE_MAP.get(name)
    if not vp or not version:
        return None
    part = vp[2] if len(vp) > 2 else "a"
    return f"cpe:2.3:{part}:{vp[0]}:{vp[1]}:{version}:*:*:*:*:*:*:*"


def _build_properties(ident: dict) -> list[dict]:
    """Board and build of the firmware (from .px4/.apj metadata or Betaflight/INAV build blocks)."""
    build = ident.get("build") if isinstance(ident.get("build"), dict) else {}
    props = [("dfa:board", ident.get("board_name")), ("dfa:board-id", ident.get("board_id")),
             ("dfa:vehicle", ident.get("vehicle_type")), ("dfa:build-revision", build.get("revision")),
             ("dfa:build-date", " ".join(str(x) for x in (build.get("date"), build.get("time")) if x) or None)]
    return [{"name": k, "value": str(v)[:200]} for k, v in props if v not in (None, "")]


def cyclonedx(scan: Scan) -> dict:
    ident = scan.identification or {}
    root_ref = f"firmware:{scan.sha256[:16]}"
    components = []
    vulns: dict[str, dict] = {}

    def add_vulns(ref: str, vs: list[dict]) -> None:
        for v in vs or []:
            entry = vulns.setdefault(v["id"], {
                "bom-ref": f"vuln:{v['id']}", "id": v["id"], "source": {"name": v.get("source", "OSV"),
                                                                        "url": f"https://osv.dev/vulnerability/{v['id']}"},
                "ratings": ([{"score": v["score"], "severity": v.get("severity"), "method": "CVSSv31"}]
                            if v.get("score") else [{"severity": v.get("severity") or "unknown", "method": "other"}]),
                "references": [{"id": a, "source": {"name": "alias"}} for a in v.get("aliases", [])],
                "affects": []})
            entry["affects"].append({"ref": ref})
            if v.get("fixed"):
                entry.setdefault("recommendation", f"Upgrade to {v['fixed']} or later")

    pk = (scan.packages or {}).get("packages", [])
    for p in pk:
        ref = p.get("purl") or f"pkg:{p['manager']}:{p['name']}@{p['version']}"
        components.append({
            "type": "library" if p["manager"] != "dpkg" or not p["name"].startswith("linux-image") else "operating-system",
            "bom-ref": ref, "name": p["name"], "version": p["version"], "purl": p.get("purl"),
            "properties": [{"name": "dfa:method", "value": f"package-db:{p['manager']}"},
                           {"name": "dfa:source-package", "value": f"{p.get('source')} {p.get('source_version')}"},
                           {"name": "dfa:database", "value": p.get("database", "")}]})
        add_vulns(ref, p.get("vulnerabilities", []))
    for c in scan.components or []:
        ref = f"component:{c['name']}@{c.get('version', '')}"
        framework = c["name"] in ("px4", "ardupilot", "nuttx", "chibios", "freertos", "esp-idf", "zephyr")
        entry = {"type": "framework" if framework else "library",
                 "bom-ref": ref, "name": c["name"], "version": c.get("version") or "",
                 "properties": [{"name": "dfa:method", "value": c.get("method", "string-match")}] +
                               [{"name": "dfa:found-in", "value": s} for s in c.get("sources", [])[:5]]}
        if c.get("variant"):
            entry["properties"].append({"name": "dfa:variant", "value": c["variant"]})
        cpe = _cpe(c["name"], c.get("version", ""))
        if cpe:
            entry["cpe"] = cpe
        if c["name"] in PURL_MAP and c.get("version"):
            entry["purl"] = f"{PURL_MAP[c['name']]}@{c['version']}"
        components.append(entry)
        add_vulns(ref, c.get("vulnerabilities", []))
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "Drone Firmware Analyzer", "version": __version__}]},
            "component": {"type": "firmware", "bom-ref": root_ref, "name": scan.original_filename,
                          "version": str(ident.get("platform_version") or "unknown"),
                          "hashes": [{"alg": "SHA-256", "content": scan.sha256}],
                          "properties": [{"name": "dfa:platform", "value": str(ident.get("platform"))},
                                         {"name": "dfa:architecture", "value": str(ident.get("architecture"))},
                                         {"name": "dfa:scan-id", "value": scan.id}] + _build_properties(ident)},
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": [c["bom-ref"] for c in components]}],
        "vulnerabilities": list(vulns.values()),
    }
