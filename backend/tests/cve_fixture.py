"""Tiny offline CVE feeds (NVD JSON 2.0 / CISA KEV / Exploit-DB CSV) for the CVE database tests.

Records are hand-written in the real feed formats; IDs in the CVE-2099 range are fictitious.
"""
from __future__ import annotations

import csv
import json
import lzma
from datetime import UTC, datetime
from pathlib import Path


def cpe(vendor: str, product: str, version: str = "*", update: str = "*", part: str = "a") -> str:
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"


def match(criteria: str, vulnerable: bool = True, **bounds) -> dict:
    return {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "X", **bounds}


def item(cid: str, desc: str, matches: list[dict] | None = None, metrics: dict | None = None,
         status: str = "Analyzed", affected: list[dict] | None = None, cwe: str | None = None) -> dict:
    d = {"id": cid, "sourceIdentifier": "test", "published": "2020-01-01T00:00:00.000", "vulnStatus": status,
         "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": desc}], "metrics": metrics or {}}
    if matches is not None:
        d["configurations"] = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}]
    if affected is not None:
        d["affected"] = [{"source": "cna", "affectedData": affected}]
    if cwe:
        d["weaknesses"] = [{"source": "nvd", "type": "Primary", "description": [{"lang": "en", "value": cwe}]}]
    return d


def v31(score: float, kind: str = "Primary") -> dict:
    return {"cvssMetricV31": [{"source": "nvd", "type": kind, "cvssData": {"version": "3.1", "baseScore": score,
                                                                          "vectorString": "CVSS:3.1/AV:N"}}]}


KERNEL_BLOCK = {"vendor": "Linux", "product": "Linux", "defaultStatus": "affected", "versions": [
    {"version": "4.10", "status": "affected"},
    {"version": "0", "lessThan": "4.10", "versionType": "semver", "status": "unaffected"},
    {"version": "4.14.99", "lessThanOrEqual": "4.14.*", "versionType": "semver", "status": "unaffected"},
    {"version": "6.0", "lessThanOrEqual": "*", "versionType": "original_commit_for_fix", "status": "unaffected"}]}
KERNEL_GIT_BLOCK = {"vendor": "Linux", "product": "Linux", "defaultStatus": "affected", "versions": [
    {"version": "8370c3d08bd98576d97514eca29970e03767a5d1", "lessThan": "dc7a4bfde507ffe1d8bef49aba1322f1d20c2cb3",
     "versionType": "git", "status": "affected"}]}
BUSYBOX_KB_CVES = ["CVE-2021-42373", "CVE-2021-42374", "CVE-2021-42378", "CVE-2021-42386"]


def items() -> list[dict]:
    heartbleed = [match(cpe("openssl", "openssl", v)) for v in
                  ("1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f")]
    out = [
        item("CVE-2014-0160", "Heartbleed: the TLS heartbeat extension leaks memory.", heartbleed, v31(7.5),
             cwe="CWE-125"),
        item("CVE-2016-2107", "AES-NI padding oracle.",
             [match(cpe("openssl", "openssl"), versionStartIncluding="1.0.1", versionEndExcluding="1.0.1t")],
             {"cvssMetricV30": [{"type": "Secondary", "cvssData": {"version": "3.0", "baseScore": 5.9}}],
              "cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 2.6}}]}),
        item("CVE-2099-0001", "Every OpenSSL version (no bounds).", [match(cpe("openssl", "openssl"))], v31(5.0)),
        item("CVE-2099-0002", "Rejected record.", [match(cpe("openssl", "openssl", "1.0.1e"))], v31(9.0),
             status="Rejected"),
        *[item(cid, f"BusyBox awk/ash memory corruption {cid}.",
               [match(cpe("busybox", "busybox"), versionEndExcluding="1.34.0")], v31(6.6)) for cid in BUSYBOX_KB_CVES],
        item("CVE-2024-58251", "BusyBox netstat escape sequences (CNA data only).", None, {},
             status="Deferred", affected=[{"vendor": "BusyBox", "product": "BusyBox", "defaultStatus": "unknown",
                                           "versions": [{"version": "0", "lessThanOrEqual": "1.37.0",
                                                         "versionType": "semver", "status": "affected"}]}]),
        item("CVE-2099-1000", "Kernel bug known only from kernel CNA data.", None, {}, status="Awaiting Analysis",
             affected=[KERNEL_GIT_BLOCK, KERNEL_BLOCK]),
        item("CVE-2099-1001", "Kernel bug fixed in 4.14.98.",
             [match(cpe("linux", "linux_kernel", part="o"), versionStartIncluding="4.14",
                    versionEndExcluding="4.14.98")], v31(7.8)),
        item("CVE-2099-1002", "Kernel bug fixed after 4.14.98.",
             [match(cpe("linux", "linux_kernel", part="o"), versionStartExcluding="4.14.97",
                    versionEndIncluding="4.14.98")], v31(9.8, "Secondary")),
        item("CVE-2099-2000", "ntpd 4.2.8p15 specific.", [match(cpe("ntp", "ntp", "4.2.8", "p15"))], v31(3.1)),
        item("CVE-2099-3000", "Router hardware issue.",
             [match(cpe("acme", "router", "1.0", part="h")), match(cpe("busybox", "busybox"), vulnerable=False,
                                                                   versionEndExcluding="9.9")], v31(8.0)),
    ]
    return out


def write_feeds(dest: Path, timestamp: str | None = None, nvd_items: list[dict] | None = None,
                truncate: bool = False) -> dict[str, Path]:
    dest.mkdir(parents=True, exist_ok=True)
    data = nvd_items if nvd_items is not None else items()
    feed = {"timestamp": timestamp or datetime.now(UTC).isoformat(timespec="seconds"), "cve_count": len(data),
            "feed_name": "CVE-all", "source": "test", "cve_items": data}
    text = json.dumps(feed, indent=2)
    if truncate:
        text = text[: len(text) // 2]
    nvd = dest / "CVE-all.json.xz"
    nvd.write_bytes(lzma.compress(text.encode()))
    kev = dest / "kev.json"
    kev.write_text(json.dumps({"title": "KEV", "catalogVersion": "2026.11.06", "count": 2, "vulnerabilities": [
        {"cveID": "CVE-2014-0160", "dateAdded": "2022-05-04", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2099-1000", "dateAdded": "2026-10-01", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "not-a-cve", "dateAdded": "2026-10-01"}]}))
    edb = dest / "files_exploits.csv"
    with edb.open("w", newline="") as fp:
        w = csv.writer(fp)
        w.writerow(["id", "file", "description", "date_published", "author", "type", "platform", "port", "date_added",
                    "date_updated", "verified", "codes", "tags", "aliases", "screenshot_url", "application_url",
                    "source_url"])
        w.writerow(["32745", "exploits/multiple/remote/32745.py", "OpenSSL TLS Heartbeat Extension - Memory Disclosure",
                    "2014-04-08", "x", "remote", "multiple", "443", "", "", "1", "CVE-2014-0160;OSVDB-105465", "", "",
                    "", "", ""])
        w.writerow(["39768", "exploits/linux/dos/39768.c", "OpenSSL - Padding Oracle", "2016-05-04", "x", "dos",
                    "linux", "", "", "", "1", "cve-2016-2107", "", "", "", "", ""])
        w.writerow(["99999", "exploits/x.txt", "No CVE here", "2020-01-01", "x", "webapps", "php", "", "", "", "0",
                    "OSVDB-1", "", "", "", "", ""])
    return {"nvd": nvd, "kev": kev, "exploitdb": edb}


def build_db(dest: Path, **kw) -> Path:
    from dfa.cve.build import build_database

    feeds = write_feeds(dest / "feeds", **kw)
    db = dest / "cve.db"
    build_database(db, feeds["nvd"], feeds["kev"], feeds["exploitdb"], log=lambda m: None)
    return db
