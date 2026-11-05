"""Vulnerability matching stage (runs on the worker against the offline OSV database)."""
from __future__ import annotations

from collections import defaultdict

from .core.findings import Classification as C
from .core.findings import Confidence as K
from .core.findings import Evidence, Finding
from .core.findings import Severity as S
from .vulndb import UPSTREAM, VulnDB, VulnMatch

# string-identified component -> distribution source package names that ship it
DISTRO_SOURCE = {"glibc": ("glibc", "eglibc"), "openssl": ("openssl", "openssl1.1"), "zlib": ("zlib",),
                 "busybox": ("busybox",), "openssh": ("openssh",), "dropbear": ("dropbear",),
                 "dnsmasq": ("dnsmasq",), "sqlite": ("sqlite3",), "libcurl": ("curl",), "curl": ("curl",),
                 "mbedtls": ("mbedtls",), "hostapd": ("wpa", "hostapd"), "wpa_supplicant": ("wpa",),
                 "lighttpd": ("lighttpd",), "u-boot": ("u-boot",), "uclibc": ("uclibc", "uclibc-ng"),
                 "libpcap": ("libpcap",), "freertos": ("freertos",), "zephyr": ("zephyr",)}

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 2}


def _sort(ms: list[VulnMatch]) -> list[VulnMatch]:
    return sorted(ms, key=lambda m: (SEV_RANK.get(m.severity, 2), -(m.score or 0), m.id))


def _max_sev(ms: list[VulnMatch]) -> S:
    best = min((SEV_RANK.get(m.severity, 2) for m in ms), default=2)
    return S(["critical", "high", "medium", "low", "info"][best])


def _vuln_entry(m: VulnMatch) -> dict:
    return {"id": m.id, "severity": m.severity, "score": m.score, "fixed": m.fixed,
            "aliases": m.aliases[:5], "source": m.source}


def match(manifest: dict, db: VulnDB, where: str) -> tuple[list[Finding], dict]:
    """Returns (findings, stats). Annotates manifest components/packages with their vulnerabilities."""
    findings: list[Finding] = []
    stats = {"packages_checked": 0, "components_checked": 0, "affected": 0, "vulnerabilities": 0,
             "dataset": db.meta(), "unmatched_managers": []}
    inv = manifest.get("packages") or {}
    distro = inv.get("distro")
    by_source: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for p in inv.get("packages", []):
        eco = db.distro_ecosystem(distro, p["manager"])
        if eco is None:
            if p["manager"] not in stats["unmatched_managers"]:
                stats["unmatched_managers"].append(p["manager"])
            continue
        by_source[(eco, p.get("source") or p["name"], p.get("source_version") or p["version"])].append(p)
    for (eco, src, ver), pkgs in sorted(by_source.items()):
        stats["packages_checked"] += len(pkgs)
        ms = _sort(db.match_package(pkgs[0], eco))
        for p in pkgs:
            p["vulnerabilities"] = [_vuln_entry(m) for m in ms[:200]]
        if not ms:
            continue
        stats["affected"] += 1
        stats["vulnerabilities"] += len(ms)
        fixed = sorted({m.fixed for m in ms if m.fixed}, key=lambda v: v)
        names = ", ".join(sorted({p["name"] for p in pkgs})[:6])
        findings.append(Finding(
            title=f"{src} {ver}: {len(ms)} known vulnerabilit{'y' if len(ms) == 1 else 'ies'} ({eco})",
            description=(f"The installed {eco} source package '{src}' version {ver} (binary packages: {names}) is "
                         f"listed as affected by {len(ms)} vulnerabilities in the distribution's security data "
                         "(via OSV). The distribution's fixed versions are compared with the exact installed "
                         "version, so backported fixes are taken into account. Exploitability in this firmware's "
                         "configuration was not verified."),
            severity=_max_sev(ms), classification=C.detected, confidence=K.high, source_tool="osv",
            rule_id="osv-distro-package", affected_component=f"{where} > {pkgs[0].get('database', '')}",
            remediation=(f"Update '{src}' to a fixed version (at least {fixed[-1]})." if fixed
                         else f"No fixed version is published for some of these issues; review mitigations for '{src}'."),
            evidence=[Evidence("string", f"{m.id} [{m.severity or 'n/a'}{f' {m.score}' if m.score else ''}]"
                                         f"{f' fixed in {m.fixed}' if m.fixed else ' (no fix)'}: {m.summary[:120]}",
                               ", ".join(m.aliases[:3]) or None) for m in ms[:40]],
            references=[m.id for m in ms[:50]], cwe="CWE-1395",
            tags=["vulnerable-dependency", "osv", eco]))
    distro_sources = {p.get("source") or p["name"] for p in inv.get("packages", [])
                      if db.distro_ecosystem(distro, p["manager"])}
    stats["superseded"] = []
    for comp in manifest.get("components", []):
        name, ver = comp.get("name"), comp.get("version")
        if name not in UPSTREAM or not ver:
            continue
        if any(src in distro_sources for src in DISTRO_SOURCE.get(name, (name,))):
            # the distribution's package data (backport-aware) already covers this component
            comp["vulnerabilities_note"] = "covered by distribution package data"
            stats["superseded"].append(f"{name} {ver}")
            continue
        stats["components_checked"] += 1
        ms = _sort(db.match_upstream(name, ver, comp.get("variant")))
        comp["vulnerabilities"] = [_vuln_entry(m) for m in ms[:200]]
        if not ms:
            continue
        stats["affected"] += 1
        stats["vulnerabilities"] += len(ms)
        findings.append(Finding(
            title=f"{name} {ver}: {len(ms)} known vulnerabilit{'y' if len(ms) == 1 else 'ies'} (upstream release)",
            description=(f"Version {ver} of {name} was identified from {comp.get('method', 'version strings')} and "
                         f"matches {len(ms)} vulnerabilities in OSV's upstream (GIT) data, by the affected release "
                         "tags or by the affected-version range published with the CVE. This is a version-based "
                         "match: vendor backports and whether the affected code is built in cannot be seen, so "
                         "each entry needs manual confirmation."),
            severity=_max_sev(ms), classification=C.unverified, confidence=K.medium, source_tool="osv",
            rule_id=f"osv-upstream-{name}", affected_component=f"{name} {ver}",
            remediation=f"Upgrade {name} to a release that fixes these issues, or confirm vendor backports.",
            evidence=[Evidence("string", f"{m.id} [{m.severity or 'n/a'}{f' {m.score}' if m.score else ''}]: "
                                         f"{m.summary[:120]}" + (f" ({m.source.removeprefix('OSV GIT (')[:-1]})"
                                                                  if "range" in m.source else ""),
                               ", ".join(m.aliases[:3]) or None) for m in ms[:40]],
            references=[m.id for m in ms[:50]], cwe="CWE-1395",
            tags=["vulnerable-dependency", "osv", "version-match"]))
    return findings, stats
