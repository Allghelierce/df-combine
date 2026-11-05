"""Offline vulnerability database built from OSV.dev data dumps.

Sources (https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip, refreshed daily):
* ``Debian`` / ``Alpine`` - distribution security trackers. Records are keyed by *source* package
  and release (``Debian:11``, ``Alpine:v3.15``) with the distribution's own fixed versions, so
  matching the installed package version accounts for vendor backports.
* ``GIT`` - CVEs mapped to upstream repositories, many with explicit lists of affected release
  tags. Used for components that were identified from version strings (BusyBox, OpenSSL, NuttX,
  PX4, ...). These matches cannot see backports and are therefore reported as ``unverified``.

Not used for matching: the ``Linux`` (kernel) ecosystem only provides commit-hash ranges, which
cannot be compared with a kernel version string offline.

    python -m dfa.vulndb update --source-dir /path/with/zips   # or --download
    python -m dfa.vulndb info
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_ECOSYSTEMS = ("Debian", "Alpine", "GIT")

# Upstream projects: component name -> (repo URL fragments, tag candidate builder)
def _tags_semver(v: str) -> list[str]:
    return [v, f"v{v}"]


UPSTREAM: dict[str, tuple[tuple[str, ...], object]] = {
    "openssl": (("github.com/openssl/openssl",),
                lambda v: [v, f"OpenSSL_{v.replace('.', '_')}", f"openssl-{v}"]),
    "busybox": (("github.com/mirror/busybox", "git.busybox.net"), lambda v: [v.replace(".", "_"), v]),
    "dropbear": (("github.com/mkj/dropbear",), lambda v: [f"DROPBEAR_{v}", v]),
    "dnsmasq": (("thekelleys.org.uk/dnsmasq", "infrastructureservices/dnsmasq"), lambda v: [f"v{v}", v]),
    "zlib": (("github.com/madler/zlib",), _tags_semver),
    "glibc": (("sourceware.org/git/glibc", "github.com/bminor/glibc"), lambda v: [f"glibc-{v}", v]),
    "sqlite": (("github.com/sqlite/sqlite",), lambda v: [f"version-{v}", v]),
    "openssh": (("github.com/openssh/openssh-portable",),
                lambda v: [v, f"V_{v.upper().replace('.', '_').replace('P', '_P')}"]),
    "u-boot": (("github.com/u-boot/u-boot",), lambda v: [f"v{v}", v]),
    "mbedtls": (("github.com/mbed-tls/mbedtls", "github.com/Mbed-TLS/mbedtls", "ARMmbed/mbedtls"),
                lambda v: [v, f"v{v}", f"mbedtls-{v}"]),
    "hostapd": (("w1.fi/cgit/hostap", "w1.fi/srv/git/hostap"), lambda v: [f"hostap_{v.replace('.', '_')}"]),
    "wpa_supplicant": (("w1.fi/cgit/hostap", "w1.fi/srv/git/hostap"), lambda v: [f"hostap_{v.replace('.', '_')}"]),
    "lighttpd": (("github.com/lighttpd/lighttpd1.4",), lambda v: [f"lighttpd-{v}"]),
    "uclibc": (("github.com/wbx-github/uclibc-ng",), _tags_semver),
    "libcurl": (("github.com/curl/curl",), lambda v: [f"curl-{v.replace('.', '_')}", v]),
    "curl": (("github.com/curl/curl",), lambda v: [f"curl-{v.replace('.', '_')}", v]),
    "libpcap": (("the-tcpdump-group/libpcap",), lambda v: [f"libpcap-{v}"]),
    "nuttx": (("github.com/apache/nuttx", "apache/incubator-nuttx"), lambda v: [f"nuttx-{v}", v]),
    "px4": (("github.com/px4/px4-autopilot", "github.com/PX4/PX4-Autopilot", "github.com/PX4/Firmware"),
            lambda v: [f"v{v}", v]),
    "ardupilot": (("github.com/ardupilot/ardupilot",), lambda v: _ardupilot_tags(v, None)),
    "esp-idf": (("github.com/espressif/esp-idf",), lambda v: [f"v{v}", f"v{_describe_base(v)}"]),
    "freertos": (("github.com/freertos/freertos-kernel",), lambda v: [f"V{v}", f"V{v}-kernel-only", f"v{v}"]),
    "zephyr": (("github.com/zephyrproject-rtos/zephyr",), lambda v: [f"v{v}", f"zephyr-v{v}"]),
}
# ArduPilot tags releases per vehicle ("Copter-4.5.7", "Plane-4.5.7", ...); the detected vehicle selects them.
_AP_VEHICLE_TAGS = {"ArduCopter": ("Copter", "ArduCopter"), "ArduPlane": ("Plane", "ArduPlane"),
                    "ArduRover": ("Rover", "APMrover2", "ArduRover"), "ArduSub": ("Sub", "ArduSub"),
                    "AntennaTracker": ("Tracker", "AntennaTracker"), "Blimp": ("Blimp",), "AP_Periph": ("AP_Periph",)}
VARIANT_TAGS = {"ardupilot": lambda v, variant: _ardupilot_tags(v, variant)}


def _ardupilot_tags(v: str, vehicle: str | None) -> list[str]:
    if vehicle == "AP_Bootloader":
        return []  # the bootloader is not a flight-stack release; vehicle advisories do not apply
    prefixes = _AP_VEHICLE_TAGS.get(vehicle or "") or tuple(p for ps in _AP_VEHICLE_TAGS.values() for p in ps)
    return [f"{p}-{v}" for p in prefixes]


def _describe_base(v: str) -> str:
    """'5.0-beta1-427-g4532e6e0b2-dirty' -> '5.0-beta1' (the release tag a git-describe version builds on)."""
    return re.sub(r"(?:-\d+-g[0-9a-f]{6,})?(?:-dirty?)?$", "", v)
_REPO_FRAGMENTS = {frag.lower(): name for name, (frags, _f) in UPSTREAM.items() for frag in frags}


def _repo_key(repo: str) -> str | None:
    r = repo.lower().rstrip("/").removesuffix(".git")
    for frag, name in _REPO_FRAGMENTS.items():
        if r.endswith(frag) or f"{frag}/" in r:  # whole path components: "apache/nuttx" != "apache/nuttx-apps"
            return name if name not in ("curl",) else "libcurl"
    return None


# ----------------------------------------------------------------------------- version comparison
def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_cmp_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not diff:
                diff = (ord(a[i]) > ord(b[j])) - (ord(a[i]) < ord(b[j]))
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if diff:
            return diff
    return 0


def dpkg_compare(a: str, b: str) -> int:
    """Debian version comparison (epoch:upstream-revision, '~' sorts before everything)."""
    def split(v: str) -> tuple[int, str, str]:
        epoch = 0
        if ":" in v:
            e, v = v.split(":", 1)
            epoch = int(e) if e.isdigit() else 0
        up, _, rev = v.rpartition("-") if "-" in v else (v, "", "0")
        return epoch, up, rev or "0"

    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_cmp_part(ua, ub) or _dpkg_cmp_part(ra, rb)


_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_key(v: str) -> tuple:
    v, _, rev = v.partition("-r")
    m = re.match(r"^([0-9][0-9.]*)([a-z]?)((?:_[a-z]+[0-9]*)*)$", v)
    if not m:
        return ((tuple(int(x) for x in re.findall(r"\d+", v)) or (0,)), 0, (), int(rev or 0))
    nums = tuple(int(x) for x in m.group(1).strip(".").split(".") if x != "")
    letter = ord(m.group(2)) if m.group(2) else 0
    suffixes = tuple((_APK_SUFFIX.get(re.sub(r"\d+", "", s), 0), int(re.sub(r"\D", "", s) or 0))
                     for s in m.group(3).split("_") if s)
    return (nums, letter, suffixes or ((0, 0),), int(rev or 0) if rev.isdigit() else 0)


def apk_compare(a: str, b: str) -> int:
    ka, kb = _apk_key(a), _apk_key(b)
    return (ka > kb) - (ka < kb)


def _in_ranges(version: str, ranges: list[dict], cmp) -> tuple[bool, str | None]:
    """OSV ECOSYSTEM range evaluation. Returns (affected, fixed_version)."""
    for r in ranges:
        if r.get("type") != "ECOSYSTEM":
            continue
        intro, fixed, last = None, None, None
        affected = False
        for ev in r.get("events", []):
            if "introduced" in ev:
                intro = ev["introduced"]
                affected = intro == "0" or cmp(version, intro) >= 0
                fixed = last = None
            elif "fixed" in ev:
                fixed = ev["fixed"]
                if affected and cmp(version, fixed) >= 0:
                    affected = False
            elif "last_affected" in ev:
                last = ev["last_affected"]
                if affected and cmp(version, last) > 0:
                    affected = False
        if affected:
            return True, fixed
    return False, None


# ----------------------------------------------------------------------------- CVSS
_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
      "A": {"H": 0.56, "L": 0.22, "N": 0}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base(vector: str) -> float | None:
    """CVSS v3.x base score from a vector string (None if not a v3 vector)."""
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
    return _roundup(raw)


def score_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


URGENCY = {"unimportant": "info", "not yet assigned": "medium", "low": "low", "low**": "low", "medium": "medium",
           "medium**": "medium", "high": "high", "high**": "high", "end-of-life": "medium"}


# ----------------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS vulns (id TEXT PRIMARY KEY, summary TEXT, aliases TEXT, severity TEXT, score REAL,
                                  published TEXT, modified TEXT, refs TEXT);
CREATE TABLE IF NOT EXISTS distro (vuln_id TEXT, ecosystem TEXT, package TEXT, ranges TEXT, urgency TEXT);
CREATE INDEX IF NOT EXISTS distro_pkg ON distro (ecosystem, package);
CREATE TABLE IF NOT EXISTS upstream (vuln_id TEXT, component TEXT, tag TEXT);
CREATE INDEX IF NOT EXISTS upstream_tag ON upstream (component, tag);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS cvss (cve TEXT PRIMARY KEY, score REAL);
"""


def _severity_of(d: dict) -> tuple[str | None, float | None]:
    best = None
    for s in d.get("severity") or []:
        sc = cvss3_base(str(s.get("score", "")))
        if sc is not None and (best is None or sc > best):
            best = sc
    if best is None:
        aff_sev = None
        for a in d.get("affected") or []:
            sev = ((a.get("database_specific") or {}).get("severity") or "")
            aff_sev = aff_sev or sev
        sev = str((d.get("database_specific") or {}).get("severity") or aff_sev or "").lower()
        if sev in ("critical", "high", "medium", "moderate", "low"):
            return {"moderate": "medium"}.get(sev, sev), None
        return None, None
    return score_to_severity(best), best


def _cve_ids(d: dict) -> set[str]:
    out = set()
    for x in [d.get("id", ""), *(d.get("aliases") or []), *(d.get("upstream") or [])]:
        m = re.search(r"CVE-\d{4}-\d{4,}", str(x))
        if m:
            out.add(m.group(0))
    return out


def import_zip(con: sqlite3.Connection, zpath: Path, ecosystem: str) -> int:
    n = 0
    with zipfile.ZipFile(zpath) as z:
        for name in z.namelist():
            try:
                d = json.loads(z.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            rows_distro, rows_up = [], []
            for a in d.get("affected") or []:
                pkg = a.get("package") or {}
                eco = pkg.get("ecosystem", "")
                if ecosystem in ("Debian", "Alpine", "Ubuntu") and eco.startswith(ecosystem):
                    rows_distro.append((d["id"], eco, pkg.get("name", ""), json.dumps(a.get("ranges") or []),
                                        (a.get("ecosystem_specific") or {}).get("urgency")))
                elif ecosystem == "GIT":
                    for r in a.get("ranges") or []:
                        comp = _repo_key(r.get("repo", "")) if r.get("type") == "GIT" else None
                        if comp:
                            rows_up += [(d["id"], comp, t) for t in (a.get("versions") or [])[:5000]]
                            break
            sev, score = _severity_of(d)
            if score is not None:  # CVSS of every record is kept to score CVEs that other sources leave unrated
                for cve in _cve_ids(d):
                    con.execute("INSERT INTO cvss VALUES (?, ?) ON CONFLICT(cve) DO UPDATE SET "
                                "score = max(score, excluded.score)", (cve, score))
            if not rows_distro and not rows_up:
                continue
            refs = [r.get("url") for r in (d.get("references") or [])[:5] if r.get("url")]
            con.execute("INSERT OR REPLACE INTO vulns VALUES (?,?,?,?,?,?,?,?)",
                        (d["id"], (d.get("summary") or d.get("details") or "")[:300], json.dumps(d.get("aliases") or []),
                         sev, score, d.get("published"), d.get("modified"), json.dumps(refs)))
            con.executemany("INSERT INTO distro VALUES (?,?,?,?,?)", rows_distro)
            con.executemany("INSERT INTO upstream VALUES (?,?,?)", rows_up)
            n += 1
    return n


def update(db_path: Path, source_dir: Path | None, ecosystems: tuple[str, ...] = DEFAULT_ECOSYSTEMS,
           download: bool = False) -> dict:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = db_path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    con = sqlite3.connect(tmp)
    con.executescript(SCHEMA)
    stats = {}
    for eco in ecosystems:
        zpath = (source_dir or db_path.parent) / f"{eco}.zip"
        if download:
            zpath.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(f"{OSV_BASE}/{eco}/all.zip", timeout=1800) as r, zpath.open("wb") as fp:  # noqa: S310
                while chunk := r.read(1 << 20):
                    fp.write(chunk)
        if not zpath.exists():
            raise FileNotFoundError(f"{zpath} not found (use --download or --source-dir)")
        stats[eco] = import_zip(con, zpath, eco)
        con.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                    (f"dataset:{eco}", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(zpath.stat().st_mtime))))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('built', ?)", (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),))
    con.commit()
    con.close()
    tmp.replace(db_path)
    return stats


# ----------------------------------------------------------------------------- matching
@dataclass
class VulnMatch:
    id: str
    severity: str | None
    score: float | None
    summary: str
    aliases: list[str]
    fixed: str | None = None
    source: str = ""
    refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class VulnDB:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)

    def meta(self) -> dict:
        return dict(self.con.execute("SELECT key, value FROM meta").fetchall())

    def _vuln(self, vid: str) -> tuple:
        return self.con.execute("SELECT summary, aliases, severity, score, refs FROM vulns WHERE id=?", (vid,)).fetchone()

    def distro_ecosystem(self, distro: dict | None, manager: str) -> str | None:
        if not distro:
            return None
        did, ver = distro.get("id", ""), distro.get("version_id", "")
        if manager == "dpkg" and did in ("debian", "raspbian") and ver:
            return f"Debian:{ver.split('.')[0]}"
        if manager == "apk" and did == "alpine" and ver:
            return "Alpine:v" + ".".join(ver.split(".")[:2])
        return None

    def match_package(self, pkg: dict, ecosystem: str) -> list[VulnMatch]:
        cmp = dpkg_compare if ecosystem.startswith("Debian") else apk_compare
        out = []
        for vid, ranges, urgency in self.con.execute(
                "SELECT vuln_id, ranges, urgency FROM distro WHERE ecosystem=? AND package=?",
                (ecosystem, pkg.get("source") or pkg["name"])):
            try:
                hit, fixed = _in_ranges(pkg.get("source_version") or pkg["version"], json.loads(ranges), cmp)
            except Exception:  # noqa: BLE001, S112 - malformed version strings on either side
                continue
            if not hit:
                continue
            row = self._vuln(vid)
            if not row:
                continue
            summary, aliases, sev, score, refs = row
            alias_list = json.loads(aliases or "[]")
            if score is None:  # Debian records carry no CVSS; reuse the score published for the same CVE
                score = self._cve_score(vid, alias_list)
                if score is not None:
                    sev = score_to_severity(score)
            if sev is None and urgency:
                sev = URGENCY.get(urgency.lower())
            out.append(VulnMatch(vid, sev, score, summary or "", alias_list, fixed,
                                 f"OSV {ecosystem}", json.loads(refs or "[]")))
        return out

    def _cve_score(self, vid: str, aliases: list[str]) -> float | None:
        for cve in _cve_ids({"id": vid, "aliases": aliases}):
            row = self.con.execute("SELECT score FROM cvss WHERE cve=?", (cve,)).fetchone()
            if row:
                return row[0]
        return None

    def match_upstream(self, component: str, version: str, variant: str | None = None) -> list[VulnMatch]:
        spec = UPSTREAM.get(component)
        if not spec or not version:
            return []
        fn = VARIANT_TAGS.get(component)
        tags = list(dict.fromkeys(fn(version, variant) if fn else spec[1](version)))
        out = []
        placeholders = ",".join("?" * len(tags))  # only '?' placeholders are interpolated
        q = f"SELECT DISTINCT vuln_id FROM upstream WHERE component=? AND tag IN ({placeholders})"  # noqa: S608
        key = "libcurl" if component == "curl" else component
        for (vid,) in self.con.execute(q, (key, *tags)):
            row = self._vuln(vid)
            if row:
                summary, aliases, sev, score, refs = row
                out.append(VulnMatch(vid, sev, score, summary or "", json.loads(aliases or "[]"), None,
                                     "OSV GIT (upstream release tags)", json.loads(refs or "[]")))
        return out


def open_db(settings) -> VulnDB | None:
    p = Path(settings.vulndb_path) if settings.vulndb_path else settings.data_dir / "vulndb.sqlite"
    return VulnDB(p) if p.exists() else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dfa.vulndb")
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("update", help="build the database from OSV dumps")
    u.add_argument("--source-dir", type=Path, help="directory containing <Ecosystem>.zip files")
    u.add_argument("--download", action="store_true", help="download the dumps from osv-vulnerabilities")
    u.add_argument("--ecosystems", default=",".join(DEFAULT_ECOSYSTEMS))
    u.add_argument("--db", type=Path)
    i = sub.add_parser("info")
    i.add_argument("--db", type=Path)
    args = ap.parse_args(argv)
    from .config import get_settings
    s = get_settings()
    db = args.db or (Path(s.vulndb_path) if s.vulndb_path else s.data_dir / "vulndb.sqlite")
    if args.cmd == "update":
        t = time.time()
        stats = update(db, args.source_dir, tuple(e.strip() for e in args.ecosystems.split(",") if e.strip()),
                       args.download)
        print(f"built {db} in {time.time() - t:.0f}s: {stats}")
    else:
        if not db.exists():
            print("no vulnerability database; run: python -m dfa.vulndb update --download")
            return 1
        print(json.dumps(VulnDB(db).meta(), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
