"""Build the local CVE database from public feeds.

Sources (all public, no API key):

* NVD JSON 2.0 via the fkie-cad mirror (``CVE-all.json.xz``, ~113 MB, updated daily)
* CISA Known Exploited Vulnerabilities catalog
* Exploit-DB ``files_exploits.csv`` (CVE ids in the ``codes`` column)

The NVD feed decompresses to several GB, so it is streamed item by item with
the standard library. The database is written to ``<db>.tmp`` and moved into
place only when complete: a failed update never damages the previous database.
"""
from __future__ import annotations

import csv
import json
import lzma
import os
import re
import shutil
import sqlite3
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from . import SCHEMA_VERSION

NVD_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
SOURCES = {"nvd": NVD_URL, "kev": KEV_URL, "exploitdb": EXPLOITDB_URL}

CHUNK = 1 << 20
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SKIP = re.compile(r"[\s,]*")
_CPE_SPLIT = re.compile(r"(?<!\\):")
_GIT_HASH = re.compile(r"^[0-9a-f]{12,40}$")
CVSS_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")
EMPTY = ("", "*", "-")

Log = Callable[[str], None]

SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE cve(id TEXT PRIMARY KEY, published TEXT, summary TEXT, score REAL, severity TEXT,
                 cvss_version TEXT, vector TEXT, cwe TEXT);
CREATE TABLE cpe_match(cve_id TEXT, part TEXT, vendor TEXT, product TEXT, version TEXT,
                       start_incl TEXT, start_excl TEXT, end_incl TEXT, end_excl TEXT);
CREATE TABLE cna_affected(cve_id TEXT, vendor TEXT, product TEXT, default_status TEXT, versions TEXT);
CREATE TABLE kev(cve_id TEXT PRIMARY KEY, date_added TEXT, ransomware INTEGER);
CREATE TABLE exploit(cve_id TEXT, edb_id TEXT, title TEXT);
"""
INDEXES = """
CREATE INDEX ix_cpe ON cpe_match(vendor, product);
CREATE INDEX ix_cna ON cna_affected(vendor, product);
CREATE INDEX ix_exploit ON exploit(cve_id);
"""


class BuildError(Exception):
    """A feed could not be downloaded or parsed; the existing database is untouched."""


# --------------------------------------------------------------------------- NVD feed
def iter_cve_items(path: Path, header: dict | None = None) -> Iterator[dict]:
    """Yield the objects of the feed's top-level ``cve_items`` array one at a time.

    Memory stays bounded by the largest single item (plus one read chunk), not
    the multi-GB decompressed feed. ``header`` (if given) receives the feed's
    ``timestamp`` and ``cve_count``.
    """
    dec = json.JSONDecoder()
    opener = lzma.open if path.suffix == ".xz" else open
    with opener(path, "rt", encoding="utf-8") as fp:
        buf = ""
        while True:
            i = buf.find('"cve_items"')
            j = buf.find("[", i) if i >= 0 else -1
            if j >= 0:
                break
            chunk = fp.read(CHUNK)
            if not chunk:
                raise BuildError("NVD feed: 'cve_items' array not found")
            buf += chunk
        if header is not None:
            for key in ("timestamp", "cve_count"):
                m = re.search(rf'"{key}"\s*:\s*"?([^",\n]+)"?', buf[:i])
                if m:
                    header[key] = m.group(1)
        buf, pos, eof = buf[j + 1:], 0, False
        while True:
            pos = _SKIP.match(buf, pos).end()
            if pos >= len(buf):
                if eof:
                    raise BuildError("NVD feed is truncated (unterminated cve_items array)")
                chunk = fp.read(CHUNK)
                eof = not chunk
                buf, pos = buf[pos:] + chunk, 0
                continue
            if buf[pos] == "]":
                return
            try:
                obj, end = dec.raw_decode(buf, pos)
            except json.JSONDecodeError:
                if eof:
                    raise BuildError("NVD feed is truncated or malformed") from None
                chunk = fp.read(CHUNK)
                eof = not chunk
                buf, pos = buf[pos:] + chunk, 0
                continue
            yield obj
            pos = end
            if pos > CHUNK:
                buf, pos = buf[pos:], 0


def pick_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """(score, version, vector): CVSS 3.1 > 3.0 > 4.0 > 2.0, NVD 'Primary' before 'Secondary'."""
    for key in CVSS_KEYS:
        entries = metrics.get(key) or []
        for want in ("Primary", "Secondary", None):
            for m in entries:
                if want is None or m.get("type") == want:
                    data = m.get("cvssData") or {}
                    score = data.get("baseScore")
                    if isinstance(score, (int, float)):
                        return float(score), str(data.get("version") or key[-2:]), data.get("vectorString")
    return None, None, None


def severity_for(score: float | None) -> str:
    if score is None:
        return "medium"  # unscored: don't downplay it
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def parse_cpe(criteria: str) -> tuple[str, str, str, str] | None:
    """cpe:2.3:part:vendor:product:version:update:... -> (part, vendor, product, version+update)."""
    f = _CPE_SPLIT.split(criteria)
    if len(f) < 7 or f[0] != "cpe" or f[1] != "2.3":
        return None
    part, vendor, product, version, update = f[2], f[3], f[4], f[5], f[6]
    unesc = lambda s: s.replace("\\", "")  # noqa: E731
    version = unesc(version)
    if version not in EMPTY and update not in EMPTY:
        version += unesc(update)  # openssh 7.4:p1 -> 7.4p1, ntp 4.2.8:p15 -> 4.2.8p15
    return part, unesc(vendor).lower(), unesc(product).lower(), version


def parse_item(item: dict) -> tuple[tuple, list[tuple], list[tuple]] | None:
    """One NVD item -> (cve row, cpe_match rows, cna_affected rows); None if rejected/invalid."""
    cid = item.get("id", "")
    if not CVE_RE.match(cid) or item.get("vulnStatus") == "Rejected":
        return None
    summary = next((d.get("value", "") for d in item.get("descriptions") or [] if d.get("lang") == "en"), "")
    summary = " ".join(summary.split())
    if len(summary) > 300:
        summary = summary[:297].rstrip() + "..."
    score, cvss_version, vector = pick_cvss(item.get("metrics") or {})
    cwe = None
    for w in sorted(item.get("weaknesses") or [], key=lambda w: w.get("type") != "Primary"):
        cwe = next((d.get("value") for d in w.get("description") or [] if str(d.get("value", "")).startswith("CWE-")),
                   None)
        if cwe:
            break
    row = (cid, (item.get("published") or "")[:10], summary, score, severity_for(score), cvss_version, vector, cwe)

    cpes: set[tuple] = set()
    configs = item.get("configurations") or []
    for conf in configs:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                parsed = parse_cpe(m.get("criteria", ""))
                if not parsed or parsed[0] not in ("a", "o"):
                    continue
                part, vendor, product, version = parsed
                cpes.add((cid, part, vendor, product, version, m.get("versionStartIncluding"),
                          m.get("versionStartExcluding"), m.get("versionEndIncluding"), m.get("versionEndExcluding")))
    cnas: dict[tuple, tuple] = {}
    if not configs:
        # CNA-published CVE 5 "affected" blocks, only for CVEs NVD has not analysed. Each block is kept
        # whole (defaultStatus + affected/unaffected ranges) because e.g. the Linux kernel CNA publishes
        # "default affected, except these fixed stable ranges".
        for aff in item.get("affected") or []:
            for ad in aff.get("affectedData") or []:
                vendor, product = str(ad.get("vendor", "")).strip().lower(), str(ad.get("product", "")).strip().lower()
                if not vendor or product in ("", "n/a"):
                    continue
                versions = []
                for v in ad.get("versions") or []:
                    ver = str(v.get("version", "")).strip()
                    if (v.get("status") not in ("affected", "unaffected") or v.get("versionType") == "git"
                            or _GIT_HASH.match(ver) or ver in ("", "n/a", "unspecified")):
                        continue
                    e = {"s": v["status"], "v": ver}
                    for src, dst in (("lessThan", "lt"), ("lessThanOrEqual", "le")):
                        if v.get(src):
                            e[dst] = str(v[src]).strip()
                    versions.append(e)
                if not versions:
                    continue  # only git-commit ranges: cannot be evaluated against a version string
                default = str(ad.get("defaultStatus") or "unknown")
                body = json.dumps(versions, separators=(",", ":"), sort_keys=True)
                cnas[(vendor, product, default, body)] = (cid, vendor, product, default, body)
    return row, sorted(cpes, key=str), sorted(cnas.values())


# --------------------------------------------------------------------------- KEV / Exploit-DB
def parse_kev(path: Path) -> tuple[list[tuple], str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = {}
    for v in data.get("vulnerabilities") or []:
        cid = str(v.get("cveID", ""))
        if CVE_RE.match(cid):
            rows[cid] = (cid, str(v.get("dateAdded", ""))[:10],
                         1 if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else 0)
    if not rows:
        raise BuildError("KEV feed contains no vulnerabilities")
    return list(rows.values()), str(data.get("catalogVersion", ""))


def parse_exploitdb(path: Path) -> list[tuple]:
    rows = set()
    with path.open(encoding="utf-8", errors="replace", newline="") as fp:
        reader = csv.DictReader(fp)
        if not reader.fieldnames or "codes" not in reader.fieldnames or "id" not in reader.fieldnames:
            raise BuildError("Exploit-DB CSV is missing the 'id'/'codes' columns")
        for r in reader:
            for code in (r.get("codes") or "").split(";"):
                code = code.strip().upper()
                if CVE_RE.match(code):
                    rows.add((code, str(r["id"]).strip(), (r.get("description") or "")[:200]))
    return sorted(rows)


# --------------------------------------------------------------------------- build
def build_database(db_path: Path, nvd: Path, kev: Path, exploitdb: Path, log: Log = print) -> dict:
    """Build ``db_path`` from local feed files. Atomic: writes ``<db>.tmp`` then renames."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = db_path.with_name(db_path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    t0 = time.monotonic()
    try:
        kev_rows, kev_version = parse_kev(kev)
        edb_rows = parse_exploitdb(exploitdb)
        conn = sqlite3.connect(tmp)
        try:
            conn.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;" + SCHEMA)
            header: dict = {}
            n = skipped = rejected = 0
            cves, cpes, cnas = [], [], []

            def flush() -> None:
                conn.executemany("INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?,?)", cves)
                conn.executemany("INSERT INTO cpe_match VALUES (?,?,?,?,?,?,?,?,?)", cpes)
                conn.executemany("INSERT INTO cna_affected VALUES (?,?,?,?,?)", cnas)
                cves.clear(), cpes.clear(), cnas.clear()

            for item in iter_cve_items(nvd, header):
                try:
                    parsed = parse_item(item)
                except Exception:  # noqa: BLE001 - one malformed record must not stop the build
                    skipped += 1
                    continue
                if parsed is None:
                    rejected += 1
                    continue
                row, c, a = parsed
                cves.append(row)
                cpes.extend(c)
                cnas.extend(a)
                n += 1
                if len(cves) >= 5000:
                    flush()
                if n % 50000 == 0:
                    log(f"  {n:,} CVEs processed")
            flush()
            if n == 0:
                raise BuildError("NVD feed contained no usable CVE records")
            conn.executemany("INSERT INTO kev VALUES (?,?,?)", kev_rows)
            conn.executemany("INSERT INTO exploit VALUES (?,?,?)", edb_rows)
            log("  building indexes")
            conn.executescript(INDEXES)
            meta = {
                "schema_version": str(SCHEMA_VERSION),
                "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "nvd_timestamp": header.get("timestamp", ""),
                "nvd_feed_count": header.get("cve_count", ""),
                "cve_count": str(n), "rejected": str(rejected), "skipped_records": str(skipped),
                "cpe_rows": str(conn.execute("SELECT count(*) FROM cpe_match").fetchone()[0]),
                "cna_rows": str(conn.execute("SELECT count(*) FROM cna_affected").fetchone()[0]),
                "kev_version": kev_version, "kev_count": str(len(kev_rows)), "exploit_rows": str(len(edb_rows)),
            }
            conn.executemany("INSERT INTO meta VALUES (?,?)", meta.items())
            conn.commit()
        finally:
            conn.close()
        os.replace(tmp, db_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    meta["build_seconds"] = f"{time.monotonic() - t0:.0f}"
    return meta


def fetch(src: str | Path, dest: Path, log: Log = print) -> Path:
    """Return a local path for ``src``: a local file is used as is, a URL is downloaded to ``dest``."""
    if isinstance(src, Path) or not str(src).startswith(("http://", "https://")):
        p = Path(src)
        if not p.is_file():
            raise BuildError(f"feed file not found: {p}")
        return p
    import httpx

    log(f"  downloading {src}")
    try:
        with httpx.stream("GET", str(src), follow_redirects=True, timeout=httpx.Timeout(60.0, read=300.0)) as r:
            r.raise_for_status()
            with dest.open("wb") as fp:
                for chunk in r.iter_bytes(CHUNK):
                    fp.write(chunk)
    except httpx.HTTPError as exc:
        raise BuildError(f"download failed for {src}: {type(exc).__name__}: {exc}") from exc
    return dest


def update(db_path: Path, sources: dict[str, str | Path] | None = None, log: Log = print) -> dict:
    """Download the feeds (or use local files given in ``sources``) and rebuild ``db_path``."""
    src = {**SOURCES, **(sources or {})}
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cve-feeds-", dir=db_path.parent))
    try:
        nvd = fetch(src["nvd"], work / "CVE-all.json.xz", log)
        kev = fetch(src["kev"], work / "kev.json", log)
        edb = fetch(src["exploitdb"], work / "files_exploits.csv", log)
        log("  parsing feeds and building the database (usually under a minute)")
        return build_database(db_path, nvd, kev, edb, log)
    finally:
        shutil.rmtree(work, ignore_errors=True)
