"""Local CVE database: build, matching, findings, adapter and report integration (all offline)."""
import sqlite3
from types import SimpleNamespace

import pytest
from cve_fixture import build_db, write_feeds

from dfa.adapters.base import AdapterContext
from dfa.adapters.cve_lookup import CveLookupAdapter
from dfa.core.findings import Finding, dedupe
from dfa.cve import build
from dfa.cve.match import (
    build_findings,
    cna_affects,
    component_inputs,
    lookup,
    nvd_match,
    supersede_kb,
)
from dfa.cve.store import CveDbError, CveStore


@pytest.fixture()
def db(tmp_path):
    return build_db(tmp_path)


def ids(details, name):
    comp = next(c for c in details["components"] if c["name"] == name)
    return {c["id"] for c in comp["cves"]}


def comps(*pairs):
    return [{"name": n, "version": v, "method": "string-match"} for n, v in pairs]


# --------------------------------------------------------------------------- build / store
def test_build_tables_and_meta(db):
    conn = sqlite3.connect(db)
    q = lambda sql: conn.execute(sql).fetchall()  # noqa: E731
    cves = {r[0] for r in q("SELECT id FROM cve")}
    assert "CVE-2099-0002" not in cves  # rejected
    assert {"CVE-2014-0160", "CVE-2024-58251", "CVE-2099-1000"} <= cves
    # CNA rows only for CVEs without NVD configurations; git-only kernel block dropped.
    assert {r[0] for r in q("SELECT cve_id FROM cna_affected")} == {"CVE-2024-58251", "CVE-2099-1000"}
    assert q("SELECT count(*) FROM cna_affected WHERE cve_id='CVE-2099-1000'")[0][0] == 1
    # Hardware and non-vulnerable CPE entries are not stored.
    assert q("SELECT count(*) FROM cpe_match WHERE cve_id='CVE-2099-3000'")[0][0] == 0
    # ntp 4.2.8:p15 -> version '4.2.8p15'
    assert q("SELECT version FROM cpe_match WHERE cve_id='CVE-2099-2000'") == [("4.2.8p15",)]
    # CVSS preference: 3.0 Secondary beats 2.0 Primary; unscored -> medium.
    assert q("SELECT score, cvss_version, severity FROM cve WHERE id='CVE-2016-2107'") == [(5.9, "3.0", "medium")]
    assert q("SELECT score, severity FROM cve WHERE id='CVE-2024-58251'") == [(None, "medium")]
    assert q("SELECT summary, cwe FROM cve WHERE id='CVE-2014-0160'")[0] == (
        "Heartbleed: the TLS heartbeat extension leaks memory.", "CWE-125")
    assert q("SELECT ransomware FROM kev WHERE cve_id='CVE-2099-1000'") == [(1,)]
    assert {r[0] for r in q("SELECT cve_id FROM exploit")} == {"CVE-2014-0160", "CVE-2016-2107"}
    with CveStore(db) as st:
        meta = st.meta()
    assert meta["schema_version"] == "1" and meta["rejected"] == "1" and meta["kev_count"] == "2"
    assert int(meta["cve_count"]) == len(cves)


def test_iter_streams_across_small_chunks(tmp_path, monkeypatch):
    feeds = write_feeds(tmp_path)
    expected = [i["id"] for i in build.iter_cve_items(feeds["nvd"])]
    monkeypatch.setattr(build, "CHUNK", 37)  # every item spans many reads
    header = {}
    assert [i["id"] for i in build.iter_cve_items(feeds["nvd"], header)] == expected
    assert header["cve_count"] == str(len(expected))


def test_failed_build_keeps_previous_database(tmp_path):
    db = build_db(tmp_path / "good")
    before = db.read_bytes()
    bad = write_feeds(tmp_path / "bad", truncate=True)
    with pytest.raises(build.BuildError):
        build.update(db, sources=bad, log=lambda m: None)
    assert db.read_bytes() == before
    assert not db.with_name("cve.db.tmp").exists()
    with pytest.raises(build.BuildError, match="not found"):
        build.update(db, sources={**bad, "kev": tmp_path / "missing.json"}, log=lambda m: None)


def test_store_rejects_wrong_schema(tmp_path):
    p = tmp_path / "old.db"
    conn = sqlite3.connect(p)
    conn.executescript("CREATE TABLE meta(key TEXT, value TEXT); INSERT INTO meta VALUES ('schema_version', '0');")
    conn.commit()
    conn.close()
    with pytest.raises(CveDbError, match="schema"):
        CveStore(p)
    (tmp_path / "junk.db").write_bytes(b"not sqlite at all" * 100)
    with pytest.raises(CveDbError):
        CveStore(tmp_path / "junk.db")


def test_parse_cpe():
    assert build.parse_cpe("cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*") == ("a", "openbsd", "openssh", "7.4p1")
    assert build.parse_cpe("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*")[3] == "*"
    assert build.parse_cpe(r"cpe:2.3:a:x:a\:b:1.0:-:*:*:*:*:*:*")[2] == "a:b"
    assert build.parse_cpe("garbage") is None


# --------------------------------------------------------------------------- matching
def row(version="*", si=None, se=None, ei=None, ee=None):
    return {"version": version, "start_incl": si, "start_excl": se, "end_incl": ei, "end_excl": ee}


@pytest.mark.parametrize("version,r,expected", [
    ("1.0.1e", row("1.0.1e"), True),
    ("1.0.1e", row("1.0.1f"), False),
    ("1.0.1e", row(si="1.0.1", ee="1.0.1t"), True),
    ("1.0.1t", row(si="1.0.1", ee="1.0.1t"), False),
    ("1.0.1g", row(ei="1.0.1f"), False),
    ("1.0.1f", row(ei="1.0.1f"), True),
    ("4.14.97", row(se="4.14.97", ei="4.14.98"), False),
    ("4.14.98", row(se="4.14.97", ei="4.14.98"), True),
    ("1.0.1e", row("*"), False),  # no bounds: too broad
    ("1.0.1e", row("-"), False),
    ("4.2.8p15", row("4.2.8p15"), True),
    ("4.2.8p14", row("4.2.8p15"), False),
])
def test_nvd_match(version, r, expected):
    assert nvd_match(version, r) is expected


@pytest.mark.parametrize("version,expected", [
    ("4.14.98", True),   # default affected, no fix in 4.14 yet
    ("4.14.99", False),  # stable fix 4.14.99 .. 4.14.*
    ("4.14.200", False),
    ("4.9.1", False),    # before the bug was introduced
    ("4.10", True),
    ("5.4.1", True),
    ("6.1", False),      # fixed in 6.0 onwards
])
def test_cna_kernel_semantics(version, expected):
    from cve_fixture import KERNEL_BLOCK
    entries = [{"s": v["status"], "v": v["version"], **({"lt": v["lessThan"]} if "lessThan" in v else {}),
                **({"le": v["lessThanOrEqual"]} if "lessThanOrEqual" in v else {})} for v in KERNEL_BLOCK["versions"]]
    assert cna_affects(version, "affected", entries) is expected


def test_cna_default_unknown_needs_explicit_affected():
    assert cna_affects("1.37.0", "unknown", [{"s": "affected", "v": "0", "le": "1.37.0"}])
    assert not cna_affects("1.38.0", "unknown", [{"s": "affected", "v": "0", "le": "1.37.0"}])


def test_lookup(db):
    with CveStore(db) as st:
        d = lookup(st, comps(("openssl", "1.0.1e"), ("openssl", "1.0.1g"), ("busybox", "1.31.1"),
                             ("linux", "4.14.98"), ("ntp", "4.2.8p15"), ("chibios", "20.3.4")))
    by = {(c["name"], c["version"]): c for c in d["components"]}
    assert {c["id"] for c in by[("openssl", "1.0.1e")]["cves"]} == {"CVE-2014-0160", "CVE-2016-2107"}
    assert {c["id"] for c in by[("openssl", "1.0.1g")]["cves"]} == {"CVE-2016-2107"}
    bb = {c["id"]: c for c in by[("busybox", "1.31.1")]["cves"]}
    assert set(bb) == {*["CVE-2021-42373", "CVE-2021-42374", "CVE-2021-42378", "CVE-2021-42386"], "CVE-2024-58251"}
    assert bb["CVE-2024-58251"]["match"] == "cna" and bb["CVE-2024-58251"]["score"] is None
    assert {c["id"]: c["match"] for c in by[("linux", "4.14.98")]["cves"]} == {"CVE-2099-1000": "cna",
                                                                           "CVE-2099-1002": "nvd"}
    assert ids(d, "ntp") == {"CVE-2099-2000"}
    assert by[("chibios", "20.3.4")]["mapped"] is False and by[("chibios", "20.3.4")]["cves"] == []
    first = by[("openssl", "1.0.1e")]["cves"][0]  # KEV first
    assert first["id"] == "CVE-2014-0160" and first["kev"] and first["exploits"] == ["32745"]
    assert first["kev_added"] == "2022-05-04" and first["cwe"] == "CWE-125"
    kernel = next(c for c in by[("linux", "4.14.98")]["cves"] if c["id"] == "CVE-2099-1000")
    assert kernel["ransomware"] is True
    t = d["totals"]
    assert t["components"] == 6 and t["cves"] == 10  # CVE-2016-2107 counted once across both OpenSSL versions
    assert t["known_exploited"] == 2 and t["public_exploit"] == 2 and t["critical"] == 1


def test_component_inputs_bounds_untrusted_manifest():
    man = {"components": [{"name": "OpenSSL", "version": "1.0.1e"}, {"name": "openssl", "version": "1.0.1e"},
                          {"name": "bad name;", "version": "1"}, {"name": "busybox", "version": "x' OR 1=1"},
                          {"name": "zlib", "version": "1" * 200}, "not-a-dict"],
           "identification": {"platform": "PX4", "platform_version": "v1.14.0"}}
    assert component_inputs(man) == [
        {"name": "openssl", "version": "1.0.1e", "method": "string-match"},
        {"name": "px4", "version": "1.14.0", "method": "platform-identification"}]
    assert component_inputs({"identification": {"platform": "Unknown", "platform_version": "1.0"}}) == []


# --------------------------------------------------------------------------- findings
def cve(i, sev="medium", score=5.0, kev=False, exploits=(), match="nvd"):
    return {"id": f"CVE-2099-{i:04d}", "score": score, "severity": sev, "cvss_version": "3.1", "kev": kev,
            "kev_added": "2026-01-01" if kev else None, "ransomware": False, "exploits": list(exploits),
            "summary": f"bug {i}", "published": "2020-01-01", "cwe": None, "match": match}


def test_build_findings_groups_and_caps():
    many = [cve(1, "medium", 6.5, kev=True), cve(2, "high", 8.0, exploits=["1"])] + \
           [cve(i, "low", 2.0) for i in range(3, 13)]
    details = {"db": {"nvd_timestamp": "2026-11-06T01:00:00+00:00"},
               "components": [{"name": "busybox", "version": "1.31.1", "cves": many},
                              {"name": "zlib", "version": "1.3", "cves": []}]}
    fs = build_findings(details)
    summary = fs[0]
    assert summary.title == "busybox 1.31.1: 12 known CVEs (1 high, 1 medium, 10 low)"
    assert summary.severity.value == "high" and summary.classification.value == "unverified"
    assert summary.rule_id == "cve-component-busybox" and summary.source_tool == "cve_lookup"
    assert len(summary.evidence) == 11 and summary.evidence[-1].value.startswith("...and 2 more")
    assert "2026-11-06" in summary.description
    kev = next(f for f in fs if f.rule_id == "cve-CVE-2099-0001")
    assert kev.title.endswith("actively exploited") and kev.severity.value == "high"  # raised from medium
    edb = next(f for f in fs if f.rule_id == "cve-CVE-2099-0002")
    assert edb.title.endswith("public exploit available") and "public-exploit" in edb.tags
    assert len(fs) == 3  # zlib has no CVEs -> no finding


def test_cna_only_component_has_low_confidence():
    details = {"components": [{"name": "px4", "version": "1.14.0", "cves": [cve(1, match="cna")]}]}
    assert build_findings(details)[0].confidence.value == "low"


def kb_finding(component, tags, rule="outdated-x"):
    return Finding(title=f"KB {component}", description="d", severity="high", classification="unverified",
                   confidence="medium", source_tool="builtin:components", rule_id=rule,
                   affected_component=component, remediation="r", tags=["outdated-component", *tags])


def test_supersede_kb():
    details = {"components": [{"name": "openssl", "version": "1.0.1e", "cves": [{"id": "CVE-2014-0160"}]},
                              {"name": "busybox", "version": "1.31.1", "cves": [{"id": "CVE-2021-42373"}]}]}
    heartbleed = kb_finding("openssl 1.0.1e", ["CVE-2014-0160"])
    partial = kb_finding("busybox 1.31.1", ["CVE-2021-42373", "CVE-2021-42374"])
    eol = kb_finding("linux 4.14.98", [])
    other = kb_finding("openssl 1.0.2", ["CVE-2014-0160"])
    assert supersede_kb([heartbleed, partial, eol, other], details) == [partial, eol, other]


# --------------------------------------------------------------------------- adapter
def adapter_ctx(settings, tmp_path, manifest):
    return AdapterContext(scan_id="t", input_path=tmp_path / "in.bin", original_name="in.bin", work_dir=tmp_path,
                          manifest=manifest, settings=settings)


MANIFEST = {"components": [{"name": "openssl", "version": "1.0.1e", "method": "string-match"},
                           {"name": "chibios", "version": "20.3.4", "method": "string-match"}]}


def test_adapter_without_database(settings, tmp_path):
    ad = CveLookupAdapter(settings)
    assert ad.status().available is False and "make cve-db" in ad.status().detail
    r = ad.execute(adapter_ctx(settings, tmp_path, MANIFEST))
    assert r.status == "unavailable" and "make cve-db" in r.message


def test_adapter_completed(settings, tmp_path, db):
    settings.cve_db_path = db
    ad = CveLookupAdapter(settings)
    assert ad.status().available and "CVEs, NVD data from" in ad.status().detail
    r = ad.execute(adapter_ctx(settings, tmp_path, MANIFEST))
    assert r.status == "completed", r.message
    assert "2 CVEs matched in 1 of 2 components" in r.message and "no CVE mapping for chibios 20.3.4" in r.message
    assert r.details["db"]["stale"] is False and r.details["totals"]["known_exploited"] == 1
    assert {f.rule_id for f in r.findings} == {"cve-component-openssl", "cve-CVE-2014-0160", "cve-CVE-2016-2107"}
    assert r.raw_output_path.endswith("cve_lookup.json")


def test_adapter_stale_database(settings, tmp_path):
    settings.cve_db_path = build_db(tmp_path / "old", timestamp="2020-01-01T00:00:00+00:00")
    r = CveLookupAdapter(settings).execute(adapter_ctx(settings, tmp_path, MANIFEST))
    assert r.status == "completed" and "out of date" in r.message and r.details["db"]["stale"] is True


def test_adapter_bad_database_fails(settings, tmp_path):
    bad = tmp_path / "cve.db"
    bad.write_bytes(b"garbage" * 100)
    settings.cve_db_path = bad
    r = CveLookupAdapter(settings).execute(adapter_ctx(settings, tmp_path, MANIFEST))
    assert r.status == "failed" and "CveDbError" in r.message


def test_adapter_disabled_and_not_applicable(settings, tmp_path, db):
    settings.cve_db_path = db
    settings.cve_lookup_enabled = False
    assert CveLookupAdapter(settings).execute(adapter_ctx(settings, tmp_path, MANIFEST)).status == "skipped"
    settings.cve_lookup_enabled = True
    r = CveLookupAdapter(settings).execute(adapter_ctx(settings, tmp_path, {"components": []}))
    assert r.status == "skipped" and "Not applicable" in r.message


def test_companion_image_end_to_end(settings, tmp_path, db, fixtures, run_analysis):
    """Built-in analysis of the companion fixture -> CVE lookup -> superseded KB -> deduped findings."""
    settings.cve_db_path = db
    man = run_analysis(fixtures["tar_gz"])
    r = CveLookupAdapter(settings).execute(adapter_ctx(settings, tmp_path, man))
    assert r.status == "completed", r.message
    assert len(ids(r.details, "openssl")) > 1
    assert set(ids(r.details, "busybox")) >= {"CVE-2021-42373", "CVE-2021-42374", "CVE-2021-42378",
                                              "CVE-2021-42386"}
    builtin = [Finding.from_dict(f) for f in man["findings"]]
    assert any("Heartbleed" in f.title for f in builtin)  # built-in KB reports it ...
    final = dedupe(supersede_kb(builtin + r.findings, r.details))
    heart = [f for f in final if "CVE-2014-0160" in f.title or "Heartbleed" in f.title]
    assert len(heart) == 1 and heart[0].source_tool == "cve_lookup"  # ... but it appears once, from the lookup
    assert not any(f.rule_id == "outdated-busybox" for f in final)  # KB BusyBox CVEs all covered
    assert any(f.rule_id == "outdated-linux" for f in final) or not any(
        f.rule_id == "outdated-linux" for f in builtin)  # CVE-less KB entries are kept


# --------------------------------------------------------------------------- PDF
def test_pdf_cve_section(db):
    from reportlab.lib.styles import getSampleStyleSheet

    from dfa.reports.export import PDF_CVE_TOP, _cve_story
    ss = getSampleStyleSheet()
    styles = (ss["Heading2"], ss["BodyText"], ss["BodyText"])
    text = lambda story: " ".join(getattr(x, "text", "") for x in story)  # noqa: E731
    assert "did not run" in text(_cve_story(None, *styles))
    missing = SimpleNamespace(status="unavailable", message="CVE database not installed", details={})
    assert "CVE database not installed" in text(_cve_story(missing, *styles))
    many = [cve(1, "high", 8.0, kev=True)] + [cve(i, "low", 2.0) for i in range(2, PDF_CVE_TOP + 10)]
    done = SimpleNamespace(status="completed", message="ok", details={
        "db": {"nvd_timestamp": "2026-11-06T01:00:00+00:00"},
        "totals": {"cves": len(many), "known_exploited": 1},
        "components": [{"name": "linux", "version": "4.14.98", "mapped": True, "cves": many},
                       {"name": "chibios", "version": "20.3.4", "mapped": False, "cves": []}]})
    out = text(_cve_story(done, *styles))
    assert "Showing 26 of 34 CVEs" in out and "chibios 20.3.4 (no CVE mapping)" in out and "2026-11-06" in out
