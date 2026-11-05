"""Integration tests: upload -> worker -> findings -> reports through the HTTP API."""
import time

import pytest

from dfa.worker import claim_next, run_one


def upload(client, path, name=None):
    with open(path, "rb") as fp:
        r = client.post("/api/scans", files={"file": (name or path.name, fp, "application/octet-stream")})
    assert r.status_code == 201, r.text
    return r.json()


def process_all(settings):
    while (sid := claim_next("test-worker")):
        run_one(sid, settings)


def test_health_and_config(client):
    assert client.get("/api/health").json()["status"] == "ok"
    cfg = client.get("/api/config").json()
    assert cfg["sandbox_mode"] == "local" and cfg["max_upload_mb"] == 64


def test_end_to_end_companion(client, settings, fixtures):
    scan = upload(client, fixtures["tar_gz"])
    assert scan["status"] == "queued"
    process_all(settings)
    d = client.get(f"/api/scans/{scan['id']}").json()
    assert d["status"] == "completed", d.get("error")
    assert d["progress"] == 100
    assert d["identification"]["os_hint"] == "linux"
    assert d["severity_counts"]["critical"] >= 1
    assert d["risk_score"] > 50
    tools = {t["tool"]: t for t in d["tool_runs"]}
    assert tools["builtin:secrets"]["status"] == "completed"
    assert tools["fact"]["status"] == "unavailable"  # not configured
    assert "DFA_FACT_URL" in tools["fact"]["message"]
    assert tools["cwe_checker"]["status"] in ("unavailable", "completed", "failed")
    assert any(e["stage"] == "complete" for e in d["events"])

    f = client.get(f"/api/scans/{scan['id']}/findings").json()["items"]
    assert any(x["rule_id"] == "empty-password" for x in f)
    crit = client.get(f"/api/scans/{scan['id']}/findings", params={"severity": "critical"}).json()["items"]
    assert crit and all(x["severity"] == "critical" for x in crit)
    sus = client.get(f"/api/scans/{scan['id']}/findings", params={"classification": "suspicious"}).json()["items"]
    assert sus and all(x["classification"] == "suspicious" for x in sus)

    arts = client.get(f"/api/scans/{scan['id']}/artifacts").json()
    assert arts["total"] > 10 and arts["link_count"] >= 1

    rj = client.get(f"/api/scans/{scan['id']}/report.json")
    assert rj.status_code == 200 and "attachment" in rj.headers["content-disposition"]
    rep = rj.json()
    assert rep["scan"]["sha256"] == scan["sha256"] and rep["disclaimer"]
    assert len(rep["scan"]["findings"]) == len(f)

    rp = client.get(f"/api/scans/{scan['id']}/report.pdf")
    assert rp.status_code == 200 and rp.content.startswith(b"%PDF") and len(rp.content) > 3000

    rs = client.get(f"/api/scans/{scan['id']}/report.sarif")
    assert rs.status_code == 200 and rs.headers["content-type"].startswith("application/sarif+json")
    sar = rs.json()
    assert sar["version"] == "2.1.0" and len(sar["runs"][0]["results"]) == len(f)
    res0 = sar["runs"][0]["results"][0]
    assert res0["ruleId"] in {r["id"] for r in sar["runs"][0]["tool"]["driver"]["rules"]}
    assert res0["properties"]["classification"] in ("detected", "suspicious", "unverified", "info")
    assert all(r["kind"] == "review" for r in sar["runs"][0]["results"] if r["properties"]["classification"] != "detected")

    pk = client.get(f"/api/scans/{scan['id']}/packages").json()
    assert set(pk) >= {"distro", "managers", "total", "items"}


@pytest.mark.parametrize("key,platform", [("px4", "PX4"), ("apj", "ArduPilot"), ("hex", "ArduPilot")])
def test_end_to_end_flight_controllers(client, settings, fixtures, key, platform):
    scan = upload(client, fixtures[key])
    process_all(settings)
    d = client.get(f"/api/scans/{scan['id']}").json()
    assert d["status"] == "completed", d.get("error")
    assert d["identification"]["platform"] == platform
    tools = {t["tool"]: t for t in d["tool_runs"]}
    # FwAnalyzer must not pretend to analyse MCU firmware.
    assert tools["fwanalyzer"]["status"] in ("skipped", "unavailable")


def test_history_search_and_delete(client, settings, fixtures):
    a = upload(client, fixtures["px4"])
    b = upload(client, fixtures["px4"], name="copy.px4")
    assert b["previous_scans_same_hash"] == 1
    lst = client.get("/api/scans").json()
    assert lst["total"] == 2
    assert client.get("/api/scans", params={"q": "copy"}).json()["total"] == 1
    assert client.get("/api/scans", params={"sha256": a["sha256"]}).json()["total"] == 2
    assert client.delete(f"/api/scans/{a['id']}").status_code == 204
    assert client.get(f"/api/scans/{a['id']}").status_code == 404
    assert client.get("/api/scans").json()["total"] == 1


def test_pdf_requires_completed(client, fixtures):
    s = upload(client, fixtures["px4"])
    assert client.get(f"/api/scans/{s['id']}/report.pdf").status_code == 409


def test_rescan(client, settings, fixtures):
    s = upload(client, fixtures["apj"])
    process_all(settings)
    assert client.post(f"/api/scans/{s['id']}/rescan").status_code == 202
    process_all(settings)
    d = client.get(f"/api/scans/{s['id']}").json()
    assert d["status"] == "completed"
    # Tool runs are replaced, not duplicated.
    assert len([t for t in d["tool_runs"] if t["tool"] == "fact"]) == 1


def test_upload_limits(client, settings, tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with open(empty, "rb") as fp:
        assert client.post("/api/scans", files={"file": ("e.bin", fp)}).status_code == 400
    settings.max_upload_mb = 1
    big = tmp_path / "big.bin"
    big.write_bytes(b"\0" * (1024 * 1024 + 10))
    with open(big, "rb") as fp:
        assert client.post("/api/scans", files={"file": ("big.bin", fp)}).status_code == 413
    assert not list(settings.uploads_dir.iterdir())


def test_filename_sanitised(client, fixtures):
    s = upload(client, fixtures["px4"], name="../../etc/passwd\x07.px4")
    name = s["original_filename"]
    assert "/" not in name and ".." not in name and name.startswith("passwd")
    assert all(c.isprintable() for c in name)


def test_malicious_archive_scan_completes(client, settings, fixtures):
    s = upload(client, fixtures["zip_slip"])
    process_all(settings)
    d = client.get(f"/api/scans/{s['id']}").json()
    assert d["status"] == "completed"
    assert any("traversal" in w for w in d["extraction_summary"]["warnings"])


def test_inprocess_worker_thread(make_client, fixtures):
    c = make_client(start_worker=True)
    if True:
        s = upload(c, fixtures["px4"])
        for _ in range(120):
            d = c.get(f"/api/scans/{s['id']}").json()
            if d["status"] in ("completed", "failed"):
                break
            time.sleep(0.25)
        assert d["status"] == "completed"


def test_stats(client, settings, fixtures):
    upload(client, fixtures["px4"])
    process_all(settings)
    st = client.get("/api/stats").json()
    assert st["total_scans"] == 1 and st["platforms"].get("PX4") == 1


def test_tools_endpoint(client):
    tools = client.get("/api/tools").json()["tools"]
    names = {t["name"] for t in tools}
    assert {"builtin", "fwanalyzer", "cwe_checker", "fact"} <= names
    for t in tools:
        assert "detail" in t and isinstance(t["available"], bool)


def test_stale_recovery(settings, client, fixtures):
    from dfa.db import session_scope
    from dfa.models import Scan
    from dfa.worker import recover_stale
    s = upload(client, fixtures["px4"])
    with session_scope() as db:
        scan = db.get(Scan, s["id"])
        scan.status, scan.worker_id, scan.attempts = "running", "nohost:1:0", 1
        scan.heartbeat_at = None
    assert recover_stale(settings) == 1
    with session_scope() as db:
        assert db.get(Scan, s["id"]).status == "queued"


def test_compare_releases(client, settings, fixtures, tmp_path):
    import shutil
    import tarfile

    import factory
    v1 = upload(client, fixtures["tar_gz"], name="companion-1.0.tar.gz")
    root = tmp_path / "v2"
    factory.companion_rootfs(root)
    (root / "etc/shadow").write_text("root:!:19000:0:99999:7:::\n")          # fixed
    (root / "etc/inittab").write_text("::sysinit:/etc/init.d/rcS\n")          # telnet removed
    (root / "bin/busybox").write_text("\x00BusyBox v1.36.1 (2024) multi-call binary.\x00")  # upgraded
    (root / "etc/app/debug.conf").write_text("admin_password=letmein\n")     # new issue
    out = tmp_path / "companion-2.0.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        tf.add(root, arcname=".")
    shutil.rmtree(root)
    v2 = upload(client, out)
    process_all(settings)
    r = client.get("/api/compare", params={"base": v1["id"], "target": v2["id"]})
    assert r.status_code == 200, r.text
    d = r.json()
    resolved = {f["rule_id"] for f in d["resolved"]}
    assert {"empty-password", "telnetd-shell-no-auth", "outdated-busybox"} <= resolved
    assert any("admin_password" in str(f["evidence"]) for f in d["new"])
    assert any(c["name"] == "busybox" and c["change"] == "changed" for c in d["components"])
    assert d["summary"]["unchanged"] > 5  # same issues in renamed archive still match
    assert client.get("/api/compare", params={"base": v1["id"], "target": "nope"}).status_code == 404


def test_dash_prefixed_filename(client, settings, fixtures):
    s = upload(client, fixtures["px4"], name="-fw.px4")
    process_all(settings)
    assert client.get(f"/api/scans/{s['id']}").json()["status"] == "completed"


def test_spa_route_does_not_serve_sibling_dirs(settings, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from dfa.main import create_app
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>app</html>")
    (tmp_path / "dist-old").mkdir()
    (tmp_path / "dist-old" / "secret.txt").write_text("SECRET")
    monkeypatch.setenv("DFA_FRONTEND_DIST", str(dist))
    with TestClient(create_app(settings, start_worker=False)) as c:
        r = c.get("/%2e%2e/dist-old/secret.txt")  # SPA route is public by design (static assets only)
        assert "SECRET" not in r.text


def test_purge_extracted_files(client, settings, fixtures):
    settings.keep_extracted = False
    s = upload(client, fixtures["tar_gz"])
    process_all(settings)
    d = client.get(f"/api/scans/{s['id']}").json()
    assert d["status"] == "completed" and d["severity_counts"]["critical"] >= 1
    work = settings.work_root / s["id"]
    assert not (work / "files").exists() and (work / "manifest.json").exists()
    assert client.get(f"/api/scans/{s['id']}/artifacts").json()["total"] > 5


def test_links_planted_by_a_compromised_sandbox_are_not_followed(client, settings, fixtures, monkeypatch):
    """A compromised sandbox can leave anything in the scan directory. The worker must not write its
    results through a planted link (here: into the database or a directory outside the scan)."""
    import dfa.pipeline
    real = dfa.pipeline.run_analysis
    outside = settings.data_dir / "outside"
    outside.mkdir(parents=True, exist_ok=True)

    def compromised(input_path, name, work, s, progress=None):
        res = real(input_path, name, work, s, progress)
        (work / "findings.json").symlink_to(settings.data_dir / "dfa.db")
        (work / "tools").symlink_to(outside)
        return res
    monkeypatch.setattr(dfa.pipeline, "run_analysis", compromised)
    db_before = (settings.data_dir / "dfa.db").read_bytes()[:16]
    s = upload(client, fixtures["px4"])
    process_all(settings)
    d = client.get(f"/api/scans/{s['id']}").json()
    assert d["status"] == "completed"
    assert (settings.data_dir / "dfa.db").read_bytes()[:16] == db_before == b"SQLite format 3\x00"
    work = settings.work_root / s["id"]
    assert not (work / "findings.json").is_symlink() and (work / "findings.json").read_text().startswith("[")
    assert list(outside.iterdir()) == []  # no tool directory was created through the link
    assert client.get(f"/api/scans/{s['id']}/artifacts").status_code == 200


def test_artifacts_expose_raw_image_facts(client, settings, fixtures):
    """The inventory shows a raw MCU image's load address (curated keys only, not arbitrary details)."""
    s = upload(client, fixtures["px4"])
    process_all(settings)
    arts = client.get(f"/api/scans/{s['id']}/artifacts").json()["items"]
    images = [a["image"] for a in arts if a.get("image")]
    assert images and images[0]["flash_base"].startswith("0x")
    assert all(set(i) <= {"flash_base", "flash_base_source", "derived_from_elf", "symbol_count", "symbols_from",
                          "identical_to"} for i in images)


def test_cyclonedx_sbom(client, settings, fixtures):
    """CycloneDX 1.5 export: firmware metadata (incl. board/build from the .px4 container), components with
    purl/CPE where known, attachment download."""
    s = upload(client, fixtures["px4"])
    process_all(settings)
    r = client.get(f"/api/scans/{s['id']}/sbom.cdx.json")
    assert r.status_code == 200 and "attachment" in r.headers.get("content-disposition", "")
    bom = r.json()
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.5")
    comp = bom["metadata"]["component"]
    assert comp["type"] == "firmware" and comp["hashes"][0]["content"] == s["sha256"]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["dfa:platform"] == "PX4" and props["dfa:board"] == "PX4FMUv5" and props["dfa:board-id"] == "50"
    assert all(c.get("bom-ref") for c in bom["components"])
    assert bom["dependencies"][0]["ref"] == comp["bom-ref"]
