"""CROMFS/LZF, package databases, OSV matching - synthetic unit tests plus real-data tests."""
import io
import json
import zipfile
from pathlib import Path

import factory
import pytest

from dfa.core.formats.simplefs import FormatError, cromfs_header, iter_cromfs, lzf_decompress
from dfa.core.scanners.packages import parse_apk, parse_dpkg, parse_os_release, purl

REAL = Path(__file__).resolve().parents[2] / "fixtures" / "real"


def test_lzf_literals_and_backreferences():
    assert lzf_decompress(bytes([2]) + b"abc" + bytes([0x80, 0x02]), 9) == b"abcabcabc"
    with pytest.raises(FormatError):
        lzf_decompress(bytes([0x80, 0x10]), 10)  # reference before start of output
    with pytest.raises(FormatError):
        lzf_decompress(bytes([5]) + b"ab", 10)  # truncated literal run


def test_cromfs_roundtrip():
    vol = factory.cromfs({"rcS": b"param set CBRK_IO_SAFETY 22027\n" * 40, "rc.board": b"echo hi\n"})
    assert cromfs_header(vol, len(vol))["nnodes"] == 3
    ents = list(iter_cromfs(io.BytesIO(vol), 0, len(vol), 100, 1 << 20))
    files = {e.name: d for e, d in ents if e.kind == "file"}
    assert files["init.d/rcS"].startswith(b"param set CBRK_IO_SAFETY")
    assert len(files["init.d/rcS"]) == 31 * 40


def test_cromfs_extracted_and_scanned(tmp_path, run_analysis):
    vol = factory.cromfs({"rcS": b"param set-default CBRK_IO_SAFETY 22027\n"})
    img = factory.cortexm_image(["PX4 Autopilot v1.15.0", "NuttX", "uORB", "px4io"], embedded=[vol])
    p = tmp_path / "fw.bin"
    p.write_bytes(img)
    m = run_analysis(p)
    assert any(a["format"] == "cromfs" for a in m["extraction"]["artifacts"])
    assert any(f["rule_id"] == "px4-cbrk_io_safety" for f in m["findings"])


def test_cromfs_rejects_loops():
    vol = bytearray(factory.cromfs({"a": b"x"}))
    # make the file node's peer point back to the directory node
    import struct
    struct.pack_into("<I", vol, 40 + 12, 20)
    with pytest.raises(FormatError):
        list(iter_cromfs(io.BytesIO(bytes(vol)), 0, len(vol), 100, 1 << 20))


DPKG = """Package: libssl1.1
Status: install ok installed
Architecture: armhf
Source: openssl
Version: 1.1.1k-1+deb11u1

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Architecture: armhf
Version: 5.1-2
"""


def test_package_parsers():
    pk = parse_dpkg(DPKG)
    assert [(p["name"], p["source"], p["source_version"]) for p in pk] == [
        ("libssl1.1", "openssl", "1.1.1k-1+deb11u1"), ("bash", "bash", "5.1-2")]
    apk = parse_apk("P:busybox\nV:1.34.1-r3\nA:aarch64\no:busybox\n\nP:musl\nV:1.2.2-r7\n")
    assert apk[0]["name"] == "busybox" and apk[1]["version"] == "1.2.2-r7"
    osr = parse_os_release('ID=debian\nVERSION_ID="11"\nPRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\n')
    assert osr["ID"] == "debian" and osr["VERSION_ID"] == "11"
    assert purl(pk[0], {"id": "debian", "version_id": "11"}) == \
        "pkg:deb/debian/libssl1.1@1.1.1k-1%2Bdeb11u1?arch=armhf&distro=debian-11"


def _osv_zip(path: Path, records: list[dict]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return path


def test_vulndb_import_and_match(tmp_path):
    from dfa.vulndb import VulnDB, update
    from dfa.vulnmatch import match
    _osv_zip(tmp_path / "Debian.zip", [
        {"id": "DEBIAN-CVE-2099-0001", "aliases": [], "upstream": ["CVE-2099-0001"], "summary": "openssl bug",
         "affected": [{"package": {"ecosystem": "Debian:11", "name": "openssl"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1n-0+deb11u1"}]}],
                       "ecosystem_specific": {"urgency": "medium"}}]},
        {"id": "DEBIAN-CVE-2099-0002", "summary": "already fixed", "affected": [
            {"package": {"ecosystem": "Debian:11", "name": "openssl"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1k-1"}]}]}]},
    ])
    _osv_zip(tmp_path / "Alpine.zip", [])
    _osv_zip(tmp_path / "GIT.zip", [
        {"id": "CVE-2099-0001", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
         "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/openssl/openssl", "events": []}],
                       "versions": ["1.1.1k"]}]},
        {"id": "CVE-2099-0003", "summary": "px4 bug",
         "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/px4/px4-autopilot", "events": []}],
                       "versions": ["v1.11.3"]}]},
    ])
    db_path = tmp_path / "v.sqlite"
    stats = update(db_path, tmp_path)
    assert stats == {"Debian": 2, "Alpine": 0, "GIT": 2}
    db = VulnDB(db_path)
    manifest = {"packages": {"distro": {"id": "debian", "version_id": "11"},
                             "packages": [{"name": "libssl1.1", "version": "1.1.1k-1+deb11u1", "source": "openssl",
                                           "source_version": "1.1.1k-1+deb11u1", "manager": "dpkg",
                                           "database": "/var/lib/dpkg/status"}]},
                "components": [{"name": "openssl", "version": "1.1.1k"}, {"name": "px4", "version": "1.11.3"},
                               {"name": "px4", "version": "1.17.0"}]}
    fs, st = match(manifest, db, "fw")
    by = {f.rule_id: f for f in fs}
    d = by["osv-distro-package"]
    assert d.classification.value == "detected" and "1 known vulnerability" in d.title
    assert d.severity.value == "critical"  # CVSS 9.8 borrowed from the GIT record of the same CVE
    assert "1.1.1n-0+deb11u1" in d.remediation
    assert st["superseded"] == ["openssl 1.1.1k"]  # covered by the distro package data
    px4 = by["osv-upstream-px4"]
    assert px4.classification.value == "unverified" and "CVE-2099-0003" in px4.references
    assert sum(1 for f in fs if f.rule_id == "osv-upstream-px4") == 1  # 1.17.0 not affected


@pytest.mark.skipif(not (REAL / "debian11-armhf-rootfs-20210816.tar.gz").exists()
                    or not Path("/opt/osv/vulndb.sqlite").exists(), reason="real Debian rootfs / OSV DB not present")
def test_real_debian_rootfs_matching(run_analysis):
    from dfa.vulndb import VulnDB
    from dfa.vulnmatch import match
    m = run_analysis(REAL / "debian11-armhf-rootfs-20210816.tar.gz")
    assert m["identification"]["architecture"] == "ARM (32-bit)"
    inv = m["packages"]
    assert inv["distro"]["id"] == "debian" and inv["distro"]["version_id"] == "11"
    assert inv["managers"][0]["type"] == "dpkg" and inv["managers"][0]["count"] > 80
    fs, st = match(m, VulnDB(Path("/opt/osv/vulndb.sqlite")), "debian11")
    assert st["affected"] > 5 and all(f.classification.value == "detected" for f in fs)
    assert "glibc 2.31" in st["superseded"]  # no duplicate string-based glibc matches


@pytest.mark.skipif(not (REAL / "px4_fmu-v5_default.px4").exists(), reason="official PX4 sample not downloaded")
def test_real_px4_extraction(run_analysis):
    m = run_analysis(REAL / "px4_fmu-v5_default.px4")
    i = m["identification"]
    assert i["platform"] == "PX4" and i["platform_version"] == "1.17.0" and i["board_id"] == 50
    assert i["architecture"].startswith("ARM Cortex-M")
    arts = m["extraction"]["artifacts"]
    image = next(a for a in arts if a["format"] == "cortexm_raw" and a["name"] == "image.bin")
    assert image["details"]["flash_base"] == "0x8008000"
    names = {a["name"] for a in arts}
    assert {"/init.d/rcS", "/extras/px4_io-v2_default.bin"} <= names
    assert any(a["format"] == "cromfs" for a in arts)
    assert "ArduPilot" not in [c["name"] for c in i["platform_candidates"]]
