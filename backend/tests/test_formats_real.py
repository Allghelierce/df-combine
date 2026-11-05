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


def test_upstream_tag_mapping():
    from dfa.vulndb import _ardupilot_tags, _describe_base, _repo_key
    assert _describe_base("5.0-beta1-427-g4532e6e0b2-dirty") == "5.0-beta1"
    assert _describe_base("5.0-beta1-427-g4532e6e0b2-dirt") == "5.0-beta1"  # esp_app_desc_t truncates to 31 chars
    assert _describe_base("4.4.2") == "4.4.2"
    assert _ardupilot_tags("4.6.2", "ArduCopter") == ["Copter-4.6.2", "ArduCopter-4.6.2"]
    assert "Plane-4.6.2" in _ardupilot_tags("4.6.2", None)
    assert _repo_key("https://github.com/apache/nuttx") == "nuttx"
    assert _repo_key("https://github.com/apache/nuttx-apps") is None  # different project, different tags
    assert _repo_key("https://git.busybox.net/busybox") == "busybox"
    assert _repo_key("https://github.com/espressif/esp-idf.git") == "esp-idf"


def test_vulndb_vehicle_and_describe_matching(tmp_path):
    from dfa.vulndb import VulnDB, update
    from dfa.vulnmatch import match
    _osv_zip(tmp_path / "Debian.zip", [])
    _osv_zip(tmp_path / "Alpine.zip", [])
    _osv_zip(tmp_path / "GIT.zip", [
        {"id": "CVE-2099-1000", "summary": "plane-only release tag",
         "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/ardupilot/ardupilot", "events": []}],
                       "versions": ["Plane-4.6.3", "Copter-4.6.2"]}]},
        {"id": "CVE-2099-1001", "summary": "idf bug",
         "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/espressif/esp-idf", "events": []}],
                       "versions": ["v5.0-beta1"]}]},
        {"id": "CVE-2099-1002", "summary": "apps bug",
         "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/apache/nuttx-apps", "events": []}],
                       "versions": ["nuttx-12.0.0"]}]},
    ])
    update(tmp_path / "v.sqlite", tmp_path)
    db = VulnDB(tmp_path / "v.sqlite")

    def rules(components):
        fs, _ = match({"components": components}, db, "fw")
        return {f.rule_id: f.references for f in fs}

    assert rules([{"name": "ardupilot", "version": "4.6.3", "variant": "ArduCopter"}]) == {}  # Copter-4.6.3 not listed
    assert "CVE-2099-1000" in rules([{"name": "ardupilot", "version": "4.6.3", "variant": "ArduPlane"}])[
        "osv-upstream-ardupilot"]
    assert "osv-upstream-ardupilot" in rules([{"name": "ardupilot", "version": "4.6.3"}])  # vehicle unknown
    assert "CVE-2099-1001" in rules([{"name": "esp-idf", "version": "5.0-beta1-427-g4532e6e0b2-dirty"}])[
        "osv-upstream-esp-idf"]
    assert rules([{"name": "nuttx", "version": "12.0.0"}]) == {}  # nuttx-apps records are not NuttX releases


ESP = REAL / "esp"


@pytest.mark.skipif(not (ESP / "esp_idf_blink_esp32s2.bin").exists(),
                    reason="esptool sample images not fetched (scripts/fetch_real_firmware.py)")
def test_real_espressif_images():
    from dfa.core.formats.esp import parse_esp_image
    from dfa.core.identify import detect_format
    expect = {"bootloader_esp32.bin": ("ESP32", "Xtensa", None), "bootloader_esp32c3.bin": ("ESP32-C3", "RISC-V", True),
              "esp8266_deepsleep.bin": ("ESP8266", "Xtensa", None),
              "esp_idf_blink_esp32s2.bin": ("ESP32-S2", "Xtensa", True)}
    for name, (chip, arch, sha) in expect.items():
        data = (ESP / name).read_bytes()
        assert detect_format(ESP / name).format == "esp_image", name
        info = parse_esp_image(data)
        assert (info["chip"], info["architecture"], info["checksum_valid"], info.get("sha256_valid")) == \
            (chip, arch, True, sha), name
    app = parse_esp_image((ESP / "esp_idf_blink_esp32s2.bin").read_bytes())["app"]
    assert app["project_name"] == "blink" and app["idf_version"] == "v5.0-beta1-427-g4532e6e0b2-dirt"
    pt = detect_format(ESP / "partitions_singleapp.bin")
    assert pt.format == "esp_partition_table"
    assert [(p["label"], p["subtype"]) for p in pt.details["partitions"]] == \
        [("factory", "factory"), ("rfdata", "phy"), ("wifidata", "nvs")]


@pytest.mark.skipif(not (ESP / "esp_idf_blink_esp32s2.bin").exists(),
                    reason="esptool sample images not fetched (scripts/fetch_real_firmware.py)")
def test_real_esp_flash_layout_pipeline(tmp_path, run_analysis):
    """A flash layout assembled from real images: bootloader @0x1000, partition table @0x8000, app @0x10000."""
    d = bytearray(b"\xff" * 0x200000)
    for off, name in ((0x1000, "bootloader_esp32.bin"), (0x8000, "partitions_singleapp.bin"),
                      (0x10000, "esp_idf_blink_esp32s2.bin")):
        blob = (ESP / name).read_bytes()
        d[off:off + len(blob)] = blob
    p = tmp_path / "flash.bin"
    p.write_bytes(bytes(d))
    m = run_analysis(p)
    ident = m["identification"]
    assert ident["format"] == "esp_flash" and ident["platform"] == "Espressif"
    assert ("esp-idf", "5.0-beta1-427-g4532e6e0b2-dirt") in {(c["name"], c["version"]) for c in m["components"]}
    code = [a for a in m["extraction"]["artifacts"] if (a["details"].get("arch_guess") or {}).get("architecture")]
    assert code and all(a["details"]["arch_guess"]["architecture"] == "Xtensa" for a in code)


def test_package_file_ownership_parsers():
    from dfa.core.scanners.packages import apk_files, list_files
    apk = "P:busybox\nV:1.34.1-r3\nF:bin\nR:busybox\nF:etc\nR:securetty\n\nP:musl\nV:1.2.2-r7\nF:lib\nR:ld-musl-aarch64.so.1\n"
    assert apk_files(apk) == {"/bin/busybox": "busybox", "/etc/securetty": "busybox",
                              "/lib/ld-musl-aarch64.so.1": "musl"}
    assert list_files("/.\n/usr\n/usr/sbin/sshd\n/usr/bin/x\t0755\n") == ["/.", "/usr", "/usr/sbin/sshd", "/usr/bin/x"]


def test_findings_are_attributed_to_owning_packages():
    from dfa.core.findings import Classification, Confidence, Evidence, Finding, Severity, aggregate, attribute_packages
    inv = {"packages": [{"name": "openssh-server", "version": "1:8.4p1-5"}, {"name": "busybox", "version": "1.34"}],
           "owners": {"fw > rootfs > /usr/sbin/sshd": "openssh-server", "fw > rootfs > /bin/busybox": "busybox"}}

    def f(comp, ev=()):
        return Finding("t", "d", Severity.medium, Classification.suspicious, Confidence.medium, "builtin:binary",
                       "elf-nx", comp, "r", evidence=list(ev))
    fs = [f("fw > rootfs > /usr/sbin/sshd"), f("multiple", [Evidence("path", "x", "fw > rootfs > /bin/busybox")]),
          f("fw > rootfs > /usr/bin/unowned")]
    assert attribute_packages(fs, inv) == 2
    assert [x.package for x in fs] == ["openssh-server 1:8.4p1-5", "busybox 1.34", None]
    assert "package:openssh-server" in fs[0].tags
    merged = aggregate([f("fw > rootfs > /a"), f("fw > rootfs > /b"), f("fw > rootfs > /c")])
    assert merged[0].package is None


@pytest.mark.skipif(not (REAL / "debian11-armhf-rootfs-20210816.tar.gz").exists(), reason="real Debian rootfs absent")
def test_real_debian_binary_findings_name_their_package(run_analysis):
    from dfa.core.findings import Finding, attribute_packages
    m = run_analysis(REAL / "debian11-armhf-rootfs-20210816.tar.gz")
    fs = [Finding.from_dict(d) for d in m["findings"]]
    attribute_packages(fs, m["packages"])
    binary = [f for f in fs if f.source_tool == "builtin:binary"]
    assert binary and sum(1 for f in binary if f.package) >= len(binary) // 2, [(f.affected_component, f.package)
                                                                                 for f in binary][:5]
    owners = m["packages"]["owners"]
    assert owners[next(k for k in owners if k.endswith("/sbin/killall5"))] == "sysvinit-utils"
