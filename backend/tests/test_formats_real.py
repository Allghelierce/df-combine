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


def test_cromfs_loops_end_the_list():
    """A peer pointing back to an already-listed node ends the list (no revisit, no endless walk)."""
    vol = bytearray(factory.cromfs({"a": b"x"}))
    import struct
    struct.pack_into("<I", vol, 40 + 12, 20)  # the file node's peer points back to the first node
    entries = [e.name for e, _ in iter_cromfs(io.BytesIO(bytes(vol)), 0, len(vol), 100, 1 << 20)]
    assert entries == ["init.d", "init.d/a"]
    struct.pack_into("<I", vol, 40 + 12, 8)  # an offset inside the volume header is still malformed
    with pytest.raises(FormatError):
        list(iter_cromfs(io.BytesIO(bytes(vol)), 0, len(vol), 100, 1 << 20))


@pytest.mark.skipif(not (REAL / "px4_v1.15.0_fmu-v5_default.px4").exists(), reason="PX4 v1.15.0 sample not fetched")
def test_real_px4_v1_15_threaded_cromfs(run_analysis):
    """PX4 v1.15.0's /etc CROMFS ends subdirectory lists by pointing to the parent's next entry; all files are
    extracted at their real paths (no 'loop' error, nothing listed twice or under the wrong directory)."""
    m = run_analysis(REAL / "px4_v1.15.0_fmu-v5_default.px4")
    arts = m["extraction"]["artifacts"]
    assert not [a for a in arts if a.get("extraction") == "failed"]
    names = [a["name"] for a in arts if a.get("origin") == "extracted"]
    assert len(names) == len(set(names))
    assert {"/init.d/rcS", "/extras/px4_io-v2_default.bin", "/init.d/airframes/4001_quad_x"} <= set(names)
    assert not any(n.startswith("/extras/init.d") for n in names)


def test_cromfs_offset_at_or_past_fsize_ends_the_list():
    """NuttX (cromfs_offset2addr) treats offsets >= cv_fsize as NULL. Real PX4 FMUv2 builds end a directory's
    peer chain with peer == cv_fsize, followed by unrelated flash contents."""
    import struct
    vol = bytearray(factory.cromfs({"a": b"x", "b": b"y"}))
    fsize = struct.unpack_from("<I", vol, 12)[0]
    entries = list(iter_cromfs(io.BytesIO(bytes(vol)), 0, len(vol), 100, 1 << 20))
    last = None
    off = struct.unpack_from("<I", vol, 8)[0]  # root node; walk its peer chain to the last node
    while off:
        last, off = off, struct.unpack_from("<I", vol, off + 12)[0]
    struct.pack_into("<I", vol, last + 12, fsize)
    tail = bytes(vol) + b"\xff\xec\xc2\x0f" * 8  # what follows the volume in flash
    again = list(iter_cromfs(io.BytesIO(tail), 0, len(tail), 100, 1 << 20))
    assert [e.name for e, _ in again] == [e.name for e, _ in entries]


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
    # board and build as recorded in the .px4 container (summary, git_hash, build_time)
    assert i["board_name"] == "PX4FMUv5" and i["build"]["revision"] == "d6f12ad1c4f7"
    assert i["build"]["date"] == "May 13 2026"
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
    assert _ardupilot_tags("4.6.2", "AP_Bootloader") == []
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


APBL = REAL / "ardupilot"


@pytest.mark.skipif(not (APBL / "fmuv3_bl.bin").exists(),
                    reason="ArduPilot bootloaders not fetched (scripts/fetch_real_firmware.py)")
def test_real_ardupilot_bootloaders_identified(run_analysis):
    """Official AP_Bootloader builds committed in ardupilot/Tools/bootloaders (tag Copter-4.5.7)."""
    for name in ("fmuv3_bl.bin", "MatekH743_bl.bin", "Pixhawk6X_bl.bin", "CubeOrange_bl.bin", "CubeOrange_bl.hex"):
        ident = run_analysis(APBL / name)["identification"]
        assert (ident["platform"], ident["platform_confidence"], ident["vehicle_type"]) == \
            ("ArduPilot", "high", "AP_Bootloader"), (name, ident["platform_candidates"])
        assert ident["architecture"] == "ARM Cortex-M (Thumb-2)"


@pytest.mark.skipif(not ((REAL / "px4_fmu-v2_default.elf").exists() and (REAL / "px4_fmu-v2_default.px4").exists()),
                    reason="official PX4 FMUv2 ELF/.px4 not downloaded")
def test_real_px4_elf_yields_the_official_flash_image(tmp_path):
    """The flash image derived from the unstripped ELF's load segments is byte-identical to the image in the
    official .px4 of the same release, and its function symbols are recorded for cwe_checker."""
    import base64
    import zlib

    from dfa.core.analyze import run
    from dfa.core.limits import Limits
    work = tmp_path / "work"
    m = run(REAL / "px4_fmu-v2_default.elf", "px4_fmu-v2_default.elf", work, Limits())
    arts = m["extraction"]["artifacts"]
    flash = next(a for a in arts if a["name"] == "flash.bin")
    assert flash["format"] == "cortexm_raw" and flash["details"]["derived_from_elf"] is True
    assert flash["details"]["flash_base"] == "0x8004000"
    assert flash["details"]["flash_base_source"] == "ELF load address"
    assert flash["details"]["symbol_count"] > 5000
    px4 = json.loads((REAL / "px4_fmu-v2_default.px4").read_text())
    official = zlib.decompress(base64.b64decode(px4["image"]))
    assert (work / flash["path"]).read_bytes() == official
    symbols = json.loads((work / flash["details"]["symbol_map"]).read_text())
    assert any(e[2] == "main" or e[2].endswith("_main") for e in symbols)
    import shutil
    if shutil.which("c++filt"):  # C++ names are demangled on the sandbox side (binutils in the sandbox image)
        readable = {e[2]: e[3] for e in symbols if len(e) == 4}
        assert readable.get("_ZN3px46logger6Logger3runEv") == "px4::logger::Logger::run"
    # the NuttX /etc CROMFS inside the image is extracted as it is from the .px4
    assert {"/init.d/rcS", "/extras/px4_io-v2_default.bin"} <= {a["name"] for a in arts}


SITL = {  # ArduPilot SITL builds from dronekit-sitl's public bucket: (platform version, vehicle)
    "sitl-linux-copter-3.2.1.tar.gz": ("3.2.1", "ArduCopter"),  # 'ArduCopter V3.2.1'
    "sitl-linux-copter-3.3.tar.gz": ("3.3", "ArduCopter"),      # 'APM:Copter V3.3'
    "sitl-linux-plane-3.3.0.tar.gz": ("3.3.0", "ArduPlane"),
    "sitl-linux-rover-2.50.tar.gz": ("2.50", "ArduRover"),      # 'ArduRover v2.50', 'APMrover2'
}


@pytest.mark.skipif(not (APBL / "sitl-linux-copter-3.3.tar.gz").exists(),
                    reason="ArduPilot SITL builds not fetched (scripts/fetch_real_firmware.py)")
def test_real_ardupilot_vehicle_builds_identified(run_analysis):
    from dfa.vulndb import _ardupilot_tags
    for name, (version, vehicle) in SITL.items():
        m = run_analysis(APBL / name)
        ident = m["identification"]
        assert (ident["platform"], ident["platform_confidence"], ident["platform_version"],
                ident["vehicle_type"]) == ("ArduPilot", "high", version, vehicle), (name, ident["platform_candidates"])
        assert [(c["name"], c["version"], c.get("variant")) for c in m["components"]] == \
            [("ardupilot", version, vehicle)]
        # the bundled default.parm is checked by the drone rules; these SITL defaults contain no unsafe values
        assert not [f for f in m["findings"] if f["rule_id"].startswith("ardupilot-")]
    # release tags used for OSV matching follow ArduPilot's historical naming
    assert "APMrover2-2.50" in _ardupilot_tags("2.50", "ArduRover")
    assert "ArduCopter-3.2.1" in _ardupilot_tags("3.2.1", "ArduCopter")
    assert "Copter-3.3" in _ardupilot_tags("3.3", "ArduCopter")


FC = {  # official Betaflight / INAV release builds: (platform, version, board/target)
    "betaflight/betaflight_4.3.2_STM32F405.hex": ("Betaflight", "4.3.2", "STM32F405"),
    "betaflight/betaflight_4.3.2_STM32H743.hex": ("Betaflight", "4.3.2", "STM32H743"),
    "inav/inav_7.1.2_MATEKF405.hex": ("INAV", "7.1.2", "MATEKF405"),  # initial SP 0x10010000 (CCM)
    "inav/inav_7.1.2_MATEKH743.hex": ("INAV", "7.1.2", "MATEKH743"),
    "inav/inav_6.1.1_MATEKF405.hex": ("INAV", "6.1.1", "MATEKF405"),
}


@pytest.mark.skipif(not (REAL / "inav" / "inav_7.1.2_MATEKF405.hex").exists(),
                    reason="Betaflight/INAV builds not fetched (scripts/fetch_real_firmware.py)")
def test_real_betaflight_and_inav_builds_identified(run_analysis):
    for name, (platform, version, board) in FC.items():
        m = run_analysis(REAL / name)
        i = m["identification"]
        assert (i["platform"], i["platform_confidence"], i["platform_version"], i["board_name"]) == \
            (platform, "high", version, board), (name, i["platform_candidates"])
        assert i["architecture"] == "ARM Cortex-M (Thumb-2)", name
        image = next(a for a in m["extraction"]["artifacts"] if a["name"] == "image.bin")
        assert image["format"] == "cortexm_raw" and image["details"]["flash_base"] == "0x8000000"
        assert [(c["name"], c["version"]) for c in m["components"]] == [(platform.lower(), version)]
        assert i["build"]["revision"] and i["build"]["date"]


@pytest.mark.skipif(not ((REAL / "px4_fmu-v2_default.elf").exists() and (REAL / "px4_fmu-v2_default.px4").exists()),
                    reason="official PX4 FMUv2 ELF/.px4 not downloaded")
def test_real_px4_bundle_gives_the_px4_image_the_elf_symbols(tmp_path, settings):
    """A PX4 build directory (.px4 + .elf of the same build) uploaded as one archive: the stripped .px4 image
    is identical to the ELF's flash image, so it gets the ELF's symbols and is analysed only once."""
    import tarfile

    from dfa.adapters.base import AdapterContext
    from dfa.adapters.cwe_checker import CweCheckerAdapter
    from dfa.core.analyze import run
    from dfa.core.limits import Limits
    bundle = tmp_path / "px4_fmu-v2_build.tar"
    with tarfile.open(bundle, "w") as tf:
        for n in ("px4_fmu-v2_default.px4", "px4_fmu-v2_default.elf"):
            tf.add(REAL / n, arcname=n)
    work = tmp_path / "work"
    m = run(bundle, bundle.name, work, Limits())
    arts = m["extraction"]["artifacts"]
    px4_image = next(a for a in arts if a["display_path"].endswith("px4_fmu-v2_default.px4 > image.bin"))
    assert px4_image["details"]["symbol_count"] > 5000
    assert px4_image["details"]["symbols_from"].endswith("px4_fmu-v2_default.elf")
    ctx = AdapterContext(scan_id="t", input_path=bundle, original_name=bundle.name, work_dir=work, manifest=m,
                         settings=settings)
    targets, why = CweCheckerAdapter(settings).plan(ctx)
    assert len(targets) == 3 and "3 identical copies merged" in why  # main image, IO firmware, bootloader
    assert (targets[0]["artifact"].get("details") or {}).get("symbol_map")
