import gzip
import io
import os
import tarfile
import zipfile
from pathlib import Path

import factory
import pytest

from dfa.core.extract import Extractor, UnsafePath, safe_member_path
from dfa.core.limits import Limits


def extract(path: Path, work: Path, **limits):
    ex = Extractor(work, Limits(**limits))
    return ex, ex.run(path, path.name)


def all_files_inside(root: Path) -> bool:
    root = root.resolve()
    for p in root.rglob("*"):
        if p.is_symlink():
            return False
        if not str(p.resolve()).startswith(str(root)):
            return False
    return True


@pytest.mark.parametrize("name", ["../x", "a/../../x", "a/b/../../../x", "..\\..\\x", "C:\\x", "a\x00b", ""])
def test_safe_member_path_rejects(name):
    with pytest.raises(UnsafePath):
        safe_member_path(name)


def test_safe_member_path_normalises():
    assert str(safe_member_path("/etc//passwd")) == "etc/passwd"
    assert str(safe_member_path("./a/./b")) == "a/b"


def test_zip_slip_blocked(fixtures, tmp_path):
    ex, res = extract(fixtures["zip_slip"], tmp_path / "w")
    assert not Path("/tmp/dfa_evil.txt").exists()
    assert any("path traversal" in w for w in res.warnings)
    names = [a.name for a in res.artifacts]
    assert "/ok/readme.txt" in names and "/etc/absolute.txt" in names
    assert all_files_inside(tmp_path / "w")


def test_tar_traversal_links_devices(fixtures, tmp_path):
    ex, res = extract(fixtures["tar_traversal"], tmp_path / "w")
    assert all_files_inside(tmp_path / "w")
    kinds = {link.kind for link in res.links}
    assert {"symlink", "hardlink", "device"} <= kinds
    assert not list((tmp_path / "w").rglob("link_to_root"))
    assert not list((tmp_path / "w").rglob("dev_mem"))
    assert any("traversal" in w for w in res.warnings)


def test_zip_bomb_ratio_limit(tmp_path):
    bomb = factory.zip_bomb(tmp_path / "bomb.zip", size_mb=20)
    ex, res = extract(bomb, tmp_path / "w", max_ratio=50, ratio_min_bytes=1024 * 1024)
    root = res.artifacts[0]
    assert root.extraction == "partial"
    assert "ratio" in root.extraction_note
    assert ex.budget.bytes_written < 20 * 1024 * 1024


def test_gzip_bomb_total_limit(tmp_path):
    bomb = factory.gzip_bomb(tmp_path / "bomb.gz", size_mb=20)
    ex, res = extract(bomb, tmp_path / "w", max_total_bytes=4 * 1024 * 1024, max_ratio=1e9)
    assert res.artifacts[0].extraction == "partial"
    assert "limit" in res.artifacts[0].extraction_note
    # The partially written file is removed.
    assert not any(p.is_file() and p.stat().st_size > 4 * 1024 * 1024 for p in (tmp_path / "w").rglob("*"))


def test_per_file_limit(tmp_path):
    p = tmp_path / "big.gz"
    with gzip.open(p, "wb") as fp:
        fp.write(os.urandom(3 * 1024 * 1024))
    ex, res = extract(p, tmp_path / "w", max_file_bytes=1024 * 1024)
    assert res.artifacts[0].extraction == "partial"


def test_file_count_limit(tmp_path):
    p = tmp_path / "many.tar"
    with tarfile.open(p, "w") as tf:
        for i in range(50):
            ti = tarfile.TarInfo(f"f{i}.txt")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
    ex, res = extract(p, tmp_path / "w", max_files=10)
    assert res.artifacts[0].extraction == "partial"
    assert len(res.artifacts) <= 12


def test_nesting_depth_limit(fixtures, tmp_path):
    ex, res = extract(fixtures["nested"], tmp_path / "w", max_depth=3)
    assert max(a.depth for a in res.artifacts) <= 3
    assert any(a.extraction == "skipped" for a in res.artifacts)


def test_duplicate_members_do_not_overwrite(tmp_path):
    p = tmp_path / "dup.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.txt", "first")
        zf.writestr("./a.txt", "second")
    ex, res = extract(p, tmp_path / "w")
    files = [a for a in res.artifacts if a.name == "/a.txt"]
    assert len(files) == 1
    assert ex.path_of(files[0].id).read_text() == "first"


def test_corrupt_archive_reports_failure(tmp_path):
    p = tmp_path / "corrupt.zip"
    p.write_bytes(b"PK\x03\x04" + os.urandom(200))
    ex, res = extract(p, tmp_path / "w")
    assert res.artifacts[0].extraction == "failed"


def test_unsupported_when_tool_missing(fixtures, tmp_path):
    if "squashfs" not in fixtures:
        pytest.skip("mksquashfs unavailable")
    ex = Extractor(tmp_path / "w", Limits())
    ex._external_tools["unsquashfs"] = None
    res = ex.run(fixtures["squashfs"], "fs.squashfs")
    assert res.artifacts[0].extraction == "unsupported"
    assert "not installed" in res.artifacts[0].extraction_note


@pytest.mark.parametrize("key", ["squashfs", "ext4", "disk_img", "tar_gz", "zip"])
def test_filesystem_extraction(fixtures, tmp_path, key):
    if key not in fixtures:
        pytest.skip("fixture unavailable")
    ex, res = extract(fixtures[key], tmp_path / "w")
    names = {a.name for a in res.artifacts}
    assert "/etc/shadow" in names and "/etc/hostapd/hostapd.conf" in names
    assert all_files_inside(tmp_path / "w")
    for p in (tmp_path / "w").rglob("*"):
        if p.is_file():
            assert not (p.stat().st_mode & 0o6000), f"setuid/setgid bit kept on {p}"


def test_carving_romfs_and_gzip(fixtures, tmp_path):
    ex, res = extract(fixtures["px4"], tmp_path / "w")
    assert any(a.format == "romfs" and a.origin == "carved" for a in res.artifacts)
    assert any(a.name == "/etc/rcS" for a in res.artifacts)
    ex, res = extract(fixtures["apj"], tmp_path / "w2")
    carved = [a for a in res.artifacts if a.origin == "carved"]
    assert carved and b"ARMING_CHECK 0" in ex.path_of(carved[0].id).read_bytes()


def test_dfuse_parse(tmp_path):
    import struct
    payload = b"\xAA" * 256
    elem = struct.pack("<II", 0x08000000, len(payload)) + payload
    target = b"Target" + bytes([0]) + struct.pack("<I", 1) + b"ST...".ljust(255, b"\0") + struct.pack("<II", len(elem), 1)
    body = target + elem
    prefix = b"DfuSe" + struct.pack("<BIB", 1, 11 + len(body), 1)
    suffix = struct.pack("<HHHH", 0x2200, 0xDF11, 0x0483, 0x011A) + b"UFD" + bytes([16]) + b"\0\0\0\0"
    p = tmp_path / "fw.dfu"
    p.write_bytes(prefix + body + suffix)
    ex, res = extract(p, tmp_path / "w")
    assert res.artifacts[0].format == "dfu" and res.artifacts[0].extraction == "ok"
    child = res.artifacts[1]
    assert child.details["load_address"] == "0x8000000"
    assert ex.path_of(child.id).read_bytes() == payload
    assert res.artifacts[0].details["usb_vid"] == "0483"


def test_lzma_alone_payload(tmp_path):
    import lzma
    p = tmp_path / "kernel.lzma"
    p.write_bytes(lzma.compress(b"Linux version 3.10.14 (builder@x) #1\n" * 50, format=lzma.FORMAT_ALONE))
    ex, res = extract(p, tmp_path / "w")
    assert res.artifacts[0].format == "lzma" and res.artifacts[0].extraction == "ok"
    assert b"Linux version" in ex.path_of(res.artifacts[1].id).read_bytes()


def test_traversal_and_escaping_links_are_findings(fixtures, run_analysis, tmp_path):
    m = run_analysis(fixtures["zip_slip"])
    assert any(f["rule_id"] == "archive-path-traversal" for f in m["findings"])
    p = tmp_path / "esc.tar"
    with tarfile.open(p, "w") as tf:
        ti = tarfile.TarInfo("a/evil")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../../../etc"
        tf.addfile(ti)
        ti = tarfile.TarInfo("a/ok")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../b"
        tf.addfile(ti)
    m = run_analysis(p)
    f = next(f for f in m["findings"] if f["rule_id"] == "archive-escaping-symlink")
    assert "a/evil" in f["evidence"][0]["value"] and len(f["evidence"]) == 1


def test_ext_preserves_original_modes(fixtures, tmp_path):
    if "ext4" not in fixtures:
        pytest.skip("mkfs.ext4 unavailable")
    ex, res = extract(fixtures["ext4"], tmp_path / "w")
    bb = next(a for a in res.artifacts if a.name == "/bin/busybox")
    assert bb.mode == 0o4755
    cloud = next(a for a in res.artifacts if a.name == "/etc/app/cloud.conf")
    assert cloud.mode == 0o666
    # ...but on disk nothing is setuid/world-writable
    assert not (ex.path_of(bb.id).stat().st_mode & 0o4000)


# ---------------- regressions for the security review findings ----------------
def test_ext_duplicate_entry_cannot_write_through_symlink(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("original\n")
    img = factory.ext_duplicate_entry_attack(tmp_path / "evil.img", victim)
    if img is None:
        pytest.skip("mke2fs unavailable")
    ex, res = extract(img, tmp_path / "w")
    assert victim.read_text() == "original\n"
    assert all_files_inside(tmp_path / "w")
    assert any(link.kind == "symlink" for link in res.links)


def test_unexpected_errors_are_contained(tmp_path):
    # Truncated GPT header used to raise struct.error and abort the whole scan.
    gpt = bytearray(520)
    gpt[510:512] = b"\x55\xaa"
    gpt[512:520] = b"EFI PART"
    p = tmp_path / "gpt_short.img"
    p.write_bytes(bytes(gpt))
    zp = tmp_path / "outer.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("disk.img", bytes(gpt))
        zf.writestr("etc/shadow", "root::0:0:::\n")
    ex, res = extract(zp, tmp_path / "w")
    inner = next(a for a in res.artifacts if a.name == "/disk.img")
    assert inner.extraction == "failed"
    assert any(a.name == "/etc/shadow" for a in res.artifacts)


def test_lzma_huge_dictionary_is_rejected_not_fatal(tmp_path):
    import lzma
    # xz stream whose LZMA2 filter requests a 1.5 GiB dictionary.
    data = lzma.compress(b"x" * 1000, format=lzma.FORMAT_XZ,
                         filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1536 * 1024 * 1024}])
    p = tmp_path / "bigdict.xz"
    p.write_bytes(data)
    ex, res = extract(p, tmp_path / "w")
    assert res.artifacts[0].extraction == "failed"
    assert "LZMAError" in res.artifacts[0].extraction_note or "Memory" in res.artifacts[0].extraction_note


def test_concatenated_xz_streams(tmp_path):
    import lzma
    p = tmp_path / "multi.xz"
    p.write_bytes(lzma.compress(b"first-") + lzma.compress(b"second"))
    ex, res = extract(p, tmp_path / "w")
    assert ex.path_of(res.artifacts[1].id).read_bytes() == b"first-second"


def test_partial_results_survive_a_bad_trailing_member(tmp_path):
    p = tmp_path / "collide.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("etc/shadow", "root::0:0:::\n")
        zf.writestr("x", "file")
        zf.writestr("x/y", "collides with file x")
    ex, res = extract(p, tmp_path / "w")
    assert res.artifacts[0].extraction == "ok"
    assert {"/etc/shadow", "/x"} <= {a.name for a in res.artifacts}
    assert any("collision" in w for w in res.warnings)

    bomb = tmp_path / "bombtail.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("etc/shadow", "root::0:0:::\n")
        zf.writestr("zeros.bin", b"\0" * (8 * 1024 * 1024))
    ex, res = extract(bomb, tmp_path / "w2", max_ratio=20, ratio_min_bytes=1024 * 1024)
    assert res.artifacts[0].extraction == "partial"
    assert any(a.name == "/etc/shadow" for a in res.artifacts)


def test_link_following_unpackers_refused_outside_container(tmp_path, monkeypatch):
    monkeypatch.delenv("DFA_IN_SANDBOX", raising=False)
    p = tmp_path / "fs.jffs2"
    p.write_bytes(b"\x85\x19" + b"\0" * 64)
    ex = Extractor(tmp_path / "w", Limits())
    ex._external_tools["jefferson"] = "/bin/true"
    res = ex.run(p, "fs.jffs2")
    assert res.artifacts[0].extraction == "unsupported"
    assert "container sandbox" in res.artifacts[0].extraction_note


@pytest.mark.parametrize("key", ["ubi", "jffs2"])
def test_ubi_jffs2_extraction_in_container_mode(fixtures, tmp_path, monkeypatch, key):
    import shutil as sh
    tool = {"ubi": "ubireader_extract_files", "jffs2": "jefferson"}[key]
    if key not in fixtures or not sh.which(tool):
        pytest.skip(f"{key} fixture or {tool} unavailable")
    monkeypatch.setenv("DFA_IN_SANDBOX", "1")
    ex, res = extract(fixtures[key], tmp_path / "w")
    names = {a.name for a in res.artifacts}
    assert "/etc/shadow" in names, (res.warnings, names)
    assert all_files_inside(tmp_path / "w")
