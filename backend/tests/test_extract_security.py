import gzip
import io
import os
import shutil
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


@pytest.mark.skipif(not shutil.which("cpio"), reason="GNU cpio not installed")
def test_permission_image_carries_original_modes(tmp_path):
    """FwAnalyzer reads permissions from a cpio written by the extractor: setuid bits, owners, empty and
    world-writable directories and symlinks come from the archive metadata, never from files on disk."""
    import io
    import subprocess
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        def add(name, data=b"", mode=0o644, kind=tarfile.REGTYPE, link="", uid=0):
            ti = tarfile.TarInfo(name)
            ti.type, ti.mode, ti.uid, ti.linkname, ti.size = kind, mode, uid, link, len(data)
            tf.addfile(ti, io.BytesIO(data) if data else None)
        for d in ("etc", "bin", "tmp"):
            add(d, mode=0o1777 if d == "tmp" else 0o755, kind=tarfile.DIRTYPE)
        add("etc/passwd", b"root:x:0:0::/root:/bin/sh\n")
        add("bin/su", b"\x7fELF" + bytes(60), mode=0o4755)
        add("bin/sh", kind=tarfile.SYMTYPE, link="busybox")
        add("bin/my tool", b"x")  # whitespace: FwAnalyzer cannot parse it, so it is left out (and counted)
    p = tmp_path / "rootfs.tar"
    p.write_bytes(buf.getvalue())
    from dfa.core.extract import Extractor
    from dfa.core.limits import Limits
    res = Extractor(tmp_path / "w", Limits()).run(p, "rootfs.tar")
    fs = next(f for f in res.filesystems if f["type"] == "tar")
    assert fs["mode_image_skipped"] == 1
    listing = subprocess.run(["sh", "-c", f"cpio -tvn --quiet < '{tmp_path / 'w' / fs['mode_image']}'"],
                             capture_output=True, text=True).stdout
    rows = {line.split()[-1] if "->" not in line else line.split()[-3]: line for line in listing.splitlines()}
    assert rows["bin/su"].startswith("-rwsr-xr-x")
    assert rows["tmp"].startswith("drwxrwxrwt")  # empty directory, only known from the tar header
    assert rows["bin/sh"].startswith("l") and "-> busybox" in rows["bin/sh"]
    assert "." in rows
    assert fs["special_dirs"] == {"/tmp": 0o1777}  # for reporting which bit FwAnalyzer's offender has
    assert not (tmp_path / "w").rglob("su") or all(not (f.stat().st_mode & 0o4000) for f in (tmp_path / "w").rglob("su"))


def test_generated_hostile_archives_keep_extraction_invariants(tmp_path):
    """Property check with seeded random tar/zip archives: traversal and absolute names, links to /etc, hard
    links, devices, FIFOs, setuid modes, control characters, duplicates. After every run nothing exists outside
    the work directory, nothing below it is a link or special file, nothing is setuid/setgid or world-writable,
    and the extractor either completes or raises one of its declared errors (scripts-level version: 1,500).
    Some names carry bytes that are not UTF-8 (tar: surrogateescape; zip: flagged UTF-8 anyway): every reported
    name must still be valid UTF-8 and no archive may be left unextracted because of one."""
    import io
    import os
    import random
    import stat
    import tarfile
    import warnings
    import zipfile

    from dfa.core.extract import Extractor
    from dfa.core.formats.simplefs import FormatError
    from dfa.core.limits import LimitExceeded, Limits
    rng = random.Random(20261105)
    pieces = ["..", ".", "", "etc", "bin", "a b", "x‮y", "été", "CON", "-rf", "~", "a" * 300, "\x01c",
              "back\\slash", "c:", "dir", "dir/../..", "//", "./..", "MARK", "MARK"]

    def name() -> str:
        n = "/".join(rng.choice(pieces) for _ in range(rng.randint(1, 5)))
        n = ("/" + n) if rng.random() < 0.2 else n
        return ("../" * rng.randint(1, 8) + "escape") if rng.random() < 0.1 else n[:600]

    produced = 0
    for i in range(120):
        case = tmp_path / f"c{i}"
        (case / "canary").mkdir(parents=True)
        src = case / ("in.tar" if i % 5 < 3 else "in.zip")
        buf = io.BytesIO()
        if src.suffix == ".tar":
            with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
                for _ in range(rng.randint(1, 10)):
                    ti = tarfile.TarInfo(name().replace("MARK", "M\udc80RK"))  # byte 0x80, surrogateescape
                    ti.type = rng.choice([tarfile.REGTYPE] * 4 + [tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE,
                                                                   tarfile.CHRTYPE, tarfile.FIFOTYPE])
                    ti.mode = rng.choice([0o644, 0o4755, 0o2755, 0o777, 0o7777])
                    data = b""
                    if ti.type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                        ti.linkname = rng.choice(["/etc/passwd", "../../../../etc/shadow", name(), "/"])
                    elif ti.type == tarfile.REGTYPE:
                        data = rng.randbytes(rng.randint(0, 512))
                        ti.size = len(data)
                    tf.addfile(ti, io.BytesIO(data) if data else None)
        else:
            with warnings.catch_warnings(), zipfile.ZipFile(buf, "w") as zf:
                warnings.simplefilter("ignore")  # duplicate names are part of the test
                for _ in range(rng.randint(1, 10)):
                    zi = zipfile.ZipInfo(name())
                    zi.create_system, zi.external_attr = 3, rng.choice([0o100644, 0o104755, 0o120777, 0o010644]) << 16
                    zf.writestr(zi, rng.choice([b"/etc/passwd", b"../../../x", rng.randbytes(64)]))
            raw = bytearray(buf.getvalue().replace(b"MARK", b"M\x80RK"))  # same length: offsets stay valid
            if rng.random() < 0.7:  # flag every name UTF-8, as a tool that always sets the flag would
                for sig, at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
                    j = raw.find(sig)
                    while j >= 0:
                        raw[j + at + 1] |= 0x08
                        j = raw.find(sig, j + 4)
            buf = io.BytesIO(bytes(raw))
        src.write_bytes(buf.getvalue())
        work = case / "work"
        try:
            res = Extractor(work, Limits()).run(src, src.name)
        except (FormatError, LimitExceeded, ValueError) as exc:
            assert not isinstance(exc, UnicodeError), (i, exc)
            res = None
        if res:
            produced += len(res.artifacts) - 1
            for a in res.artifacts:
                a.name.encode("utf-8"), a.path.encode("utf-8")  # storable in SQLite, servable as JSON
                assert "UnicodeDecodeError" not in (a.extraction_note or ""), (i, a.extraction_note)
            for ln in res.links:
                ln.path.encode("utf-8"), (ln.target or "").encode("utf-8")
        assert not any((case / "canary").iterdir()) and set(os.listdir(case)) <= {"canary", "work", src.name}, i
        for dirpath, dirnames, filenames in os.walk(work):
            for n in dirnames + filenames:
                st = os.lstat(os.path.join(dirpath, n))
                assert stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode), (i, n)
                assert not st.st_mode & 0o6002, (i, n, oct(st.st_mode))
    assert produced > 60  # the archives really were extracted (most hostile members are rejected by design)


def test_permission_image_for_unix_zip_root_filesystems(tmp_path):
    """A root filesystem shipped as a zip made on Unix keeps its modes in the permission image; a zip without
    Unix modes gets none (an image full of default modes would make permission checks look clean)."""
    import subprocess
    import zipfile

    from dfa.core.extract import Extractor
    from dfa.core.limits import Limits

    def make(path, unix):
        with zipfile.ZipFile(path, "w") as zf:
            for name, mode, data in (("etc/", 0o40755, b""), ("bin/", 0o40755, b""), ("tmp/", 0o41777, b""),
                                     ("etc/passwd", 0o100644, b"root:x:0:0::/root:/bin/sh\n"),
                                     ("bin/su", 0o104755, b"\x7fELF" + bytes(60))):
                zi = zipfile.ZipInfo(name)
                zi.create_system = 3 if unix else 0
                zi.external_attr = (mode << 16) if unix else (0x10 if name.endswith("/") else 0)
                zf.writestr(zi, data)
    make(tmp_path / "unix.zip", True)
    res = Extractor(tmp_path / "w1", Limits()).run(tmp_path / "unix.zip", "unix.zip")
    fs = next(f for f in res.filesystems if f["type"] == "zip")
    assert fs["unix_modes"] and fs["special_dirs"] == {"/tmp": 0o1777}
    listing = subprocess.run(["sh", "-c", f"cpio -tvn --quiet < '{tmp_path / 'w1' / fs['mode_image']}'"],
                             capture_output=True, text=True).stdout
    rows = {line.split()[-1]: line for line in listing.splitlines()}
    assert rows["bin/su"].startswith("-rwsr-xr-x") and rows["tmp"].startswith("drwxrwxrwt")
    make(tmp_path / "dos.zip", False)
    res = Extractor(tmp_path / "w2", Limits()).run(tmp_path / "dos.zip", "dos.zip")
    fs = next(f for f in res.filesystems if f["type"] == "zip")
    assert "mode_image" not in fs and "unix_modes" not in fs


def test_names_that_are_not_utf8_get_one_visible_name_on_disk_and_in_the_manifest(tmp_path):
    """Non-UTF-8 bytes in member names (tar via safe_member_path, external tools via the tree walk) are shown
    as a literal \\xNN, and the file on disk carries that same name, so the adapters can open what is reported."""
    import io
    import subprocess
    import tarfile
    bad = b"user\x80dir".decode("utf-8", "surrogateescape")
    src = tmp_path / "t.tar"
    with tarfile.open(src, "w", format=tarfile.GNU_FORMAT, encoding="utf-8", errors="surrogateescape") as tf:
        for name in (f"home/{bad}/a.txt", f"home/{bad}/a\\b.txt"):  # the backslash is a Windows separator
            ti = tarfile.TarInfo(name)
            ti.size = 2
            tf.addfile(ti, io.BytesIO(b"hi"))
        ln = tarfile.TarInfo(f"home/{bad}/link")
        ln.type, ln.linkname = tarfile.SYMTYPE, f"/{bad}"
        tf.addfile(ln)
    ex, res = extract(src, tmp_path / "w")
    names = {a.name for a in res.artifacts if a.origin == "extracted"}
    assert names == {"/home/user\\x80dir/a.txt", "/home/user\\x80dir/a/b.txt"}
    for a in res.artifacts:
        assert ex.path_of(a.id).is_file() and "\\x80" in str(ex.path_of(a.id)) or a.origin != "extracted"
    assert [(ln.path, ln.target) for ln in res.links] == [("home/user\\x80dir/link", "/user\\x80dir")]
    if not shutil.which("mksquashfs"):
        pytest.skip("mksquashfs unavailable")
    tree = tmp_path / "tree"
    os.makedirs(os.fsencode(tree) + b"/etc/bad\x80dir")
    with open(os.fsencode(tree) + b"/etc/bad\x80dir/f\xffile", "wb") as fp:
        fp.write(b"data")
    with open(os.fsencode(tree) + b"/etc/user\\x80dir", "wb") as fp:  # already the escaped spelling
        fp.write(b"x")
    with open(os.fsencode(tree) + b"/etc/user\x80dir", "wb") as fp:
        fp.write(b"y")
    img = tmp_path / "fs.squashfs"
    subprocess.run(["mksquashfs", str(tree), str(img), "-noappend", "-quiet"], check=True, capture_output=True)
    ex, res = extract(img, tmp_path / "w2")
    files = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
    assert files == {"/etc/bad\\x80dir/f\\xffile": b"data", "/etc/user\\x80dir": b"x", "/etc/user\\x80dir~1": b"y"}
    import json
    json.dumps([a.name for a in res.artifacts], ensure_ascii=False).encode("utf-8")


def _zip_with_bad_utf8_flagged_name(prefix: bytes = b"") -> bytes:
    import struct
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("etc/userXdir/id_rsa", b"key")
        zf.writestr("etc/\u00e9t\u00e9.txt", b"summer")  # valid UTF-8, flagged by zipfile itself
        zf.writestr("etc/passwd", b"root:x:0:0::/root:/bin/sh\n")
    data = bytearray(prefix + buf.getvalue().replace(b"userXdir", b"user\x80dir"))
    for sig, flag_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = data.find(sig)
        (flags,) = struct.unpack_from("<H", data, i + flag_at)
        struct.pack_into("<H", data, i + flag_at, flags | 0x800)
    return bytes(data)


def test_zip_entry_flagged_utf8_with_a_name_that_is_not_does_not_hide_the_archive(tmp_path):
    """zipfile rejects the whole archive when one UTF-8-flagged name is not UTF-8, which would leave every
    member unanalysed; such names are read as bytes instead and shown with \\xNN escapes."""
    import hashlib
    src = tmp_path / "fw.zip"
    src.write_bytes(_zip_with_bad_utf8_flagged_name())
    with pytest.raises(UnicodeDecodeError):
        zipfile.ZipFile(src)
    before = hashlib.sha256(src.read_bytes()).hexdigest()
    ex = Extractor(tmp_path / "w", Limits())
    res = ex.run(src, "fw.zip")
    files = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
    assert files == {"/etc/user\\x80dir/id_rsa": b"key", "/etc/\u00e9t\u00e9.txt": b"summer",
                     "/etc/passwd": b"root:x:0:0::/root:/bin/sh\n"}
    assert any("flagged UTF-8 are not UTF-8" in w for w in res.warnings)
    assert hashlib.sha256(src.read_bytes()).hexdigest() == before  # the upload itself is never modified


def test_zip_name_fixes_follow_prepended_data(tmp_path):
    from dfa.core.formats import zipnames
    src = tmp_path / "fw.bin"
    src.write_bytes(_zip_with_bad_utf8_flagged_name(prefix=b"VENDOR-HEADER" * 9))
    patches, shown = zipnames.utf8_flag_fixes(src)
    assert len(patches) == 2 and list(shown.values()) == ["etc/user\udc80dir/id_rsa"]
    with zipnames.PatchedReader(src, patches) as fp, zipfile.ZipFile(fp) as zf:
        assert [shown.get(zi.orig_filename, zi.filename) for zi in zf.infolist()] == [
            "etc/user\udc80dir/id_rsa", "etc/\u00e9t\u00e9.txt", "etc/passwd"]
        assert zf.read(zf.infolist()[0]) == b"key"
    src.write_bytes(b"not a zip at all")
    with pytest.raises(ValueError):
        zipnames.utf8_flag_fixes(src)


def test_name_fixes_cannot_make_zipfile_read_a_decoy_directory(tmp_path):
    """Third review: a UTF-8-flagged entry whose local header 'lies' in the archive comment, at "PK\\x03\\x04\\x14PK
    \\x0d\\x06...": clearing its flag bit there formed an end record, and zipfile read a decoy central directory
    (listing only decoy.txt); the real member, with the secrets, went unanalysed. Local headers outside the space
    before the central directory are not patched, and zipfile must read the directory that was walked."""
    import struct
    import zlib

    def lfh(name, data, method, raw):  # noqa: ANN001, ANN202
        return struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, method, 0, 0, zlib.crc32(data), len(raw),
                           len(data), len(name), 0) + name + raw

    def cdh(name, data, method, raw, flags, off, comment=b""):  # noqa: ANN001, ANN202
        return struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, flags, method, 0, 0, zlib.crc32(data),
                           len(raw), len(data), len(name), 0, len(comment), 0, 0, 0, off) + name + comment

    secret = b"aws_access_key_id = AKIAWERTYUIOPLKJHGFD\n"
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    real_raw = co.compress(secret) + co.flush()
    decoy = b"nothing to see\n"
    l_real, l_decoy = lfh(b"real.txt", secret, 8, real_raw), lfh(b"decoy.txt", decoy, 0, decoy)
    cd_start = len(l_real) + len(l_decoy)
    cd_real = cdh(b"real.txt", secret, 8, real_raw, 0, 0)
    decoy_entry = bytearray(cdh(b"decoy.txt", decoy, 0, decoy, 0, len(l_real)))
    struct.pack_into("<H", decoy_entry, 32, 22 + 5)
    cd_size = len(cd_real) + len(cdh(b"bad\xff.txt", b"", 0, b"", 0x800, 0, bytes(decoy_entry)))
    comment_pos = cd_start + cd_size + 22
    cd_bad = cdh(b"bad\xff.txt", b"", 0, b"", 0x800, comment_pos, bytes(decoy_entry))
    decoy_cd_off = comment_pos + 5 - (len(decoy_entry) + 22 + 5)
    fake = (b"PK\x03\x04\x14PK\x0d\x06" + struct.pack("<HHHHII", 0, 0, 1, 1, len(decoy_entry) + 22 + 5, decoy_cd_off)
            + b"\x00" * 5)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 2, 2, cd_size, cd_start, len(fake))
    src = tmp_path / "e.zip"
    src.write_bytes(l_real + l_decoy + cd_real + cd_bad + eocd + fake)
    ex = Extractor(tmp_path / "w", Limits())
    res = ex.run(src, src.name)
    files = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
    assert files == {"/real.txt": secret}, (files, res.warnings)
    assert any("could not be read" in w for w in res.warnings)  # the entry with no local header, alone


def test_one_damaged_zip_member_does_not_hide_the_others(tmp_path):
    """A member that cannot be read (bad CRC, unsupported method) failed the whole archive: every other member
    went unanalysed. It is reported and skipped now."""
    import struct
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a/broken.bin", b"A" * 64)
        zf.writestr("etc/shadow", b"root::19000:0:99999:7:::\n")
        zf.writestr("b/method.bin", b"B" * 64)
    data = bytearray(b.getvalue())
    i = data.find(b"A" * 64)
    data[i] ^= 1  # CRC mismatch
    for sig, at in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):  # b/method.bin: compression method 99 (AES)
        j = data.rfind(sig, 0, data.find(b"PK\x01\x02") if sig == b"PK\x03\x04" else len(data))
        struct.pack_into("<H", data, j + at, 99)
    src = tmp_path / "fw.zip"
    src.write_bytes(bytes(data))
    ex = Extractor(tmp_path / "w", Limits())
    res = ex.run(src, src.name)
    names = {a.name for a in res.artifacts if a.origin == "extracted"}
    assert "/etc/shadow" in names, (names, res.warnings)
    assert "/a/broken.bin" in names  # its data was read (bad CRC): kept, as unzip keeps it
    # incomplete, so the archive's own bytes are still scanned and the gap is reported
    assert res.artifacts[0].extraction == "partial" and "2 member(s) could not be read" in res.artifacts[0].extraction_note


def _zip64_archive(files: dict[bytes, bytes], prefix: bytes = b"") -> bytes:
    """A stored zip with zip64 end records, whose central directory gives each local header offset only in a
    zip64 extra field (as for members past 4 GiB). Names containing 0x80 are flagged UTF-8."""
    import struct
    import zlib
    body, cd = b"", b""
    for name, data in files.items():
        flags, crc, off = 0x800 if b"\x80" in name else 0, zlib.crc32(data), len(body)
        body += struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 45, flags, 0, 0, 0x21, crc, len(data), len(data),
                            len(name), 0) + name + data
        extra = struct.pack("<HHQ", 1, 8, off)
        cd += struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 0x031E, 45, flags, 0, 0, 0x21, crc, len(data),
                          len(data), len(name), len(extra), 0, 0, 0, 0o100644 << 16, 0xFFFFFFFF) + name + extra
    end64 = len(body) + len(cd)
    return (prefix + body + cd
            + struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, len(files), len(files), len(cd), len(body))
            + struct.pack("<4sIQI", b"PK\x06\x07", 0, end64, 1)
            + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0))


def test_zip64_or_miscounted_zip_with_a_bad_utf8_flagged_name_is_extracted(tmp_path):
    """The name fix-up refused zip64 end records and walked the central directory by the entry count the end
    record declares (zipfile walks it by size): such archives were reported as failed, every member unanalysed."""
    import struct
    import subprocess
    key, passwd = b"key", b"root:x:0:0::/root:/bin/sh\n"
    good = _zip64_archive({b"etc/userXdir/id_rsa": key, b"etc/passwd": passwd}, b"VENDOR-HEADER" * 9)
    with zipfile.ZipFile(io.BytesIO(good)) as zf:  # zipfile itself reads the hand-made zip64 layout
        assert zf.read("etc/userXdir/id_rsa") == key and zf.read("etc/passwd") == passwd
    cases = {"zip64.zip": _zip64_archive({b"etc/user\x80dir/id_rsa": key, b"etc/passwd": passwd}, b"VENDOR" * 9)}
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as zf:
        zf.writestr("etc/passwd", passwd)
        zf.writestr("etc/userXdir/id_rsa", key)
    miscounted = bytearray(b.getvalue().replace(b"userXdir", b"user\x80dir"))
    end = miscounted.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", miscounted, end + 8, 1, 1)  # declares one entry; zipfile reads both
    if shutil.which("zip"):  # the reference tool's zip64 layout (zip -fz: zip64 end records and size fields)
        tree = tmp_path / "t"
        (tree / "etc" / "userXdir").mkdir(parents=True)
        (tree / "etc" / "userXdir" / "id_rsa").write_bytes(key)
        (tree / "etc" / "passwd").write_bytes(passwd)
        subprocess.run(["zip", "-q", "-fz", "-r", str(tmp_path / "ref.zip"), "etc"], cwd=tree, check=True)
        ref = bytearray((tmp_path / "ref.zip").read_bytes().replace(b"userXdir", b"user\x80dir"))
        assert b"PK\x06\x06" in ref
        cases["info-zip.zip"] = ref
    cases["miscounted.zip"] = miscounted
    for name, data in cases.items():
        data = bytearray(data)
        for sig, flag_at, name_at, len_at in ((b"PK\x03\x04", 6, 30, 26), (b"PK\x01\x02", 8, 46, 28)):
            i = data.find(sig)
            while i >= 0:  # flag every name that is not UTF-8 as UTF-8, in both headers
                (n,) = struct.unpack_from("<H", data, i + len_at)
                if b"\x80" in data[i + name_at:i + name_at + n]:
                    struct.pack_into("<H", data, i + flag_at, struct.unpack_from("<H", data, i + flag_at)[0] | 0x800)
                i = data.find(sig, i + 4)
        src = tmp_path / name
        src.write_bytes(bytes(data))
        with pytest.raises(UnicodeDecodeError):
            zipfile.ZipFile(src)
        ex = Extractor(tmp_path / f"w_{name}", Limits())
        res = ex.run(src, name)
        assert res.artifacts[0].extraction == "ok", (name, res.artifacts[0].extraction_note)
        files = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
        assert files == {"/etc/user\\x80dir/id_rsa": key, "/etc/passwd": passwd}, name


def test_zip_name_fixes_locate_zip64_directories_as_older_zipfile_versions_do(tmp_path, monkeypatch):
    """zipfile versions before the zip64 locator checks give the classic end record's position for a zip64
    archive (and subtract the zip64 records themselves); the patches must land in the same places."""
    from dfa.core.formats import zipnames
    src = tmp_path / "fw.bin"
    src.write_bytes(_zip64_archive({b"etc/user\x80dir/id_rsa": b"key", b"etc/passwd": b"x"}, b"HDR" * 7))
    patches, _shown = zipnames.utf8_flag_fixes(src)
    with src.open("rb") as fp:
        current = zipnames._central_directory(fp)
    real = zipfile._EndRecData

    def older(fp):  # noqa: ANN001, ANN202
        endrec = real(fp)
        endrec[zipfile._ECD_LOCATION] = src.stat().st_size - 22
        return endrec
    monkeypatch.setattr(zipfile, "_EndRecData", older)  # (only the end-record half of an older zipfile)
    with src.open("rb") as fp:
        assert zipnames._central_directory(fp) == current
    assert len(patches) == 2 and current[2] == len(b"HDR" * 7)


def test_data_before_a_zip_that_ends_the_file_is_analysed(tmp_path, run_analysis):
    """Third review: a file ending in a zip is identified as the zip; its handler reads only the members, so the data
    before them (a vendor header, a self-extracting stub, the rest of a flash dump) was never analysed. With zip64
    end records accepted, an image ending in a zip64 archive lost its analysis the same way."""
    key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + b"C" * 64 + b"\n-----END RSA PRIVATE KEY-----\n"
    prefix = _noise(8192, 51) + b"\x00aws AKIAHGFDSAMNBVCXZLKJ\x00" + key + _noise(8192, 52)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as zf:
        zf.writestr("readme.txt", "release notes\n")
    for name, archive in (("classic.bin", b.getvalue()), ("zip64.bin", _zip64_archive({b"readme.txt": b"notes"}))):
        src = tmp_path / name
        src.write_bytes(prefix + archive)
        manifest = run_analysis(src)
        assert manifest["identification"]["format"] == "zip", name
        rules = {f["rule_id"] for f in manifest["findings"]}
        assert {"token-aws-access-key", "pem-private-key"} <= rules, (name, rules)
    src = tmp_path / "padded.bin"  # padding before the archive is no artifact
    src.write_bytes(b"\xff" * 4096 + b.getvalue())
    res = Extractor(tmp_path / "w_padded", Limits()).run(src, src.name)
    assert res.artifacts[0].format == "zip" and not any(a.name.startswith("leading_") for a in res.artifacts)


def test_zip64_after_a_header_or_inside_a_raw_image_is_analysed(tmp_path, run_analysis):
    """A zip64 archive (sizes in its zip64 end record) after a vendor header or a self-extracting stub was taken
    for raw data, and one inside a raw image was not carved: nothing in it was analysed."""
    key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + b"A" * 64 + b"\n-----END RSA PRIVATE KEY-----\n"
    archive = _zip64_archive({b"etc/ssl/server.key": key, b"etc/passwd": b"root::0:0::/root:/bin/sh\n"})
    cases = {"prefixed.bin": (b"VENDOR-HEADER" * 9 + archive, "zip"),
             "sfx.bin": (_noise(8192, 21) + archive, "zip"),
             "flash.bin": (_noise(8192, 22) + archive + _noise(4096, 23), "raw")}
    for name, (data, fmt) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        ex = Extractor(tmp_path / f"w_{name}", Limits())
        res = ex.run(src, name)
        assert res.artifacts[0].format == fmt, name
        files = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
        assert files.get("/etc/ssl/server.key") == key, (name, res.warnings)
        rules = {f["rule_id"] for f in run_analysis(src)["findings"]}
        assert {"pem-private-key", "empty-password"} <= rules, (name, rules)


def _cpio_modes(path: Path) -> dict[str, tuple[int, int, int]]:
    """name -> (mode, uid, gid) from a newc cpio archive."""
    data, out, i = path.read_bytes(), {}, 0
    while data[i:i + 6] == b"070701":
        f = [int(data[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        name = data[i + 110:i + 110 + f[11] - 1].decode("utf-8", "replace")
        i = (i + 110 + f[11] + 3) & ~3
        i = (i + f[6] + 3) & ~3
        if name == "TRAILER!!!":
            break
        out[name] = (f[1], f[2], f[3])
    return out


def test_squashfs_keeps_original_permissions_when_extracted_unprivileged(tmp_path, monkeypatch, run_analysis):
    """unsquashfs run by an unprivileged user, as in the sandbox, drops setuid/setgid bits and owners (observed
    with unsquashfs 4.6.1 as nobody: /bin/su 4755 in the image, 0755 on disk). The original modes now come from
    'unsquashfs -lln', for the built-in setuid check and for FwAnalyzer's permission image."""
    import subprocess
    if not shutil.which("mksquashfs"):
        pytest.skip("mksquashfs unavailable")
    tree = tmp_path / "tree"
    for d in ("etc", "bin", "tmp", "usr/share"):
        (tree / d).mkdir(parents=True)
    (tree / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    for name, mode in (("su", 0o4755), ("wall", 0o2755), ("ls", 0o755), ("bad\udc80", 0o4711)):
        p = tree / "bin" / name
        p.write_bytes(b"\x7fELF-not-really")
        os.chmod(p, mode)
    os.chmod(tree / "tmp", 0o1777)
    img = tmp_path / "rootfs.squashfs"
    subprocess.run(["mksquashfs", str(tree), str(img), "-noappend", "-quiet"], check=True, capture_output=True)

    real_run_tool = Extractor._run_tool

    def as_unprivileged(self, art, cmd, out, env=None):  # what unsquashfs leaves behind for a non-root user
        real_run_tool(self, art, cmd, out, env)
        for p in out.rglob("*"):
            if not p.is_symlink():
                os.chmod(p, p.lstat().st_mode & 0o1777)
    monkeypatch.setattr(Extractor, "_run_tool", as_unprivileged)

    ex = Extractor(tmp_path / "w", Limits())
    res = ex.run(img, "rootfs.squashfs")
    modes = {a.name: a.mode for a in res.artifacts if a.origin == "extracted"}
    assert (modes["/bin/su"], modes["/bin/wall"], modes["/bin/ls"]) == (0o4755, 0o2755, 0o755)
    assert modes["/bin/bad\\x80"] == 0o4711  # listing names are escaped like the renamed file on disk
    fs = next(f for f in res.filesystems if f["type"] == "squashfs")
    assert fs["unix_modes"] and fs["special_dirs"]["/tmp"] == 0o1777
    cpio = _cpio_modes(tmp_path / "w" / fs["mode_image"])
    assert cpio["bin/su"][0] == 0o104755 and cpio["bin/wall"][0] == 0o102755 and cpio["tmp"][0] == 0o041777
    if os.geteuid() == 0:  # mksquashfs records the builder's owner; only root builds root-owned images
        assert cpio["bin/su"][1:] == (0, 0)

    manifest = run_analysis(img)
    setuid = [f for f in manifest["findings"] if f["rule_id"] == "setuid-files"]
    assert setuid and {"/bin/su", "/bin/bad\\x80"} <= {e["value"].split(" (mode")[0] for e in setuid[0]["evidence"]}


def test_tar_members_after_an_end_marker_or_a_damaged_header_are_not_hidden(tmp_path):
    """tarfile (and GNU tar) stop silently at an end-of-archive marker or a header with a bad checksum, so
    content placed after one went unanalysed (archive reported "ok"). Reading continues past them, with a
    warning; a pax global header (git archive) is not mistaken for skipped data."""
    def tar(members: list[tuple[str, bytes]], **kw) -> bytes:
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w", **kw) as tf:
            for name, data in members:
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        return b.getvalue()

    bad = bytearray(tar([("etc/junk", b"x" * 10)], format=tarfile.USTAR_FORMAT)[:1024])
    bad[148:156] = b"0000000\x00"  # wrong header checksum
    cases = {
        "normal.tar": (tar([("a", b"1"), ("b/c", b"2")], format=tarfile.PAX_FORMAT, pax_headers={"comment": "x"}),
                       {"/a", "/b/c"}, False),
        "concat.tar": (tar([("one", b"1")]) + tar([("two", b"2")]), {"/one", "/two"}, True),
        "damaged.tar": (tar([("etc/passwd", b"root::0:0::/:/bin/sh\n")])[:-1024 * 9] + bytes(bad)
                        + tar([("root/.ssh/id_rsa", b"key")]), {"/etc/passwd", "/root/.ssh/id_rsa"}, True),
    }
    for name, (data, expected, warned) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)
        assert {a.name for a in res.artifacts if a.origin == "extracted"} == expected, name
        assert any("skipped between members" in w for w in res.warnings) == warned, (name, res.warnings)


def test_compressed_streams_followed_by_padding_or_other_data(tmp_path):
    """gzip.open/lzma failed on data after the last stream that is not another one, and the whole content went
    unanalysed: 0xFF padding of an erased flash block was enough. Padding is now ignored, several members
    (with zero padding between them) are decoded, and other trailing data is analysed as an artifact of its
    own instead of being dropped. A damaged first stream still fails."""
    import gzip
    import lzma
    import subprocess

    def tar(members: list[tuple[str, bytes]]) -> bytes:
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as tf:
            for name, data in members:
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        return b.getvalue()

    rootfs = tar([("etc/passwd", b"root::0:0::/root:/bin/sh\n"), ("etc/shadow", b"root::1:0:99999:7:::\n")])
    half = len(rootfs) // 2
    cases: dict[str, tuple[bytes, set[str]]] = {
        "ff.tar.gz": (gzip.compress(rootfs, mtime=0) + b"\xff" * 4096, {"/etc/passwd", "/etc/shadow"}),
        "ff.tar.xz": (lzma.compress(rootfs) + b"\xff" * 4096, {"/etc/passwd", "/etc/shadow"}),
        "members.tar.gz": (gzip.compress(rootfs[:half], mtime=0) + b"\0" * 1000 + gzip.compress(rootfs[half:], mtime=0),
                           {"/etc/passwd", "/etc/shadow"}),
        "fake-member.tar.gz": (gzip.compress(rootfs, mtime=0) + b"\x1f\x8b" + b"not a member" * 50,
                               {"/etc/passwd", "/etc/shadow"}),
    }
    if shutil.which("mksquashfs"):
        tree = tmp_path / "hidden"
        (tree / "etc").mkdir(parents=True)
        (tree / "etc" / "hidden.conf").write_text("telnetd=1\n")
        img = tmp_path / "hidden.squashfs"
        subprocess.run(["mksquashfs", str(tree), str(img), "-noappend", "-quiet"], check=True, capture_output=True)
        cases["hidden.tar.gz"] = (gzip.compress(rootfs, mtime=0) + b"\xff" * 8192 + img.read_bytes(),
                                  {"/etc/passwd", "/etc/shadow", "/etc/hidden.conf"})
    for name, (data, expected) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)
        assert res.artifacts[0].extraction != "failed", (name, res.artifacts[0].extraction_note)
        assert {a.name for a in res.artifacts if a.origin == "extracted"} == expected, name
        trailing = [a for a in res.artifacts if a.name.startswith("trailing_")]
        assert bool(trailing) == (name in ("fake-member.tar.gz", "hidden.tar.gz")), (name, res.warnings)
        if name.startswith("ff."):
            assert res.artifacts[0].details["trailing_padding_bytes"] == 4096
    bad = bytearray(gzip.compress(rootfs, mtime=0))
    bad[20:40] = b"\x00" * 20  # damaged deflate data in the (only) member
    (tmp_path / "bad.tar.gz").write_bytes(bytes(bad))
    res = Extractor(tmp_path / "w_bad", Limits()).run(tmp_path / "bad.tar.gz", "bad.tar.gz")
    assert res.artifacts[0].extraction == "failed"


def test_zstd_frames_followed_by_padding_or_other_data(tmp_path):
    """Same as for gzip/xz: zstd failed on 0xFF padding after the last frame ("Unknown frame descriptor"). The end
    of the complete frames is found from their headers; decoding stops there."""
    zstandard = pytest.importorskip("zstandard")
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        ti = tarfile.TarInfo("etc/passwd")
        ti.size = 26
        tf.addfile(ti, io.BytesIO(b"root::0:0::/root:/bin/sh\n\n"))
    raw = b.getvalue()
    c = zstandard.ZstdCompressor(write_checksum=True)
    cases = {
        "ff.tar.zst": (c.compress(raw) + b"\xff" * 4096, False),
        "frames.tar.zst": (c.compress(raw[:5000]) + c.compress(raw[5000:]), False),
        "other.tar.zst": (c.compress(raw) + b"appended, not a frame" * 20, True),
    }
    for name, (data, trailing) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)
        assert {a.name for a in res.artifacts if a.origin == "extracted"} == {"/etc/passwd"}, (name, res.warnings)
        assert any(a.name.startswith("trailing_") for a in res.artifacts) == trailing, name
    (tmp_path / "bad.tar.zst").write_bytes(c.compress(raw)[:8] + b"\x00" * 40)
    res = Extractor(tmp_path / "w_bad", Limits()).run(tmp_path / "bad.tar.zst", "bad.tar.zst")
    assert res.artifacts[0].extraction == "failed"


def _newc(members: list[tuple[str, bytes, int]]) -> bytes:
    """A newc cpio archive: (name, data, mode) members and the trailer."""
    out = bytearray()
    for ino, (name, data, mode) in enumerate([*members, ("TRAILER!!!", b"", 0)], 1):
        raw = name.encode() + b"\x00"
        out += b"070701" + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), 0))
        out += raw + b"\x00" * (-(110 + len(raw)) % 4) + data + b"\x00" * (-len(data) % 4)
    return bytes(out + b"\x00" * (-len(out) % 512))


def test_cpio_archives_concatenated_like_an_initramfs_are_all_analysed(tmp_path):
    """The kernel unpacks every archive of an initramfs (e.g. an uncompressed early-microcode cpio followed by the
    compressed main one); extraction stopped at the first TRAILER!!!, so the root filesystem went unanalysed."""
    import gzip
    early = _newc([("kernel/x86/microcode/GenuineIntel.bin", b"ucode", 0o100644)])
    main = _newc([("etc/passwd", b"root::0:0::/root:/bin/sh\n", 0o100644), ("init", b"#!/bin/sh\n", 0o100755)])
    cases = {
        "initrd.img": (early + gzip.compress(main, mtime=0), True),
        "two.cpio": (early + b"\x00" * 1024 + main, False),
        "padded.cpio": (early + b"\x00" * 4096, False),
    }
    expected = {"initrd.img": {"/kernel/x86/microcode/GenuineIntel.bin", "/etc/passwd", "/init"},
                "two.cpio": {"/kernel/x86/microcode/GenuineIntel.bin", "/etc/passwd", "/init"},
                "padded.cpio": {"/kernel/x86/microcode/GenuineIntel.bin"}}
    for name, (data, trailing) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        ex = Extractor(tmp_path / f"w_{name}", Limits())
        res = ex.run(src, name)
        assert {a.name for a in res.artifacts if a.origin == "extracted"} == expected[name], (name, res.warnings)
        assert any(a.name.startswith("trailing_") for a in res.artifacts) == trailing, name
        fs_roots = [tmp_path / f"w_{name}" / fs["root"] for fs in res.filesystems if fs["type"] == "cpio"]
        assert fs_roots and not any(p.name.startswith("trailing_") for r in fs_roots for p in r.rglob("*"))


def test_root_filesystem_after_a_uimage_kernel_is_analysed(tmp_path):
    """Sysupgrade-style images put the root filesystem after the kernel uImage, on the next erase block; only
    the declared uImage payload was extracted, so the root filesystem went unanalysed."""
    import gzip
    import struct
    import subprocess
    import zlib
    if not shutil.which("mksquashfs"):
        pytest.skip("mksquashfs unavailable")
    tree = tmp_path / "rootfs"
    (tree / "etc").mkdir(parents=True)
    (tree / "etc" / "passwd").write_text("root::0:0::/root:/bin/ash\n")
    sqfs = tmp_path / "root.squashfs"
    subprocess.run(["mksquashfs", str(tree), str(sqfs), "-noappend", "-quiet"], check=True, capture_output=True)
    payload = gzip.compress(b"Linux version 5.4.0\x00" * 200, mtime=0)
    hdr = bytearray(struct.pack(">IIIIIIIBBBB32s", 0x27051956, 0, 0, len(payload), 0x80008000, 0x80008000,
                                zlib.crc32(payload), 5, 2, 2, 1, b"Linux-5.4.0"))
    struct.pack_into(">I", hdr, 4, zlib.crc32(bytes(hdr)))
    kernel = bytes(hdr) + payload
    img = tmp_path / "sysupgrade.bin"
    img.write_bytes(kernel + b"\xff" * (-len(kernel) % 65536) + sqfs.read_bytes())
    res = Extractor(tmp_path / "w", Limits()).run(img, img.name)
    rootfs = [a for a in res.artifacts if a.format == "squashfs"]
    assert rootfs and rootfs[0].details["carved_offset"] == "0x10000"  # starts after the 0xFF padding
    assert "/etc/passwd" in {a.name for a in res.artifacts if a.origin == "extracted"}
    plain = tmp_path / "kernel-only.bin"
    plain.write_bytes(kernel + b"\xff" * 4096)  # padding only: nothing extra
    res = Extractor(tmp_path / "w2", Limits()).run(plain, plain.name)
    assert not any(a.name.startswith("trailing_") for a in res.artifacts)


def test_data_after_a_squashfs_image_is_analysed(tmp_path):
    """In an OpenWrt-style rootfs partition the writable overlay (JFFS2, with the device's own configuration)
    follows the SquashFS on the next erase block; only the SquashFS was extracted. The trailing artifact starts on
    that erase block, past mksquashfs's zero padding and the 0xFF of erased flash."""
    import gzip
    import subprocess
    if not shutil.which("mksquashfs"):
        pytest.skip("mksquashfs unavailable")
    tree = tmp_path / "rom"
    (tree / "etc").mkdir(parents=True)
    (tree / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/ash\n")
    sqfs = tmp_path / "rom.squashfs"
    subprocess.run(["mksquashfs", str(tree), str(sqfs), "-noappend", "-quiet"], check=True, capture_output=True)
    rom = sqfs.read_bytes()
    pad = b"\xff" * (-len(rom) % 65536)
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        ti = tarfile.TarInfo("etc/shadow")
        ti.size = 24
        tf.addfile(ti, io.BytesIO(b"root:$1$changed:19000::\n"))
    overlays = {"gzip": gzip.compress(b.getvalue(), mtime=0)}
    if shutil.which("mkfs.jffs2"):
        jffs2 = tmp_path / "overlay.jffs2"
        subprocess.run(["mkfs.jffs2", "-r", str(tree), "-o", str(jffs2), "-e", "64KiB", "-l"], check=True,
                       capture_output=True)
        overlays["jffs2"] = jffs2.read_bytes()
    for fmt, overlay in overlays.items():
        img = tmp_path / f"rootfs-{fmt}.bin"
        img.write_bytes(rom + pad + overlay)
        res = Extractor(tmp_path / f"w_{fmt}", Limits()).run(img, img.name)
        trailing = [a for a in res.artifacts if a.name.startswith("trailing_") and a.origin == "carved"]
        assert len(trailing) == 1 and trailing[0].details["carved_offset"] == hex(len(rom) + len(pad)), fmt
        assert trailing[0].format == fmt, (fmt, trailing[0].format)
        if fmt == "gzip":
            assert {"/etc/passwd", "/etc/shadow"} <= {a.name for a in res.artifacts if a.origin == "extracted"}
    res = Extractor(tmp_path / "w_plain", Limits()).run(sqfs, sqfs.name)  # mksquashfs's own zero padding
    assert not any(a.name.startswith("trailing_") for a in res.artifacts)


def test_ext_names_with_quotes_newlines_or_bytes_that_are_not_utf8_are_extracted(tmp_path):
    """debugfs commands carried the names, so entries with quotes, backslashes, newlines, tabs, non-printable or
    non-UTF-8 bytes were skipped (a directory like that hid everything below it; two of them vanished without a
    warning). Listing and dumping now go by inode number."""
    import subprocess
    if not shutil.which("mkfs.ext4") or not shutil.which("debugfs"):
        pytest.skip("e2fsprogs unavailable")
    tree = os.fsencode(tmp_path / "tree")
    names = [b'a"b', b"new\nline", b"bad\x80", "nbsp x".encode(), b"tab\tname", b"esc\x1bname", b"plain"]
    os.makedirs(tree + b'/dir"x/deeper')
    for n in names:
        with open(tree + b"/" + n, "wb") as fp:
            fp.write(b"data:" + n)
    with open(tree + b'/dir"x/deeper/inner.txt', "wb") as fp:
        fp.write(b"inside a quoted directory")
    img = tmp_path / "ext.img"
    subprocess.run(["mkfs.ext4", "-q", "-F", "-d", os.fsdecode(tree), "-b", "1024", str(img), "2M"], check=True,
                   capture_output=True)
    ex = Extractor(tmp_path / "w", Limits())
    res = ex.run(img, "ext.img")
    got = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
    assert got == {'/a"b': b'data:a"b', "/new\nline": b"data:new\nline", "/bad\\x80": b"data:bad\x80",
                   "/nbsp x": "data:nbsp x".encode(), "/tab\tname": b"data:tab\tname",
                   "/esc\x1bname": b"data:esc\x1bname", "/plain": b"data:plain",
                   '/dir"x/deeper/inner.txt': b"inside a quoted directory"}
    assert not res.warnings
    assert not list((tmp_path / "w" / "files").rglob(".dump"))  # the staging directory is removed


def test_zip_after_a_vendor_header_is_extracted(tmp_path):
    """A zip that ends the file after other data (a vendor header, a self-extracting shell stub) was unrecognised
    (format detection only looked for 'PK' at offset 0), so its content went unanalysed; zipfile opens it as is."""
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as zf:
        zf.writestr("etc/passwd", "root::0:0::/root:/bin/sh\n")
    archive = b.getvalue()
    cases = {"vendor.bin": b"VNDRFW\x01\x00" + bytes(range(256)) * 4 + archive,
             "installer.sh": b"#!/bin/sh\nexec unzip -o \"$0\"\n" + archive}
    for name, data in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)
        assert res.artifacts[0].format == "zip", name
        assert res.artifacts[0].details["prepended_bytes"] == len(data) - len(archive)
        assert {a.name for a in res.artifacts if a.origin == "extracted"} == {"/etc/passwd"}, name
    # an end-of-central-directory signature alone at the end of random data is not a zip
    fake = tmp_path / "fake.bin"
    fake.write_bytes(bytes(range(256)) * 8 + b"PK\x05\x06" + b"\x00" * 6 + b"\x01\x00" + b"\x50\x00\x00\x00" * 2 + b"\x00\x00")
    assert Extractor(tmp_path / "w_fake", Limits()).run(fake, "fake.bin").artifacts[0].format != "zip"


def test_archives_that_are_not_unpacked_are_reported_not_hidden(tmp_path, run_analysis):
    """7-Zip, RAR and Cabinet archives were taken for raw data, so their content went unanalysed without a word.
    They are recognised now and reported as not unpacked (an info finding), never claimed as analysed."""
    heads = {"payload.7z": b"7z\xbc\xaf\x27\x1c\x00\x04", "payload.rar": b"Rar!\x1a\x07\x01\x00",
             "payload.cab": b"MSCF\x00\x00\x00\x00"}
    for name, head in heads.items():
        src = tmp_path / name
        src.write_bytes(head + bytes(range(256)) * 32)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)
        assert res.artifacts[0].extraction == "unsupported", name
        assert "not unpacked" in res.artifacts[0].extraction_note
        manifest = run_analysis(src)
        assert any(f["rule_id"] == "extraction-unsupported" for f in manifest["findings"]), name


def test_trailing_data_after_tar_and_the_other_compressors(tmp_path):
    """Found by review: data after a tar's end-of-archive marker, and after bzip2, lzma (alone), LZ4 and lzop data,
    was dropped without a word. It now goes through the same trailing-data check as gzip/xz/zstd: padding and a
    tiny tail (a kernel's size field) are ignored, anything else is analysed as an artifact of its own, starting
    where a known format begins."""
    import bz2
    import gzip
    import lzma
    import subprocess

    def tar(members: list[tuple[str, bytes]]) -> bytes:
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as tf:
            for name, data in members:
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        return b.getvalue()

    payload = tar([("etc/passwd", b"root::0:0::/root:/bin/sh\n")])
    tail = b"appended content, not padding " * 40
    cases: dict[str, tuple[bytes, bool]] = {
        "junk.tar": (payload + tail, True),
        "pad.tar.bz2": (bz2.compress(payload) + b"\xff" * 4096, False),
        "multi.tar.bz2": (bz2.compress(payload[:5000]) + bz2.compress(payload[5000:]), False),
        "tail.tar.bz2": (bz2.compress(payload) + tail, True),
        "tail.tar.lzma": (lzma.compress(payload, format=lzma.FORMAT_ALONE) + tail, True),
    }
    lz4 = pytest.importorskip("lz4.frame")
    cases["tail.tar.lz4"] = (lz4.compress(payload) + tail, True)
    import lz4.block
    legacy = b"\x02\x21\x4c\x18" + (lambda blk: len(blk).to_bytes(4, "little") + blk)(
        lz4.block.compress(payload, store_size=False))
    cases["kernel.lz4"] = (legacy + len(payload).to_bytes(4, "little"), False)  # size field after the data
    if shutil.which("lzop"):
        (tmp_path / "p.tar").write_bytes(payload)
        subprocess.run(["lzop", "-q", "-f", str(tmp_path / "p.tar"), "-o", str(tmp_path / "p.tar.lzo")], check=True)
        cases["tail.tar.lzo"] = ((tmp_path / "p.tar.lzo").read_bytes() + tail, True)
    for name, (data, trailing) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)
        assert res.artifacts[0].extraction != "failed", (name, res.artifacts[0].extraction_note)
        if name != "kernel.lz4":
            assert "/etc/passwd" in {a.name for a in res.artifacts if a.origin == "extracted"}, name
        carved = [a for a in res.artifacts if a.name.startswith("trailing_") and a.origin == "carved"]
        assert bool(carved) == trailing, (name, res.warnings)
        if carved:  # starts exactly where the appended content does
            assert ex_bytes(tmp_path / f"w_{name}", carved[0]).startswith(tail[:30]), name

    if shutil.which("mkfs.ext4"):  # an ext image after padding starts on its block, boot-block zeros included
        img = tmp_path / "ext.img"
        tree = tmp_path / "exttree"
        (tree / "etc").mkdir(parents=True)
        (tree / "etc" / "group").write_text("root:x:0:\n")
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(tree), "-b", "1024", str(img), "1M"], check=True,
                       capture_output=True)
        gz = gzip.compress(payload, mtime=0)
        src = tmp_path / "with-ext.tar.gz"
        src.write_bytes(gz + b"\x00" * (-len(gz) % 4096) + img.read_bytes())
        res = Extractor(tmp_path / "w_ext", Limits()).run(src, src.name)
        carved = [a for a in res.artifacts if a.name.startswith("trailing_") and a.origin == "carved"]
        assert carved and carved[0].format == "ext" and carved[0].details["carved_offset"] == hex(-(-len(gz) // 4096) * 4096)


def ex_bytes(work: Path, art) -> bytes:
    return (work / art.path).read_bytes()


def test_data_appended_to_an_executable_is_analysed(tmp_path):
    """An ordinary ELF file was analysed as it was, so a payload appended after its own data (what self-extracting
    and packed programs, or a dropper, do) was never looked at. It is now analysed as an artifact of its own; a
    signed kernel module's appended signature is recognised and only recorded."""
    import gzip
    elf = Path("/usr/bin/true")
    if not elf.is_file() or elf.read_bytes()[:4] != b"\x7fELF":
        pytest.skip("no ELF executable to build the sample from")
    from dfa.core.extract import MODULE_SIG_MARKER, _elf_data_end
    base = elf.read_bytes()
    with elf.open("rb") as fp:
        assert _elf_data_end(fp, len(base)) == len(base)  # a normal executable has no overlay
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        ti = tarfile.TarInfo("etc/passwd")
        ti.size = 26
        tf.addfile(ti, io.BytesIO(b"root::0:0::/root:/bin/sh\n\n"))
    import struct

    def signed(elf: bytes, id_type: int = 2) -> bytes:  # PKCS#7 blob, struct module_signature, marker
        der = b"\x30\x82" + (512).to_bytes(2, "big") + bytes(range(256)) * 2
        info = bytes([0, 0, id_type, 0, 0, 0, 0, 0]) + struct.pack(">I", len(der))
        return elf + der + info + MODULE_SIG_MARKER

    rel = bytearray(base)
    rel[16:18] = (1).to_bytes(2, "little" if base[5] == 1 else "big")  # ET_REL, as a kernel module is
    cases = {"dropper": (base + gzip.compress(b.getvalue(), mtime=0), True),
             "module.ko": (signed(bytes(rel)), False),
             "fake-sig.ko": (signed(bytes(rel), id_type=0), True),  # not a PKCS#7 module signature: an overlay
             "sig-on-exec": (signed(base), True),  # an executable is not a module: an overlay
             "plain": (base, False)}
    for name, (data, overlay) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)
        carved = [a for a in res.artifacts if a.name.startswith("trailing_") and a.origin == "carved"]
        assert bool(carved) == overlay, (name, res.warnings)
        if overlay:
            assert carved[0].details["carved_offset"] == hex(len(base))
        if name == "dropper":
            assert carved[0].format == "gzip"
            assert "/etc/passwd" in {a.name for a in res.artifacts if a.origin == "extracted"}
    mod = Extractor(tmp_path / "w_mod2", Limits()).run(tmp_path / "module.ko", "module.ko").artifacts[0]
    assert mod.details["module_signature_bytes"] == len(cases["module.ko"][0]) - len(base)


def test_data_after_a_filesystem_image_that_declares_its_size(tmp_path):
    """ext, FAT, ROMFS and CramFS images declare their size; whatever followed them in the file (another
    partition, an overlay) was ignored. It now goes through the trailing-data check."""
    import gzip
    import subprocess
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        ti = tarfile.TarInfo("etc/passwd")
        ti.size = 26
        tf.addfile(ti, io.BytesIO(b"root::0:0::/root:/bin/sh\n\n"))
    appended = gzip.compress(b.getvalue(), mtime=0)
    images: dict[str, bytes] = {"romfs": factory.romfs({"rcS": b"echo hello\n"})}
    tree = tmp_path / "tree"
    (tree / "etc").mkdir(parents=True)
    (tree / "etc" / "hostname").write_text("drone\n")
    if shutil.which("mkfs.ext4"):
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(tree), "-b", "1024", str(tmp_path / "e.img"), "1M"],
                       check=True, capture_output=True)
        images["ext"] = (tmp_path / "e.img").read_bytes()
    if shutil.which("mkfs.cramfs"):
        subprocess.run(["mkfs.cramfs", str(tree), str(tmp_path / "c.img")], check=True, capture_output=True)
        images["cramfs"] = (tmp_path / "c.img").read_bytes()
    if shutil.which("mformat"):
        (tmp_path / "f.img").write_bytes(b"\0" * 1440 * 1024)
        subprocess.run(["mformat", "-i", str(tmp_path / "f.img"), "-f", "1440", "::"], check=True, capture_output=True)
        images["fat"] = (tmp_path / "f.img").read_bytes()
    for fmt, image in images.items():
        src = tmp_path / f"{fmt}-plus.bin"
        src.write_bytes(image + appended)
        res = Extractor(tmp_path / f"w_{fmt}", Limits()).run(src, src.name)
        assert res.artifacts[0].format == fmt, (fmt, res.artifacts[0].format)
        carved = [a for a in res.artifacts if a.name.startswith("trailing_") and a.origin == "carved"]
        assert carved and carved[0].details["carved_offset"] == hex(len(image)), (fmt, res.warnings)
        assert "/etc/passwd" in {a.name for a in res.artifacts if a.origin == "extracted"}, fmt
        plain = tmp_path / f"{fmt}.bin"
        plain.write_bytes(image)
        res = Extractor(tmp_path / f"w3_{fmt}", Limits()).run(plain, plain.name)
        assert not any(a.name.startswith("trailing_") for a in res.artifacts), fmt


def test_zip_inside_a_raw_image_is_carved(tmp_path):
    """Raw flash dumps are the most common input, but the carver did not know zip: an archive stored inside one
    (a configuration backup, an update package) went unanalysed. Zips are carved back from their end-of-central-
    directory record, which says where the archive starts; a lone end signature is not taken for one."""
    import random
    rng = random.Random(7)

    def noise(n: int) -> bytes:
        data = bytearray(rng.randbytes(n))
        for magic in (b"PK", b"hsqs", b"\x1f\x8b", b"CROM", b"-rom1fs-", b"070701", b"\x7fELF", b"\xfd7zXZ"):
            data = data.replace(magic, b"\x00" * len(magic))  # keep the noise free of other signatures
        return bytes(data)

    def zipped(comment: bytes = b"") -> bytes:
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as zf:
            zf.writestr("backup/etc/shadow", "root:$1$x$y:19000::::::\n")
            zf.comment = comment
        return b.getvalue()

    for name, archive in (("plain", zipped()), ("comment", zipped(b"config backup 2026-11-05"))):
        img = tmp_path / f"flash-{name}.bin"
        img.write_bytes(noise(8192) + archive + noise(4096))
        ex = Extractor(tmp_path / f"w_{name}", Limits())
        res = ex.run(img, img.name)
        carved = [a for a in res.artifacts if a.origin == "carved" and a.format == "zip"]
        assert carved and carved[0].details["carved_offset"] == hex(8192), (name, res.warnings)
        assert ex.path_of(carved[0].id).read_bytes() == archive  # exactly the archive, comment included
        assert "/backup/etc/shadow" in {a.name for a in res.artifacts if a.origin == "extracted"}
    lone = tmp_path / "lone.bin"
    lone.write_bytes(noise(8192) + b"PK\x05\x06" + b"\x00" * 6 + b"\x01\x00" + b"\x2e\x00\x00\x00" * 2 + b"\x00\x00"
                     + noise(4096))
    res = Extractor(tmp_path / "w_lone", Limits()).run(lone, "lone.bin")
    assert not [a for a in res.artifacts if a.origin == "carved"]


def test_appended_data_is_reported_as_a_finding(tmp_path, run_analysis):
    """Appended data is analysed on its own, and its presence is reported too: appended to an executable as a
    suspicious pattern (packers, self-extracting programs, droppers), after an image or archive as information."""
    import gzip
    elf = Path("/usr/bin/true")
    if not elf.is_file() or elf.read_bytes()[:4] != b"\x7fELF":
        pytest.skip("no ELF executable to build the sample from")
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        ti = tarfile.TarInfo("etc/passwd")
        ti.size = 26
        tf.addfile(ti, io.BytesIO(b"root::0:0::/root:/bin/sh\n\n"))
    payload = gzip.compress(b.getvalue(), mtime=0)
    dropper = tmp_path / "updater"
    dropper.write_bytes(elf.read_bytes() + payload)
    found = {f["rule_id"]: f for f in run_analysis(dropper)["findings"]}
    f = found["appended-to-executable"]
    assert (f["classification"], f["severity"]) == ("suspicious", "low")
    assert f["evidence"][0]["value"].startswith(hex(len(elf.read_bytes())) + ":")
    archive = tmp_path / "rootfs.tar"
    archive.write_bytes(b.getvalue() + b"appended blob, not padding " * 20)
    found = {f["rule_id"]: f for f in run_analysis(archive)["findings"]}
    assert found["data-after-image"]["classification"] == "info"
    assert "appended-to-executable" not in found
    plain = tmp_path / "plain"
    plain.write_bytes(elf.read_bytes())
    assert not {"appended-to-executable", "data-after-image"} & {f["rule_id"] for f in run_analysis(plain)["findings"]}


def test_7z_inside_a_raw_image_is_carved_and_reported(tmp_path, run_analysis):
    """7-Zip archives are not unpacked, but one inside a raw image is carved (its signature header gives the exact
    length and is CRC-protected) so that the report names it as content that was not analysed."""
    import random
    import struct
    import zlib
    rng = random.Random(11)
    noise = bytearray(rng.randbytes(8192))
    for magic in (b"7z", b"PK", b"hsqs", b"\x1f\x8b", b"CROM", b"-rom1fs-", b"070701", b"\x7fELF", b"\xfd7zXZ"):
        noise = noise.replace(magic, b"\x00" * len(magic))
    body = rng.randbytes(300)  # packed streams and header: not parsed, only measured
    fields = struct.pack("<QQI", len(body) - 40, 40, zlib.crc32(body[-40:]))
    archive = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(fields)) + fields + body
    img = tmp_path / "flash.bin"
    img.write_bytes(bytes(noise) + archive + bytes(noise[:4096]))
    res = Extractor(tmp_path / "w", Limits()).run(img, img.name)
    carved = [a for a in res.artifacts if a.origin == "carved" and a.format == "7z"]
    assert carved and carved[0].details["carved_offset"] == hex(8192) and carved[0].size == len(archive)
    assert carved[0].extraction == "unsupported"
    findings = run_analysis(img)["findings"]
    assert any(f["rule_id"] == "extraction-unsupported" and "7-Zip" in f["title"] for f in findings)
    broken = bytearray(archive)
    broken[12] ^= 1  # header CRC no longer matches: not carved
    img.write_bytes(bytes(noise) + bytes(broken) + bytes(noise[:4096]))
    res = Extractor(tmp_path / "w2", Limits()).run(img, img.name)
    assert not [a for a in res.artifacts if a.origin == "carved"]


# ---------------------------------------------------------------- second review (each case failed before)
def _key_payload() -> bytes:
    import gzip
    key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + b"A" * 64 + b"\n-----END RSA PRIVATE KEY-----\n"
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        ti = tarfile.TarInfo("etc/ssl/server.key")
        ti.size = len(key)
        tf.addfile(ti, io.BytesIO(key))
    return gzip.compress(b.getvalue(), mtime=0)


def _noise(n: int, seed: int) -> bytes:
    import random
    data = bytearray(random.Random(seed).randbytes(n))
    for magic in (b"PK", b"7z", b"hsqs", b"\x1f\x8b", b"CROM", b"-rom1fs-", b"070701", b"\x7fELF", b"\xfd7zXZ",
                  b"\x27\x05\x19\x56"):
        data = data.replace(magic, b"\x00" * len(magic))
    return bytes(data)


def test_hostile_elf_headers_cannot_fail_or_flood_a_scan(tmp_path, run_analysis):
    """The ELF overlay check ran outside the per-container error handling and before the depth limit: a 64-bit
    table entry size of 32 (struct.error), a header size of 0 (the whole file looked appended: 985 copies, then
    RecursionError) or exhausting the budget failed the whole scan; a chain of headers nested past max_depth."""
    import struct

    def elf64(phentsize: int = 56, phnum: int = 0, ehsize: int = 64) -> bytes:
        return (b"\x7fELF\x02\x01\x01" + b"\x00" * 9
                + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64 if phnum else 0, 0, 0, ehsize, phentsize, phnum, 64, 0, 0))

    cases = {"phent32.elf": elf64(phentsize=32, phnum=1) + b"\x01" * 32 + b"x" * 64,
             "ehsize0.elf": elf64(ehsize=0) + b"A" * 4096,
             "chain.elf": b"".join(elf64() for _ in range(300))}
    for name, data in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        res = Extractor(tmp_path / f"w_{name}", Limits()).run(src, name)  # must not raise
        assert max(a.depth for a in res.artifacts) <= Limits().max_depth, name
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as zf:
        zf.writestr("bin/odd", cases["phent32.elf"])
        zf.writestr("etc/shadow", "root:$1$abc$DEFghijklmnopqrstuv12/:19000:0:99999:7:::\n")
    fw = tmp_path / "fw.zip"
    fw.write_bytes(b.getvalue())
    manifest = run_analysis(fw)
    assert "fatal_error" not in manifest and any(f["rule_id"] == "static-password-hash" for f in manifest["findings"])
    elf = Path("/usr/bin/true")
    if elf.is_file() and elf.read_bytes()[:4] == b"\x7fELF":  # overlay while the byte budget runs out
        t = io.BytesIO()
        with tarfile.open(fileobj=t, mode="w") as tf:
            for name, data in (("big.bin", os.urandom(3 * 1024 * 1024)), ("bin/tool", elf.read_bytes() + _key_payload())):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        (tmp_path / "budget.tar").write_bytes(t.getvalue())
        res = Extractor(tmp_path / "w_budget", Limits(max_total_bytes=2 * 1024 * 1024)).run(tmp_path / "budget.tar", "b")
        assert res.limits_hit


def test_overlay_check_covers_mcu_elfs_and_unvalidated_signature_markers(tmp_path, run_analysis):
    """A Cortex-M ELF went to its own handler, which never looked past its segments, and any file ending in the
    module-signature marker was taken for a signed module: in both cases an appended payload went unanalysed."""
    import struct

    def arm_elf(profile: bytes) -> bytes:  # minimal ARM executable with an .ARM.attributes CPU profile
        attrs = b"A" + struct.pack("<I", 17) + b"aeabi\x00" + b"\x01" + struct.pack("<I", 7) + b"\x07" + profile
        shstr = b"\x00.ARM.attributes\x00.shstrtab\x00"
        code = bytes(range(256))
        code_off, attr_off = 52 + 32, 52 + 32 + 256
        str_off = attr_off + len(attrs)
        sh_off = (str_off + len(shstr) + 3) & ~3
        eh = b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, 0x08000000, 52, sh_off,
                                                                  0x05000000, 52, 32, 1, 40, 3, 2)
        ph = struct.pack("<IIIIIIII", 1, code_off, 0x08000000, 0x08000000, 256, 256, 5, 4)
        body = eh + ph + code + attrs + shstr
        body += b"\x00" * (sh_off - len(body))
        return body + b"\x00" * 40 + struct.pack("<IIIIIIIIII", 1, 0x70000003, 0, 0, attr_off, len(attrs), 0, 0, 1, 0) \
            + struct.pack("<IIIIIIIIII", 17, 3, 0, 0, str_off, len(shstr), 0, 0, 1, 0)

    from dfa.core.extract import MODULE_SIG_MARKER
    samples = {"mcu.elf": arm_elf(b"M") + _key_payload(),
               "marked": arm_elf(b"A") + _key_payload() + MODULE_SIG_MARKER}
    for name, data in samples.items():
        src = tmp_path / name
        src.write_bytes(data)
        rules = {f["rule_id"] for f in run_analysis(src)["findings"]}
        assert {"appended-to-executable", "pem-private-key"} <= rules, (name, rules)


def test_data_after_a_damaged_image_is_still_examined_and_names_do_not_clash(tmp_path, run_analysis):
    """Data after a declared-size image was examined only if the image's own handler succeeded, and a container
    whose name sanitised to 'trailing' collided with the trailing-data directory (the payload was lost)."""
    import gzip
    import struct
    good = factory.romfs({"rcS": b"echo hello\n"})
    bad = bytearray(good)
    first = struct.unpack_from(">I", bad, 32 + 4)[0]  # the first file header of /etc points to itself: a loop
    nxt = struct.unpack_from(">I", bad, first)[0]
    struct.pack_into(">I", bad, first, (first & ~0xF) | (nxt & 0xF))
    cases = {"romfs_loop": bytes(bad) + _key_payload(), "trailing.gz": gzip.compress(good + _key_payload(), mtime=0)}
    for name, data in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        rules = {f["rule_id"] for f in run_analysis(src)["findings"]}
        assert {"data-after-image", "pem-private-key"} <= rules, (name, rules)


def test_a_failed_image_is_carved_like_raw_data(tmp_path, run_analysis):
    """A forged SquashFS superblock claiming the rest of a flash dump (unsquashfs rejects it: "Bad id count") hid
    everything after it from carving, and an image or archive that failed to unpack hid everything inside it.
    Such an image is now carved like raw data, within the extent it declares (data after it stays trailing data)."""
    import struct
    import subprocess
    if not shutil.which("mksquashfs"):
        pytest.skip("mksquashfs unavailable")
    tree = tmp_path / "rom"
    (tree / "etc").mkdir(parents=True)
    (tree / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/ash\n")
    sqfs = tmp_path / "rom.squashfs"
    subprocess.run(["mksquashfs", str(tree), str(sqfs), "-noappend", "-quiet"], check=True, capture_output=True)
    rom = sqfs.read_bytes()
    used = struct.unpack_from("<Q", rom, 40)[0]
    payload, noise = _key_payload(), _noise(8192, 31)
    flash = bytearray(noise + rom + b"\xff" * (-len(rom) % 65536) + payload + _noise(4096, 32))
    struct.pack_into("<Q", flash, len(noise) + 40, len(flash) - len(noise))  # bytes_used: the rest of the dump
    inflated = bytearray(rom[:used] + payload + b"\x00" * 4096)
    struct.pack_into("<Q", inflated, 40, len(inflated))  # claims the appended payload as its own
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("fw/rootfs.tar.gz", payload)
        zf.writestr("fw/pad.bin", _noise(8192, 33))
    damaged = bytearray(b.getvalue())
    cd = damaged.rfind(b"PK\x01\x02")
    damaged[cd + 3] = 0  # central directory signature damaged: zipfile rejects the whole archive
    pad = b"\xff" * (-len(rom) % 65536)
    chain = bytearray(noise + rom + pad + rom + pad + payload + _noise(4096, 34))  # a forged claim inside another
    for at in (len(noise), len(noise) + len(rom) + len(pad)):
        struct.pack_into("<Q", chain, at + 40, len(chain) - at)
    cases = {"flash.bin": flash, "inflated.sqfs": inflated, "damaged.zip": damaged, "chain.bin": chain}
    for name, data in cases.items():
        src = tmp_path / name
        src.write_bytes(bytes(data))
        ex = Extractor(tmp_path / f"w_{name}", Limits())
        res = ex.run(src, name)
        assert any(a.extraction == "failed" for a in res.artifacts), name  # the failure is still reported
        assert ex.budget.bytes_written <= 3 * len(data), name  # forged claims do not nest into copies of copies
        files = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
        assert b"BEGIN RSA PRIVATE KEY" in files.get("/etc/ssl/server.key", b""), (name, res.warnings)
        rules = [f["rule_id"] for f in run_analysis(src)["findings"]]
        assert rules.count("pem-private-key") == 1, (name, rules)  # once: not also as trailing data
    small = tmp_path / "small.sqfs"  # a small failed image is carved too (unlike raw data, at any size)
    small.write_bytes(bytes(inflated[:used]) + payload)
    struct.pack_into("<Q", buf := bytearray(small.read_bytes()), 40, len(buf))
    small.write_bytes(bytes(buf))
    ex = Extractor(tmp_path / "w_small", Limits())
    res = ex.run(small, small.name)
    files = {a.name: ex.path_of(a.id).read_bytes() for a in res.artifacts if a.origin == "extracted"}
    assert res.artifacts[0].extraction == "failed" and b"BEGIN RSA" in files.get("/etc/ssl/server.key", b"")


def test_a_secret_in_a_carved_region_is_reported_once(tmp_path, run_analysis):
    """A plaintext key inside a region carved verbatim out of a binary (a stored zip member in a flash dump, an
    executable's overlay) was reported twice: at its offset in the binary and again for the extracted file."""
    key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + b"B" * 64 + b"\n-----END RSA PRIVATE KEY-----\n"
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("etc/ssl/server.key", key)
    cases = {"flash.bin": (_noise(8192, 41) + b.getvalue() + _noise(4096, 42), "/etc/ssl/server.key"),
             "plain.bin": (_noise(8192, 43) + key + _noise(4096, 44), "plain.bin")}  # not carved: found in place
    elf = Path("/usr/bin/true")
    if elf.is_file() and elf.read_bytes()[:4] == b"\x7fELF":
        cases["tool"] = (elf.read_bytes() + b.getvalue(), "/etc/ssl/server.key")
    for name, (data, where) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        keys = [f for f in run_analysis(src)["findings"] if f["rule_id"] == "pem-private-key"]
        assert len(keys) == 1 and keys[0]["affected_component"].endswith(where), (name, keys)


def test_secrets_outside_every_unpacked_file_are_still_reported(tmp_path, run_analysis):
    """Third review: suppressing the byte ranges carved into children (to report a key once) hid secrets that no
    child analyses - a zip's bytes between members, a uImage's name field - and lost keys across range edges or
    beyond the 2 MiB a text child is read. Only a secret a descendant reports itself is dropped from a container."""
    import base64
    import random
    import struct
    import zlib
    rnd = random.Random(1)

    def filler(n: int) -> bytes:  # not printable, no carve magics
        return bytes(rnd.choice(range(0x80, 0x100)) for _ in range(n))

    def pem(body: str | None = None) -> bytes:
        body = body or base64.b64encode(rnd.randbytes(600)).decode()
        return ("-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
                + "\n-----END RSA PRIVATE KEY-----\n").encode()

    name, data = b"a.txt", b"hello world\n"
    lfh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, zlib.crc32(data), len(data), len(data),
                      len(name), 0) + name + data
    gap = b"\x00" * 16 + b"\naws_key AKIAQWERTYUIOPASDFGH\n" + pem() + b"\x00" * 16  # between member and directory
    cd = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, zlib.crc32(data), len(data), len(data),
                     len(name), 0, 0, 0, 0, 0, 0) + name
    zgap = lfh + gap + cd + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(cd), len(lfh + gap), 0)
    payload = filler(2048)
    hdr = bytearray(struct.pack(">IIIIIIIBBBB", 0x27051956, 0, 0, len(payload), 0x80008000, 0x80008000,
                                zlib.crc32(payload), 5, 2, 2, 0) + b"AKIAQAZWSXEDCRFVTGBY".ljust(32, b"\x00"))
    struct.pack_into(">I", hdr, 4, zlib.crc32(bytes(hdr)))
    ehdr = bytearray(52)  # an ELF whose extent ends in printable bytes; the key follows outside it
    ehdr[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHI", ehdr, 16, 2, 3, 1)
    struct.pack_into("<I", ehdr, 32, 0x200)
    struct.pack_into("<HHHHHH", ehdr, 40, 52, 32, 0, 40, 1, 0)
    elf = bytes(ehdr) + filler(0x200 - 52) + b"\x00" * 8 + b"       export AWS_ACCESS_KEY_ID="
    body = base64.b64encode(rnd.randbytes(600)).decode()
    cases = {"zip_gap.bin": (filler(4096) + zgap + filler(4096), {"token-aws-access-key", "pem-private-key"}),
             "uimage_name.bin": (filler(4096) + bytes(hdr) + payload + filler(4096), {"token-aws-access-key"}),
             "edge.bin": (filler(4096) + elf + b"AKIAMNBVCXZLKJHGFDSA\n" + filler(4096), {"token-aws-access-key"}),
             "pem_cpio.bin": (filler(4096) + pem(body[:400] + "07070100" + body[408:]) + b"\x00" * 32 + b"TRAILER!!!"
                              + filler(4096), {"pem-private-key"})}
    true = Path("/usr/bin/true")
    if true.is_file() and true.read_bytes()[:4] == b"\x7fELF":  # a text overlay; the key 2.5 MiB into it
        line = b"2026-11-05 12:00:00 info: service heartbeat ok\n"
        text = bytearray(line * (3 * 1024**2 // len(line)))
        at = 2 * 1024**2 + 512 * 1024 - (2 * 1024**2 + 512 * 1024) % len(line)
        text[at:at + len(line)] = b"aws key AKIALKJHGFDSAPOIUYTR ok........ \n"[:len(line) - 1] + b"\n"
        cases["text_overlay"] = (true.read_bytes() + bytes(text), {"token-aws-access-key"})
    for name, (data, want) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        rules = {f["rule_id"] for f in run_analysis(src)["findings"]}
        assert want <= rules, (name, rules)


def test_a_real_image_behind_a_forged_header_or_a_flood_of_magics_is_carved(tmp_path, run_analysis, monkeypatch):
    """Third review: a forged copy of the real SquashFS superblock, claiming the rest of the dump, hid the real root
    filesystem behind it (objects of the failed image's own kind were not carved from it); and 256 signatures of
    any kind (even ones that could not be valid) silently ended carving, so a gzip'd root filesystem after them
    was never found - in a failed image as in any raw dump."""
    import gzip
    import struct
    import subprocess

    from dfa.core import extract
    if not shutil.which("mksquashfs"):
        pytest.skip("mksquashfs unavailable")
    tree = tmp_path / "rootfs"
    (tree / "etc").mkdir(parents=True)
    (tree / "etc" / "shadow").write_text("root::19000:0:99999:7:::\n")
    sq = tmp_path / "rootfs.sqsh"
    subprocess.run(["mksquashfs", str(tree), str(sq), "-noappend", "-quiet"], check=True, capture_output=True)
    real, noise = sq.read_bytes(), _noise(8192, 61)
    forged = bytearray(real[:96])
    struct.pack_into("<Q", forged, 40, 4096 + len(real) + len(noise))  # the rest of the dump
    struct.pack_into("<I", forged, 4, 0x7FFFFFFF)  # an inode count unsquashfs rejects
    shadow = b"root::19000:0:99999:7:::\n"
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        ti = tarfile.TarInfo("etc/shadow")
        ti.size = len(shadow)
        tf.addfile(ti, io.BytesIO(shadow))
    gz = gzip.compress(b.getvalue(), mtime=0)
    flooded = bytearray(96)
    flooded[:4] = b"hsqs"
    struct.pack_into("<I", flooded, 4, 0x7FFFFFFF)
    struct.pack_into("<H", flooded, 28, 4)
    flood = b"hsqs\x00\x00\x00\x00" * 300
    struct.pack_into("<Q", flooded, 40, 96 + len(flood) + 4096 + len(gz) + 8192)
    cases = {"forged_front.bin": noise + bytes(forged) + b"\xff" * (4096 - 96) + real + noise,
             "flood_failed.bin": bytes(flooded) + flood + _noise(4096, 62) + gz + _noise(8192, 63),
             "flood_raw.bin": _noise(8192, 64) + flood + _noise(4096, 65) + gz + _noise(8192, 66)}
    for name, data in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        rules = {f["rule_id"] for f in run_analysis(src)["findings"]}
        assert "empty-password" in rules, (name, rules)
    monkeypatch.setattr(extract, "MAX_CARVE_ATTEMPTS", 50)  # a flood past the limit is reported, never silent
    src = tmp_path / "flood_raw.bin"
    checked = b"".join(b"\x1f\x8b\x08\x00" + bytes([i]) * 12 for i in range(60))  # 60 gzip headers, none valid
    src.write_bytes(_noise(8192, 67) + checked + _noise(4096, 68) + gz + _noise(4096, 69))
    res = Extractor(tmp_path / "w_limit", Limits()).run(src, src.name)
    assert "max_carve_candidates" in res.limits_hit and any("carving stopped" in w for w in res.warnings)


def test_carving_stays_disjoint_bounded_and_unhidden(tmp_path, run_analysis):
    """Zips carved back from forged end records nested and overlapped (100 near-full copies from 1 MB, past the
    carve limit); a stored member was also carved on its own (two findings for one key); a forged 7z header
    claiming the rest of the image hid everything after it."""
    import struct
    import zlib
    n = 30
    img = bytearray(_noise(64 * (n + 1), 1))
    starts = [64 * (n + 1 - k) for k in range(1, n + 1)]
    for s in starts:
        img[s:s + 4] = b"PK\x03\x04"
    cd = len(img)
    img += b"PK\x01\x02" + _noise(42, 2) + _noise(200_000, 3)
    for s in starts:
        end = len(img)
        img += b"PK\x05\x06" + b"\x00" * 6 + struct.pack("<HIIH", 1, end - cd, cd - s, 0)
    img += _noise(4096, 4)
    (tmp_path / "zipend.bin").write_bytes(bytes(img))
    ex = Extractor(tmp_path / "w_zipend", Limits())
    res = ex.run(tmp_path / "zipend.bin", "zipend.bin")
    # the outer forged zip fails; carved like raw data, its first zip (a real archive behind a forged end record
    # would be recovered) is taken once, fails too and is not carved again: never copies of copies
    assert len([a for a in res.artifacts if a.origin == "carved"]) <= 2
    assert ex.budget.bytes_written <= 2 * len(img)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as zf:
        zf.writestr("update/rootfs.tar.gz", _key_payload(), compress_type=zipfile.ZIP_STORED)
    (tmp_path / "stored.bin").write_bytes(_noise(8192, 5) + b.getvalue() + _noise(4096, 6))
    keys = [f for f in run_analysis(tmp_path / "stored.bin")["findings"] if f["rule_id"] == "pem-private-key"]
    assert len(keys) == 1 and len(keys[0]["evidence"]) == 1
    rest = _noise(2048, 7) + _key_payload() + _noise(4096, 8)
    fields = struct.pack("<QQI", len(rest) - 8, 8, 0)  # claims everything after the header
    fake7z = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(fields)) + fields
    (tmp_path / "fake7z.bin").write_bytes(_noise(8192, 9) + fake7z + rest)
    rules = {f["rule_id"] for f in run_analysis(tmp_path / "fake7z.bin")["findings"]}
    assert {"extraction-unsupported", "pem-private-key"} <= rules


# ---------------------------------------------------------------- fourth review (each case failed before)
def _zip_of_members(members: list[dict], base: int = 0) -> bytes:
    """A hand-made zip: members are dicts of name, data, method (0/8), crc (override), cd_off_delta, lfh_name and
    lfh_flags; the offsets written in the central directory are relative to ``base``."""
    import struct
    import zlib
    body, cds = b"", b""
    for m in members:
        data, method = m["data"], m.get("method", 0)
        if method == 8:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            raw = co.compress(data) + co.flush()
        else:
            raw = data
        crc = m.get("crc", zlib.crc32(data))
        off = len(body)
        body += struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, m.get("lfh_flags", 0), method, 0, 0, crc, len(raw),
                            len(data), len(m.get("lfh_name", m["name"])), 0) + m.get("lfh_name", m["name"]) + raw
        cds += struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, method, 0, 0, crc, len(raw), len(data),
                           len(m["name"]), 0, 0, 0, 0, 0, off + m.get("cd_off_delta", 0)) + m["name"]
    return body + cds + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(members), len(members), len(cds),
                                    len(body) + base, 0)


def _pem_block(seed: int, encrypted: bool = False) -> bytes:
    import base64
    import random
    body = base64.b64encode(random.Random(seed).randbytes(600)).decode()
    head = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n" if encrypted else ""
    return ("-----BEGIN RSA PRIVATE KEY-----\n" + head + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
            + "\n-----END RSA PRIVATE KEY-----\n").encode()


_SHADOW = b"root::19000:0:99999:7:::\n"


def _tar_of(files: dict[str, bytes]) -> bytes:
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return b.getvalue()


def test_zip_members_that_cannot_be_read_and_data_outside_the_members_are_analysed(tmp_path, run_analysis):
    """Fourth review: a member that could not be read was dropped while the zip stayed 'ok' (its bytes then went
    unscanned: no finding at all); some member errors still failed the whole archive; and data outside the members
    - after a fake start signature, an earlier zip, or before a flood of members - was never analysed."""
    import gzip
    secrets = b"\x00\x01aws AKIAQWERTYUIOPLKJHGF\x00" + _pem_block(71)
    t = io.BytesIO()
    with tarfile.open(fileobj=t, mode="w") as tf:
        for name, data in (("etc/shadow", _SHADOW), ("etc/ssl/key.pem", _pem_block(72))):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    payload = gzip.compress(t.getvalue(), mtime=0)
    benign = [{"name": b"readme.txt", "data": b"release notes\n"}]
    fake = b"PK\x03\x04"
    cases = {
        "badcrc.zip": (_zip_of_members(benign + [{"name": b"keys/device.bin", "data": secrets, "crc": 0x12345678}]),
                       {"token-aws-access-key", "pem-private-key", "extraction-partial"}),
        "badcrc_deflated.zip": (_zip_of_members(benign + [{"name": b"etc/shadow", "data": _SHADOW, "method": 8,
                                                           "crc": 1}]), {"empty-password"}),
        "lfh_utf8.zip": (_zip_of_members([{"name": b"bad\xff", "data": b"x", "lfh_flags": 0x800},
                                          {"name": b"etc/shadow", "data": _SHADOW, "method": 8}]), {"empty-password"}),
        "fake_start.bin": (_noise(16, 73) + fake + payload + _zip_of_members(
            [dict(m, cd_off_delta=len(fake + payload)) for m in benign], base=len(fake + payload)),
                           {"empty-password", "pem-private-key"}),
        "zip_zip.bin": (_zip_of_members([{"name": b"etc/shadow", "data": _SHADOW, "method": 8}]) + _noise(64, 74)
                        + _zip_of_members(benign), {"empty-password"}),
    }
    for name, (data, want) in cases.items():
        src = tmp_path / name
        src.write_bytes(data)
        rules = {f["rule_id"] for f in run_analysis(src)["findings"]}
        assert want <= rules, (name, rules)
    src = tmp_path / "crowded.bin"  # data before the archive is analysed before its members use up the budget
    src.write_bytes(_noise(16, 75) + payload + _zip_of_members([{"name": b"f%03d" % i, "data": b""} for i in range(80)]))
    rules = {f["rule_id"] for f in run_analysis(src, Limits(max_files=40))["findings"]}
    assert {"empty-password", "pem-private-key"} <= rules, rules


def test_forged_claims_floods_and_adjusted_self_extractors(tmp_path, run_analysis):
    """Fourth review: two forged superblocks (or a decoy image) in front of the real root filesystem, and a forged
    end record appended to a real zip, still hid it; overlapping gzip headers over one endless deflate stream made a
    5 KB upload run past the sandbox timeout (each candidate decoded up to 512 MiB); a self-extractor whose offsets
    'zip -A' adjusted was not recognised."""
    import struct
    import subprocess
    import time
    import zlib
    rules_of = lambda p, lim=None: {f["rule_id"] for f in run_analysis(p, lim)["findings"]}  # noqa: E731
    key = _pem_block(81)
    real_zip = _zip_of_members([{"name": b"etc/shadow", "data": _SHADOW, "method": 8},
                                {"name": b"etc/ssl/k.pem", "data": key, "method": 8}])
    cd_off = struct.unpack_from("<I", real_zip, len(real_zip) - 6)[0]
    forged_end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(real_zip) - cd_off, cd_off, 0)
    (tmp_path / "zipend.zip").write_bytes(real_zip + forged_end)
    assert {"empty-password", "pem-private-key"} <= rules_of(tmp_path / "zipend.zip")
    if shutil.which("mksquashfs"):
        tree = tmp_path / "rootfs"
        (tree / "etc").mkdir(parents=True)
        (tree / "etc" / "shadow").write_bytes(_SHADOW)
        sq = tmp_path / "r.sqsh"
        subprocess.run(["mksquashfs", str(tree), str(sq), "-noappend", "-quiet"], check=True, capture_output=True)
        real, noise = sq.read_bytes(), _noise(8192, 82)

        def forged(rest: int) -> bytes:
            sb = bytearray(real[:96])
            struct.pack_into("<Q", sb, 40, rest)
            struct.pack_into("<I", sb, 4, 0x7FFFFFFF)
            return bytes(sb) + b"\xff" * (4096 - 96)
        rest = 2 * 4096 + len(real) + len(noise)
        (tmp_path / "double.bin").write_bytes(noise + forged(rest) + forged(rest - 4096) + real + noise)
        assert "empty-password" in rules_of(tmp_path / "double.bin")
    stream = zlib.compressobj(9, zlib.DEFLATED, -15)
    endless = stream.compress(b"\x00" * (3 * 1024 * 1024)) + stream.flush(zlib.Z_SYNC_FLUSH)  # no final block
    n = 60
    heads = b"".join(b"\x1f\x8b\x08\x04" + b"\x00" * 4 + b"\x00\x03" + struct.pack("<H", 16 * (n - i) - 12)
                     + b"\x00" * 4 for i in range(n))
    real = gzip.compress(_tar_of({"etc/shadow": _SHADOW}), mtime=0)
    (tmp_path / "flood.bin").write_bytes(_noise(4096, 83) + heads + endless + _noise(4096, 84) + real)
    t0 = time.monotonic()  # the headers share one test-decode of the stream: what follows them is carved
    found = run_analysis(tmp_path / "flood.bin", Limits(max_file_bytes=1024 * 1024))
    assert time.monotonic() - t0 < 30 and "empty-password" in {f["rule_id"] for f in found["findings"]}
    if shutil.which("zip"):
        d = tmp_path / "sfx"
        (d / "etc").mkdir(parents=True)
        (d / "etc" / "shadow").write_bytes(_SHADOW)
        subprocess.run(["zip", "-q", "-r", str(tmp_path / "a.zip"), "etc"], cwd=d, check=True)
        (tmp_path / "sfx.bin").write_bytes(_noise(4096, 85) + (tmp_path / "a.zip").read_bytes())
        subprocess.run(["zip", "-q", "-A", str(tmp_path / "sfx.bin")], check=True, capture_output=True)
        assert "empty-password" in rules_of(tmp_path / "sfx.bin")


def test_secrets_dedupe_keeps_a_containers_own_copy(tmp_path, run_analysis):
    """Fourth review: a container's finding was dropped whenever a descendant reported the same key body, even when
    the container held its own copy elsewhere and the descendant's was a library self-test key or encrypted: the
    high-severity finding disappeared."""
    key = _pem_block(91)
    enc = _pem_block(91, encrypted=True)
    for name, inner, want in (("cryptolib.bin", ("usr/lib/libcrypto.so.3", b"\x00" * 64 + key), "crypto-library-test-key"),
                              ("encrypted.bin", ("keys/enc.pem", enc), "pem-private-key")):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr(*inner)
        src = tmp_path / name
        src.write_bytes(_noise(8192, 92) + key + _noise(1024, 93) + b.getvalue() + _noise(4096, 94))
        found = [(f["rule_id"], f["severity"]) for f in run_analysis(src)["findings"]
                 if f["rule_id"] in ("pem-private-key", "crypto-library-test-key")]
        assert ("pem-private-key", "high") in found and any(r == want for r, _s in found if (r, _s) != ("pem-private-key", "high")), (name, found)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("etc/ssl/k.pem", key)
    src = tmp_path / "once.bin"  # the same bytes reported by the member and found in the dump: once
    src.write_bytes(_noise(8192, 95) + b.getvalue() + _noise(4096, 96))
    assert [f["rule_id"] for f in run_analysis(src)["findings"]].count("pem-private-key") == 1


def test_floods_cannot_run_a_scan_out_of_time_or_hide_what_follows(tmp_path, run_analysis, monkeypatch):
    """Carving checked each candidate within limits of its own file only: a cpio candidate read up to 64 MiB
    looking for a trailer (a 64 MiB flood of cpio magics took 347 s, and a bogus magic in front of a real archive
    swallowed it), test-decoding charged only bytes decoded (gzip names without a terminating NUL were read to the
    end of the file for free), the decoding limit ended carving altogether, and the limits of one file multiplied
    with the number of files (a zip of 20,000 small floods would have run for well over an hour)."""
    import struct
    import time
    import zlib

    from dfa.core import extract
    rules_of = lambda p, lim=None: {f["rule_id"] for f in run_analysis(p, lim)["findings"]}  # noqa: E731
    shadow_cpio = _newc([("etc/shadow", _SHADOW, 0o100600)])
    (tmp_path / "decoy.bin").write_bytes(_noise(8192, 101) + b"070701" + b"\x00" * 200 + shadow_cpio
                                         + _noise(4096, 102))
    assert "empty-password" in rules_of(tmp_path / "decoy.bin")
    (tmp_path / "failed.cpio").write_bytes(b"070701" + b"\x00" * 200 + shadow_cpio)  # a failed cpio: its own kind
    assert "empty-password" in rules_of(tmp_path / "failed.cpio")  # is carved once its headers lead to a trailer
    two = _newc([("etc/shadow", _SHADOW, 0o100600), ("etc/ssl/k.pem", _pem_block(116), 0o100600)])
    (tmp_path / "odd.bin").write_bytes(_noise(8191, 117) + two + _noise(4096, 118))  # padding counts from its start
    assert {"empty-password", "pem-private-key"} <= rules_of(tmp_path / "odd.bin")
    flood = tmp_path / "cpioflood.bin"  # no trailer anywhere: each candidate read the rest of the file
    with flood.open("wb") as f:
        f.write(_noise(4096, 103) + (b"070701" + b"\x00" * 10) * 4000
                + gzip.compress(_tar_of({"etc/shadow": _SHADOW}), mtime=0))
        f.truncate(32 * 1024 * 1024)
    t0 = time.monotonic()
    assert "empty-password" in rules_of(flood) and time.monotonic() - t0 < 30

    lim = Limits(max_file_bytes=4 * 1024 * 1024, max_total_bytes=16 * 1024 * 1024)  # 32 MiB of test-decoding
    names = tmp_path / "names.bin"
    names.write_bytes(_noise(4096, 104) + (b"\x1f\x8b\x08\x08" + b"AAAAAA") * 512 + b"A" * (8 * 1024 * 1024))
    t0 = time.monotonic()
    res = Extractor(tmp_path / "w_names", lim).run(names, names.name)
    assert time.monotonic() - t0 < 30 and "max_carve_decode" in res.limits_hit
    assert res.artifacts[0].extraction == "partial"  # reported

    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    bomb = co.compress(b"\x00" * (8 * 1024 * 1024)) + co.flush(zlib.Z_SYNC_FLUSH)  # no final block: never valid
    bombs = b"".join(b"\x1f\x8b\x08\x00" + struct.pack("<I", i + 1) + b"\x00\x03" + bomb for i in range(16))
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("etc/shadow", _SHADOW)
    src = tmp_path / "bombs.bin"  # distinct streams spend the budget: gzip/xz candidates after them are skipped,
    src.write_bytes(_noise(4096, 105) + bombs + _noise(4096, 106) + z.getvalue() + _noise(4096, 107))
    m = run_analysis(src, lim)  # other objects are still carved
    rules = {f["rule_id"] for f in m["findings"]}
    assert {"empty-password", "extraction-partial"} <= rules and "max_carve_decode" in m["extraction"]["limits_hit"]

    monkeypatch.setattr(extract, "MAX_CARVE_ATTEMPTS_TOTAL", 3 * extract.MAX_CARVE_ATTEMPTS)
    part = b"\x00" * 16 + (b"hsqs" + b"\x00" * 12) * extract.MAX_CARVE_ATTEMPTS
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(6):
            zf.writestr(f"part{i}.bin", part)
    (tmp_path / "floods.zip").write_bytes(z.getvalue())
    res = Extractor(tmp_path / "w_floods", Limits()).run(tmp_path / "floods.zip", "floods.zip")
    root = res.artifacts[0]  # the scan's budget is spent after three files; the rest is reported once, for the scan
    assert root.extraction == "partial" and "3 file(s) were not searched" in root.extraction_note
    assert all(a.extraction is None for a in res.artifacts[1:])  # no finding per file


def test_an_unpacker_that_prints_a_lot_is_not_stalled(tmp_path):
    """The tool's output went to a pipe read only after it exited: a tool printing more than the pipe holds (jefferson
    prints a line per directory entry and per damaged node) blocked until the timeout and its image was cut short."""
    import sys
    import time

    from dfa.core.identify import detect_format
    from dfa.core.limits import LimitExceeded
    src = tmp_path / "img.bin"
    src.write_bytes(b"\x00" * 64)
    ex = Extractor(tmp_path / "w", Limits(tool_timeout_s=20))
    art = ex._register(src, "<input>", "img.bin", detect_format(src), None, 0, "input")
    out = tmp_path / "out"
    out.mkdir()
    script = f"import sys; sys.stdout.write('node_crc does not match!\\n' * 20000); open({str(out / 'f')!r}, 'w').write('x')"
    t0 = time.monotonic()
    try:
        ex._run_tool(art, [sys.executable, "-c", script], out)
    except LimitExceeded as exc:  # the timeout
        pytest.fail(f"stalled: {exc}")
    assert time.monotonic() - t0 < 10 and (out / "f").exists()
    assert art.details["tool_output_tail"].endswith("node_crc does not match!\n")


def test_adjusted_self_extractors_with_a_comment_and_streams_past_the_file_limit(tmp_path, run_analysis):
    """A self-extractor whose offsets 'zip -A' adjusted was recognised only without an archive comment, and never
    inside a larger image (its end record's offsets count from the stub, not from the first member); a compressed
    stream that decodes past the per-file limit was skipped as if it were none, without a word."""
    import struct
    import zlib
    stub = b"\x7fSTUB" + _noise(6000, 111)
    sfx = bytearray(stub + _zip_of_members([{"name": b"etc/shadow", "data": _SHADOW, "method": 8},
                                            {"name": b"readme.txt", "data": b"hello\n", "method": 8}]))
    count, cd_size, cd_off = struct.unpack_from("<HII", sfx, len(sfx) - 12)  # what 'zip -A' does: every offset
    pos = len(stub) + cd_off  # now counts from the start of the stub
    for _ in range(count):
        struct.pack_into("<I", sfx, pos + 42, struct.unpack_from("<I", sfx, pos + 42)[0] + len(stub))
        pos += 46 + sum(struct.unpack_from("<HHH", sfx, pos + 28))
    struct.pack_into("<I", sfx, len(sfx) - 6, cd_off + len(stub))
    comment = b"made by zip -A"
    struct.pack_into("<H", sfx, len(sfx) - 2, len(comment))
    (tmp_path / "sfx.bin").write_bytes(bytes(sfx) + comment)
    m = run_analysis(tmp_path / "sfx.bin")
    assert m["extraction"]["artifacts"][0]["format"] == "zip"
    assert "empty-password" in {f["rule_id"] for f in m["findings"]}
    (tmp_path / "image.bin").write_bytes(_noise(8192, 112) + bytes(sfx) + comment + _noise(4096, 113))
    assert "empty-password" in {f["rule_id"] for f in run_analysis(tmp_path / "image.bin")["findings"]}

    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    big = co.compress(b"\x00" * (3 * 1024 * 1024)) + co.flush()
    stream = b"\x1f\x8b\x08\x00" + b"\x00" * 4 + b"\x00\x03" + big + struct.pack("<II", zlib.crc32(b"\x00" * (3 * 1024 * 1024)), 3 * 1024 * 1024)
    (tmp_path / "big.bin").write_bytes(_noise(8192, 114) + stream + _noise(4096, 115))
    res = Extractor(tmp_path / "w_big", Limits(max_file_bytes=1024 * 1024)).run(tmp_path / "big.bin", "big.bin")
    assert res.artifacts[0].extraction == "partial" and "max_file_bytes" in res.limits_hit  # reported


def _elf_hiding(payload: bytes) -> bytes:
    """A 32-bit ARM Linux executable whose section header table sits after ``payload``: the payload lies inside the
    executable's extent, while no header, section or segment covers it."""
    import struct
    text = b"\x00\xf0\x20\xe3" * 16  # nop
    text_off = 52 + 32
    shoff = text_off + len(text) + len(payload)
    shoff += -shoff % 4
    ehdr = struct.pack("<4s5B7sHHIIIIIHHHHHH", b"\x7fELF", 1, 1, 1, 0, 0, b"\x00" * 7, 2, 40, 1, 0x10000 + text_off,
                       52, shoff, 0x5000400, 52, 32, 1, 40, 2, 0)
    phdr = struct.pack("<8I", 1, 0, 0x10000, 0x10000, text_off + len(text), text_off + len(text), 5, 0x1000)
    text_sh = struct.pack("<10I", 0, 1, 6, 0x10000 + text_off, text_off, len(text), 0, 0, 4, 0)
    body = ehdr + phdr + text + payload
    return body + b"\x00" * (shoff - len(body)) + b"\x00" * 40 + text_sh


def test_data_inside_an_executable_that_no_section_covers_is_analysed(tmp_path, run_analysis):
    """An executable's extent comes from its own tables: moving the section header table behind an appended payload
    took the payload into the extent, and the overlay check no longer saw it. Data that no header, section or
    segment covers is analysed now (linkers leave none: none of the 721 ELF files in the real samples has any)."""
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("etc/shadow", _SHADOW)
    (tmp_path / "dropper").write_bytes(_elf_hiding(_noise(512, 121) + b.getvalue() + _noise(256, 122)))
    m = run_analysis(tmp_path / "dropper")
    assert m["extraction"]["artifacts"][0]["format"] == "elf"
    rules = {f["rule_id"]: f for f in m["findings"]}
    assert "empty-password" in rules and "appended-to-executable" not in rules
    hidden = rules["uncovered-data-in-executable"]
    assert hidden["classification"] == "suspicious" and hidden["severity"] == "low"
    (tmp_path / "plain").write_bytes(_elf_hiding(b""))  # nothing uncovered: nothing reported
    assert "uncovered-data-in-executable" not in {f["rule_id"] for f in run_analysis(tmp_path / "plain")["findings"]}


def test_cpio_own_kind_carving_is_bounded_by_the_scan_work_budget(tmp_path):
    """Fifth review: a failed (trailer-less) cpio of many valid headers was carved as its own kind by walking the
    whole chain to the end for every candidate offset, twice, with no charge to the scan's work budget - only the
    per-scan attempts counter bounded it, so a zip of ~32 such chains ran ~80 minutes from under 1 MB. The walk is
    now charged, so the budget stops it."""
    import struct
    import time

    from dfa.core.extract import Extractor
    from dfa.core.identify import detect_format

    def hdr(ino: int) -> bytes:
        name = b"f%05d\x00" % ino
        h = b"070701" + b"".join(b"%08X" % v for v in (ino, 0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name), 0))
        blob = h + name
        return blob + b"\x00" * (-len(blob) % 4)
    chain = b"".join(hdr(i) for i in range(3000))  # valid headers, no TRAILER!!!
    assert struct.unpack_from("<I", chain, 0) == struct.unpack_from("<I", b"0707", 0) or chain[:6] == b"070701"
    (tmp_path / "x.cpio").write_bytes(chain)
    ex = Extractor(tmp_path / "w", Limits(max_files=3000, max_total_bytes=4 * 1024 * 1024,
                                          max_file_bytes=4 * 1024 * 1024))  # work budget = 8 MiB
    art = ex._register(tmp_path / "x.cpio", "<input>", "x.cpio", detect_format(tmp_path / "x.cpio"), None, 0, "input")
    before = ex._work_left
    t0 = time.monotonic()
    ex._carve_failed(art)
    assert time.monotonic() - t0 < 20
    assert ex._work_left < before  # the chain walk was charged (pre-fix: cpio left the budget untouched)
    assert "max_carve_decode" in ex.result.limits_hit  # and the budget stopped it


def test_zip_member_over_declaring_its_compressed_size_cannot_hide_a_payload(tmp_path, run_analysis):
    """Fifth review: a zip member may declare a compressed size larger than its real deflate stream; zipfile stops
    at the stream's end and ignores the slack, but _zip_gaps covered the whole declared size, so an unbounded
    payload hidden there was neither extracted nor carved and extraction stayed 'ok' with no finding or warning."""
    import struct
    import zlib

    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    real = co.compress(b"hello\n") + co.flush()
    payload = _pem_block(131) + b"\x00" * 32 + b"aws AKIAQWERTYUIOPLKJHGF\x00" + gzip.compress(_SHADOW, mtime=0)
    slack = payload + b"\x00" * 1024
    csize = len(real) + len(slack)  # over-declared compressed size; the slack hides the payload
    n0, d0 = b"readme.txt", b"hello, world!\n"
    body = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, zlib.crc32(d0), len(d0), len(d0), len(n0), 0) + n0 + d0
    off1 = len(body)
    body += (struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 8, 0, 0, zlib.crc32(b"hello\n"), csize, 6, 10, 0)
             + b"secret.bin" + real + slack)
    cd = len(body)

    def cde(name, off, method, crc, cs, us):
        return struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, method, 0, 0, crc, cs, us, len(name),
                           0, 0, 0, 0, 0, off) + name
    cds = (cde(n0, 0, 0, zlib.crc32(d0), len(d0), len(d0))
           + cde(b"secret.bin", off1, 8, zlib.crc32(b"hello\n"), csize, 6))
    data = body + cds + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 2, 2, len(cds), cd, 0)
    (tmp_path / "bigtail.zip").write_bytes(data)
    m = run_analysis(tmp_path / "bigtail.zip")
    assert {"pem-private-key", "token-aws-access-key"} <= {f["rule_id"] for f in m["findings"]}
    assert any("region" in w for w in m["extraction"]["warnings"])  # the slack is reported, not hidden
