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
