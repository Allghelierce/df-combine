"""LZ4/zstd/lzop, CramFS, EROFS, Android sparse, Parrot PLF and DJI IM*H.

Where possible the inputs are produced by the reference tools (lzop, mkfs.cramfs, mkfs.erofs,
img2simg) rather than by our own writers, so the parsers are checked against real encoders.
"""
import gzip
import io
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path

import pytest

from dfa.core.extract import Extractor
from dfa.core.identify import detect_format
from dfa.core.limits import Limits


def _rootfs(tmp: Path) -> Path:
    root = tmp / "root"
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "etc/shadow").write_text("root::19000:0:99999:7:::\n")
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n')
    (root / "bin/payload").write_bytes(b"BusyBox v1.30.1 (2020) multi-call binary\n" * 300)
    return root


def _tar_bytes(root: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(root, arcname=".")
    return buf.getvalue()


def _extract(p: Path, work: Path, **limits):
    ex = Extractor(work, Limits(**limits))
    return ex, ex.run(p, p.name)


def _names(res):
    return {a.name for a in res.artifacts}


def test_zstd_lz4_frame_and_legacy(tmp_path):
    import lz4.block
    import lz4.frame
    import zstandard
    data = _tar_bytes(_rootfs(tmp_path))
    cases = {"fw.tar.zst": zstandard.ZstdCompressor().compress(data),
             "fw.tar.lz4": lz4.frame.compress(data)}
    legacy = b"\x02\x21\x4c\x18"
    for i in range(0, len(data), 8 << 20):
        blk = lz4.block.compress(data[i:i + (8 << 20)], store_size=False)
        legacy += struct.pack("<I", len(blk)) + blk
    cases["kernel.lz4"] = legacy
    for name, blob in cases.items():
        p = tmp_path / name
        p.write_bytes(blob)
        ex, res = _extract(p, tmp_path / f"w_{name}")
        assert res.artifacts[0].extraction == "ok", (name, res.artifacts[0].extraction_note)
        assert "/etc/shadow" in _names(res), name


def test_zstd_bomb_is_bounded(tmp_path):
    import zstandard
    p = tmp_path / "bomb.zst"
    p.write_bytes(zstandard.ZstdCompressor(level=19).compress(b"\0" * (30 * 1024 * 1024)))
    ex, res = _extract(p, tmp_path / "w", max_ratio=50, ratio_min_bytes=1024 * 1024)
    assert res.artifacts[0].extraction == "partial" and "ratio" in res.artifacts[0].extraction_note


@pytest.mark.skipif(not shutil.which("lzop"), reason="lzop not installed")
def test_lzop_reference_tool(tmp_path):
    t = tmp_path / "fw.tar"
    t.write_bytes(_tar_bytes(_rootfs(tmp_path)))
    subprocess.run(["lzop", "-q", str(t)], check=True)
    p = tmp_path / "fw.tar.lzo"
    assert detect_format(p).format == "lzop"
    ex, res = _extract(p, tmp_path / "w")
    assert "/etc/shadow" in _names(res)


@pytest.mark.skipif(not (shutil.which("mkfs.cramfs") or Path("/usr/sbin/mkfs.cramfs").exists()),
                    reason="mkfs.cramfs not installed")
def test_cramfs_reference_tool(tmp_path):
    root = _rootfs(tmp_path)
    (root / "bin/sh").symlink_to("busybox")
    img = tmp_path / "fs.cramfs"
    subprocess.run([shutil.which("mkfs.cramfs") or "/usr/sbin/mkfs.cramfs", str(root), str(img)],
                   check=True, capture_output=True)
    assert detect_format(img).format == "cramfs"
    ex, res = _extract(img, tmp_path / "w")
    assert res.artifacts[0].extraction == "ok", res.artifacts[0].extraction_note
    payload = next(a for a in res.artifacts if a.name == "/bin/payload")
    assert ex.path_of(payload.id).read_bytes() == (root / "bin/payload").read_bytes()
    assert any(link.target == "busybox" for link in res.links)


@pytest.mark.skipif(not shutil.which("mkfs.erofs"), reason="erofs-utils not installed")
def test_erofs_container_only(tmp_path, monkeypatch):
    root = _rootfs(tmp_path)
    img = tmp_path / "fs.erofs"
    subprocess.run(["mkfs.erofs", str(img), str(root)], check=True, capture_output=True)
    assert detect_format(img).format == "erofs"
    monkeypatch.delenv("DFA_IN_SANDBOX", raising=False)
    ex, res = _extract(img, tmp_path / "w1")
    assert res.artifacts[0].extraction == "unsupported"
    monkeypatch.setenv("DFA_IN_SANDBOX", "1")
    ex, res = _extract(img, tmp_path / "w2")
    assert "/etc/shadow" in _names(res), res.warnings


@pytest.mark.skipif(not shutil.which("img2simg") or not shutil.which("mkfs.ext4") and not Path("/usr/sbin/mkfs.ext4").exists(),
                    reason="img2simg / mkfs.ext4 not installed")
def test_android_sparse_reference_tool(tmp_path):
    root = _rootfs(tmp_path)
    raw = tmp_path / "system.img"
    with raw.open("wb") as fp:
        fp.truncate(16 * 1024 * 1024)
    subprocess.run([shutil.which("mkfs.ext4") or "/usr/sbin/mkfs.ext4", "-q", "-F", "-d", str(root), str(raw)],
                   check=True, capture_output=True)
    sparse = tmp_path / "system.simg"
    subprocess.run(["img2simg", str(raw), str(sparse)], check=True, capture_output=True)
    assert detect_format(sparse).format == "android_sparse"
    ex, res = _extract(sparse, tmp_path / "w")
    expanded = next(a for a in res.artifacts if a.name == "image.raw")
    assert ex.path_of(expanded.id).read_bytes() == raw.read_bytes()
    assert "/etc/shadow" in _names(res)


def _plf(sections: list[tuple[int, bytes, bool]]) -> bytes:
    body = b""
    for stype, data, compress in sections:
        payload = gzip.compress(data) if compress else data
        body += struct.pack("<5I", stype, len(payload), 0, 0x40000000, len(data) if compress else 0) + payload
        body += b"\0" * ((4 - len(payload) % 4) % 4)
    hdr = struct.pack("<14I", 0x21464C50, 11, 0x38, 0x14, 1, 0x40000000, 4, 0x5c, 1, 3, 7, 0, 0, 0x38 + len(body))
    return hdr + body


def test_parrot_plf_sections(tmp_path):
    root = _rootfs(tmp_path)
    p = tmp_path / "update.plf"
    p.write_bytes(_plf([(0x07, b"bootparams console=ttyO0\n", False), (0x03, _tar_bytes(root), True)]))
    assert detect_format(p).format == "parrot_plf"
    ex, res = _extract(p, tmp_path / "w")
    assert res.artifacts[0].extraction == "ok", res.artifacts[0].extraction_note
    assert res.artifacts[0].details["version"] == "3.7.0"
    assert "/etc/shadow" in _names(res)


def _imah(chunks: list[tuple[bytes, bytes, int]], enc_key: bytes) -> bytes:
    hsize = 192 + 32 * len(chunks)
    payload, table = b"", b""
    for cid, data, attrib in chunks:
        table += cid + struct.pack("<III", len(payload), len(data), attrib) + struct.pack("<Q", 0x8000000) + b"\0" * 8
        payload += data
    h = bytearray(192)
    h[0:4] = b"IM*H"
    struct.pack_into("<II4xIIII", h, 4, 2, hsize + len(payload), hsize, 0, len(payload), len(payload))
    h[40:44] = b"PRAK"
    h[44:48] = enc_key
    h[64:64 + 8] = b"wm220_08"
    struct.pack_into("<II", h, 100, 0x01020304, 0x20230101)
    struct.pack_into("<I", h, 156, len(chunks))
    return bytes(h) + table + payload


def test_dji_imah_plaintext_only(tmp_path):
    p = tmp_path / "wm220_0801_v01.02.03.04.sig"
    p.write_bytes(_imah([(b"0000", b"\x7fELF" + b"\0" * 60, 0x01), (b"0001", b"\x99" * 64, 0x00)], b"UFIE"))
    ex, res = _extract(p, tmp_path / "w")
    root = res.artifacts[0]
    assert root.details["enc_key_id"] == "UFIE" and root.details["module_name"] == "wm220_08"
    names = _names(res)
    assert "chunk_0000.bin" in names and "chunk_0001.bin" not in names  # encrypted chunk is never written
    p2 = tmp_path / "enc.sig"
    p2.write_bytes(_imah([(b"0000", b"\x99" * 64, 0x00)], b"UFIE"))
    ex, res = _extract(p2, tmp_path / "w2")
    assert res.artifacts[0].extraction == "unsupported" and "not decrypted" in res.artifacts[0].extraction_note
