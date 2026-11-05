"""LZ4/zstd/lzop, CramFS, EROFS, Android sparse, Parrot PLF and DJI IM*H.

Where possible the inputs are produced by the reference tools (lzop, mkfs.cramfs, mkfs.erofs,
img2simg) rather than by our own writers, so the parsers are checked against real encoders.
"""
import gzip
import io
import random
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


@pytest.mark.skipif(not shutil.which("lzop"), reason="lzop not installed")
def test_many_lzop_files_do_not_exhaust_the_address_space(tmp_path):
    """Each lzop artifact created an LZO codec whose 448 KiB of work memory was never released, so a firmware of a
    few thousand small lzop files exhausted the analysis's address-space limit (RLIMIT_AS in the local sandbox)."""
    import sys
    t = tmp_path / "busybox.txt"
    t.write_bytes(b"BusyBox v1.30.1 (2020-01-01) multi-call binary\n" * 64)
    subprocess.run(["lzop", "-q", str(t)], check=True)
    one = (tmp_path / "busybox.txt.lzo").read_bytes()
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as tf:
        for i in range(400):
            ti = tarfile.TarInfo(f"lib/modules/m{i}.lzo")
            ti.size = len(one)
            tf.addfile(ti, io.BytesIO(one))
    fw = tmp_path / "many.tar"
    fw.write_bytes(b.getvalue())
    code = ("import resource, sys\nfrom pathlib import Path\nfrom dfa.core.extract import Extractor\n"
            "from dfa.core.limits import Limits\n"
            "vm = int(next(ln for ln in open('/proc/self/status') if ln.startswith('VmSize')).split()[1]) * 1024\n"
            "resource.setrlimit(resource.RLIMIT_AS, (vm + 96 * 1024**2, vm + 96 * 1024**2))  # 400 x 448 KiB: 175 MiB\n"
            "res = Extractor(Path(sys.argv[2]), Limits()).run(Path(sys.argv[1]), 'many.tar')\n"
            "print(sum(a.format == 'lzop' and a.extraction == 'ok' for a in res.artifacts))\n")
    proc = subprocess.run([sys.executable, "-c", code, str(fw), str(tmp_path / "w")], capture_output=True, text=True,
                          timeout=600, cwd=Path(__file__).resolve().parents[1])
    assert proc.returncode == 0 and proc.stdout.strip() == "400", (proc.returncode, proc.stderr[-1500:])


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


def test_arch_guess_on_raw_code(tmp_path, run_analysis):
    from dfa.core.formats.arch import guess_architecture
    rnd = random.Random(7)

    def code(prologue: bytes, epilogue: bytes, n: int = 200) -> bytes:
        # fresh filler per function: a repeated random block could itself contain another ISA's opcodes 200x
        return b"".join(prologue + rnd.randbytes(28) + epilogue + rnd.randbytes(28) for _ in range(n))

    arm = code(b"\x00\x48\x2d\xe9", b"\x1e\xff\x2f\xe1")  # push {.., lr} / bx lr
    g = guess_architecture(arm)
    assert g and g.architecture == "ARM (32-bit)"
    mips = code(b"\x27\xbd\xff\xe0", b"\x03\xe0\x00\x08")  # addiu sp, sp, -32 / jr ra
    assert guess_architecture(mips).architecture == "MIPS" and guess_architecture(mips).endianness == "big"
    assert guess_architecture(rnd.randbytes(1 << 20)) is None
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x01" * 64 + mips)
    m = run_analysis(p)
    assert m["identification"]["architecture"].startswith("MIPS")


def test_arch_guess_never_fires_on_random_data():
    from dfa.core.formats.arch import guess_architecture
    rnd = random.Random(1234)
    for size in (4096, 65536, 1 << 20, 3 << 20):
        for _ in range(3):
            assert guess_architecture(rnd.randbytes(size)) is None


def test_esp32_image(tmp_path, run_analysis):
    from tests.factory import esp_app_desc, esp_image, xtensa_code
    drom = esp_app_desc("remoteid", "1.2.0", "v4.4.2") + b"Hello from flash" * 64
    img = esp_image([(0x3F400020, drom), (0x3FFB0000, b"\x00" * 512), (0x400D0020, xtensa_code(300))],
                    chip_id=0, hash_appended=True)
    p = tmp_path / "remoteid.bin"
    p.write_bytes(img)
    assert detect_format(p).format == "esp_image"
    m = run_analysis(p)
    ident = m["identification"]
    assert ident["architecture"] == "Xtensa (ESP32)" and ident["platform"] == "Espressif"
    root = m["extraction"]["artifacts"][0]
    assert root["details"]["checksum_valid"] is True and root["details"]["sha256_valid"] is True
    assert root["details"]["esp_app"]["project_name"] == "remoteid"
    comps = {(c["name"], c["version"]) for c in m["components"]}
    assert ("esp-idf", "4.4.2") in comps and ("remoteid", "1.2.0") in comps
    segs = [a for a in m["extraction"]["artifacts"] if a["name"].startswith("segment")]
    assert len(segs) == 3
    code = next(a for a in segs if a["details"]["load_address"] == "0x400d0020")
    assert code["details"]["arch_guess"]["architecture"] == "Xtensa"


def test_newer_espressif_chips_are_recognised(tmp_path, run_analysis):
    """Images for the ESP32-P4, -C5, -C61, -H21 and -H4 (chip IDs from esptool's targets) were not recognised at all:
    they passed as raw data, with no platform, ESP-IDF version or application name."""
    from tests.factory import esp_app_desc, esp_image
    for chip, chip_id in (("ESP32-P4", 18), ("ESP32-C61", 20), ("ESP32-C5", 23), ("ESP32-H21", 25),
                          ("ESP32-H4", 28)):
        img = esp_image([(0x40800000, esp_app_desc("telemetry", "2.0.1", "v5.4.1") + b"\x00" * 256),
                         (0x40810000, bytes(range(256)) * 16)], entry=0x40800400, chip_id=chip_id, hash_appended=True)
        p = tmp_path / f"{chip}.bin"
        p.write_bytes(img)
        assert detect_format(p).format == "esp_image", chip
        m = run_analysis(p)
        assert m["identification"]["platform"] == "Espressif", chip
        assert m["identification"]["architecture"] == f"RISC-V ({chip})"
        assert {("esp-idf", "5.4.1"), ("telemetry", "2.0.1")} <= {(c["name"], c["version"]) for c in m["components"]}


def test_esp_image_with_bad_checksum_is_flagged(tmp_path, run_analysis):
    from tests.factory import esp_image, xtensa_code
    img = bytearray(esp_image([(0x400D0020, xtensa_code(10))], chip_id=9))
    img[40] ^= 0xFF  # tamper with code; the stored checksum no longer matches
    p = tmp_path / "tampered.bin"
    p.write_bytes(bytes(img))
    assert detect_format(p).format == "esp_image"  # exact layout still identifies it
    m = run_analysis(p)
    root = m["extraction"]["artifacts"][0]
    assert root["details"]["esp_chip"] == "ESP32-S3" and root["details"]["checksum_valid"] is False
    assert any("checksum mismatch" in w for w in m["extraction"]["warnings"])


def test_esp_flash_dump(tmp_path, run_analysis):
    from tests.factory import esp_app_desc, esp_flash_dump, esp_image, esp_partition_table, xtensa_code
    boot = esp_image([(0x3FFF0000, b"\x01" * 64), (0x40078000, xtensa_code(20))], entry=0x40080400)
    app = esp_image([(0x3F400020, esp_app_desc("elrs-rx", "3.4.0", "v4.4.6-dirty")),
                     (0x400D0020, xtensa_code(100))])
    table = esp_partition_table([("nvs", 1, 2, 0x9000, 0x5000, 0), ("otadata", 1, 0, 0xE000, 0x2000, 0),
                                 ("app0", 0, 0x10, 0x10000, 0x100000, 0), ("app1", 0, 0x11, 0x110000, 0x100000, 1),
                                 ("spiffs", 1, 0x82, 0x210000, 0x10000, 0)])
    nvs = b"\xfe\xff\xff\xff" + bytes(28) + b"wifi.sta.ssid\0" * 8
    p = tmp_path / "flash.bin"
    p.write_bytes(esp_flash_dump(boot, table, {0x9000: nvs, 0x10000: app, 0x110000: b"\x55" * 4096},
                                 size=0x220000))
    assert detect_format(p).format == "esp_flash"
    m = run_analysis(p)
    arts = m["extraction"]["artifacts"]
    root = arts[0]
    assert [x["label"] for x in root["details"]["partitions"]] == ["nvs", "otadata", "app0", "app1", "spiffs"]
    assert root["details"]["partition_table_md5_valid"] is True
    notes = " | ".join(root["details"]["partition_notes"])
    assert "app1: flash-encrypted partition, not analysed" in notes and "spiffs: erased" in notes
    names = {a["name"]: a for a in arts}
    assert names["bootloader.bin"]["format"] == "esp_image"
    assert names["02_app0.app-ota_0.bin"]["format"] == "esp_image"
    assert names["02_app0.app-ota_0.bin"]["details"]["esp_app"]["project_name"] == "elrs-rx"
    assert "00_nvs.data-nvs.bin" in names and not any("app1" in n for n in names)
    assert ("esp-idf", "4.4.6-dirty") in {(c["name"], c["version"]) for c in m["components"]}


def test_esp8266_image_followed_by_app(tmp_path, run_analysis):
    from tests.factory import esp_image
    eboot = esp_image([(0x4010F000, b"\x0d\xf0\x12\xc1\xf0\x00" * 100)], entry=0x4010F29C, chip_id=None)
    app = esp_image([(0x40201010, b"\x0d\xf0" * 2000), (0x3FFE8000, b"\x00" * 256)], entry=0x40100004,
                    chip_id=None)
    data = eboot + b"\xaa" * (0x1000 - len(eboot)) + app
    p = tmp_path / "arduino.bin"
    p.write_bytes(data)
    m = run_analysis(p)
    arts = m["extraction"]["artifacts"]
    assert arts[0]["details"]["esp_chip"] == "ESP8266"
    second = next(a for a in arts if a["name"] == "trailing@0x1000.bin")
    assert second["format"] == "esp_image" and second["details"]["esp_chip"] == "ESP8266"
    assert len(second["details"]["segments"]) == 2


def test_esp_partition_table_file(tmp_path):
    from tests.factory import esp_partition_table
    p = tmp_path / "partitions.bin"
    p.write_bytes(esp_partition_table([("factory", 0, 0, 0x10000, 0x100000, 0)])[:64])
    info = detect_format(p)
    assert info.format == "esp_partition_table" and info.details["partitions"][0]["subtype"] == "factory"
    assert info.details["md5_valid"] is True
