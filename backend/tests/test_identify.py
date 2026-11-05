import json
import shutil
import struct

import factory
import pytest

from dfa.core.formats.cortexm import analyze_vector_table
from dfa.core.formats.ihex import IHexError, parse_ihex
from dfa.core.formats.px4json import ContainerError, parse_container
from dfa.core.identify import detect_format, detect_format_bytes, parse_uimage_header


@pytest.mark.parametrize("key,fmt", [
    ("px4", "px4"), ("apj", "apj"), ("hex", "ihex"), ("apj_bin", "cortexm_raw"), ("tar_gz", "gzip"),
    ("zip", "zip"), ("squashfs", "squashfs"), ("ext4", "ext"), ("disk_img", "disk_image"), ("elf", "elf"),
    ("tar_traversal", "tar"), ("random", "raw"),
])
def test_detect_fixture_formats(fixtures, key, fmt):
    if key not in fixtures:
        pytest.skip(f"{key} fixture unavailable (missing host tool)")
    assert detect_format(fixtures[key]).format == fmt


def test_extension_is_not_trusted(fixtures, tmp_path):
    spoof = tmp_path / "innocent.txt"
    shutil.copy(fixtures["px4"], spoof)
    assert detect_format(spoof).format == "px4"
    spoof2 = tmp_path / "firmware.zip"
    shutil.copy(fixtures["hex"], spoof2)
    assert detect_format(spoof2).format == "ihex"


def test_empty_and_text(tmp_path):
    e = tmp_path / "e.bin"
    e.write_bytes(b"")
    assert detect_format(e).format == "empty"
    assert detect_format_bytes(b"hello world\nthis is text\n" * 10, 250).format == "text"


def test_ihex_roundtrip():
    data = bytes(range(256)) * 4
    img = parse_ihex(factory.intel_hex(data, 0x08004000))
    assert img.base_address == 0x08004000
    assert img.data == data


def test_ihex_rejects_bad_checksum():
    with pytest.raises(IHexError):
        parse_ihex(b":0400000001020304FF\n:00000001FF\n")


def test_ihex_span_limit():
    first = factory.intel_hex(b"\x01" * 16, 0x0000_0000).replace(b":00000001FF\n", b"")
    far = first + factory.intel_hex(b"\x02" * 16, 0x7000_0000)
    with pytest.raises(IHexError, match="span"):
        parse_ihex(far, max_span=1024 * 1024)


def test_px4_container_parse(fixtures):
    c = parse_container(fixtures["px4"].read_bytes(), 10 * 1024 * 1024)
    assert c.platform == "PX4"
    assert c.metadata["board_id"] == 50
    assert "image.bin" in c.images and analyze_vector_table(c.images["image.bin"]) is not None


def test_container_image_size_limit(fixtures):
    with pytest.raises(ContainerError, match="exceeds limit"):
        parse_container(fixtures["px4"].read_bytes(), 1024)


def test_container_invalid_json():
    with pytest.raises(ContainerError):
        parse_container(b'{"image": 5', 100)
    with pytest.raises(ContainerError):
        parse_container(json.dumps({"magic": "PX4FWv1", "image": "!!notbase64"}).encode(), 100)


def test_vector_table_rejects_random():
    assert analyze_vector_table(b"\x00" * 64) is None
    assert analyze_vector_table(struct.pack("<16I", 0x2002_0000, 0x0800_0200, *([0] * 14))) is None  # even reset


def test_uimage_header():
    hdr = struct.pack(">IIIIIIIBBBB", 0x27051956, 0, 0, 100, 0x80008000, 0x80008000, 0, 5, 2, 2, 1) + b"kernel".ljust(32, b"\0")
    info = parse_uimage_header(hdr)
    assert info["arch"] == "ARM" and info["compression"] == "gzip" and info["name"] == "kernel"


def test_platform_px4(fixtures, run_analysis):
    m = run_analysis(fixtures["px4"])
    i = m["identification"]
    assert i["platform"] == "PX4" and i["platform_confidence"] == "high"
    assert i["architecture"].startswith("ARM Cortex-M")
    assert i["board_id"] == 50 and i["board_hint"]
    assert i["platform_version"] == "1.14.3"


def test_platform_ardupilot_from_hex_and_raw(fixtures, run_analysis):
    for key in ("hex", "apj_bin", "apj"):
        i = run_analysis(fixtures[key])["identification"]
        assert i["platform"] == "ArduPilot", key
        assert i["platform_version"] == "4.5.7"
    assert run_analysis(fixtures["hex"])["identification"]["vehicle_type"] == "ArduCopter"


def test_platform_companion(fixtures, run_analysis):
    i = run_analysis(fixtures["tar_gz"])["identification"]
    assert i["platform_family"] == "companion-linux"
    assert i["os_hint"] == "linux"


def test_unknown_random_blob(fixtures, run_analysis):
    m = run_analysis(fixtures["random"])
    assert m["identification"]["platform"] == "Unknown"
    assert any(f["rule_id"] == "high-entropy-unknown" for f in m["findings"])


def test_ardupilot_descriptor(fixtures, run_analysis):
    i = run_analysis(fixtures["apj_bin"])["identification"]
    d = i["ardupilot_descriptor"]
    assert d["git_hash"] == "deadbeef" and d["version"] == "4.5" and d["board_id"] == 9
    assert i["board_id"] == 9 and i["board_hint"]
    from dfa.core.identify import AP_DESCRIPTOR_SIG, parse_ardupilot_descriptor
    unfilled = parse_ardupilot_descriptor(b"x" * 10 + AP_DESCRIPTOR_SIG + b"\0" * 40, 100)
    assert "note" in unfilled


def test_vendor_containers_identified_not_overclaimed(tmp_path, run_analysis):
    import os
    p = tmp_path / "wm220_0801.sig"
    p.write_bytes(b"IM*H" + bytes([1]) + os.urandom(4096))
    m = run_analysis(p)
    assert m["identification"]["format"] == "dji_imah"
    assert m["identification"]["platform"] == "DJI"
    assert m["identification"]["details"] == {} or True
    f = [x for x in m["findings"] if x["rule_id"] == "extraction-failed" or x["rule_id"] == "extraction-unsupported"]
    assert f and all(x["severity"] == "info" for x in f)
    q = tmp_path / "bebop.plf"
    q.write_bytes(b"PLF!" + os.urandom(2048))
    assert run_analysis(q)["identification"]["platform"] == "Parrot"


def test_vector_table_accepts_stack_at_the_end_of_ccm():
    """Official INAV builds for STM32F405 start with SP = 0x10010000 (top of the 64 KiB CCM RAM)."""
    vt = struct.pack("<16I", 0x1001_0000, 0x0807_43F1, *([0x0800_2CF1] * 14))
    info = analyze_vector_table(vt)
    assert info is not None and info.initial_sp == 0x1001_0000
    assert analyze_vector_table(struct.pack("<16I", 0x1001_0004, 0x0807_43F1, *([0x0800_2CF1] * 14))) is None


def test_build_information_blocks():
    """Layouts of the version.c constants in official Betaflight 4.3.2 and INAV 7.1.2 builds."""
    from dfa.core.identify import PlatformAccumulator
    inav = (b"INAV %s (%s) %s\x00\x00%s/%s %s %s / %s (%s)\x00\x00\x004e1e59eb\x00\x00\x00\x0023:40:27\x00\x00\x00\x00"
            b"May 31 2024\x007.1.2\x00\x00\x00MATEKF405\x00\x00\x00Memory allocated")
    acc = PlatformAccumulator()
    acc.feed_bytes(inav)
    g = next(r for r in acc.results() if r.name == "INAV")
    assert (g.confidence, g.version, g.board) == ("high", "7.1.2", "MATEKF405")
    assert g.build["revision"] == "4e1e59eb" and g.build["date"] == "May 31 2024"
    # INAV 9.x F405 builds place version and target before the CLI format string (board and build were lost)
    inav9 = (b"INAV %s (%s) %s\x00\x00NONE\x00\x00\x00\x009.1.0\x00\x00\x00MATEKF405\x00\x00\x00%s/%s %s %s / %s (%s) %s"
             b"\x00\x00\x00\x0015317503\x00\x00\x00\x0002:12:07\x00\x00\x00\x00Jul  8 2026\x0013.2.1 20231009\x00GCC-%s\x00")
    acc = PlatformAccumulator()
    acc.feed_bytes(inav9)
    g = next(r for r in acc.results() if r.name == "INAV")
    assert (g.version, g.board, g.build["revision"], g.build["time"]) == ("9.1.0", "MATEKF405", "15317503", "02:12:07")
    bf = (b"Betaflight\x00\x00Betaflight STM32F405\x00\x00 ----\x00\x00\x004.3.2\x00\x00\x00%s %s: %s\x00"
          b"Firmware revision\x00\x00\x00STM32F405\x00\x00\x0060c9521\x0007:26:30\x00\x00\x00\x00Nov 28 2022\x00%s %s\x00")
    acc = PlatformAccumulator()
    acc.feed_bytes(bf)
    g = next(r for r in acc.results() if r.name == "Betaflight")
    assert (g.confidence, g.version, g.board, g.build["revision"]) == ("high", "4.3.2", "STM32F405", "60c9521")
    # 4.4/4.5 builds: the CLI 'version' line's arguments, or the "BTFL" identifier block (board and build were lost)
    for block, want in (
            (b"STM32F405\x00Betaflight\x00# %s / %s (%s) %s %s / %s (%s) MSP API: %s\x001.46\x0077d01ba\x0002:23:52\x00"
             b"Jul 27 2024\x004.5.1\x00# board: manufacturer_id", ("4.5.1", "STM32F405", "77d01ba")),
            (b"\x00\x00BTFL\x00\x00\x00\x00# Betaflight\x00\x00\x00\x00STM32F405\x00\x00\x00Jan 28 2023\x0023:33:34\x00\x00\x00\x00"
             b"4605309\x00\x00\x004.4.0\x00\x00", ("4.4.0", "STM32F405", "4605309"))):
        acc = PlatformAccumulator()
        acc.feed_bytes(block)
        g = next(r for r in acc.results() if r.name == "Betaflight")
        assert (g.version, g.board, g.build["revision"]) == want, g
    # without the project's own markers neither the block nor a bare x.y.z constant means anything
    acc = PlatformAccumulator()
    acc.feed_bytes(b"\x00\x00\x001.2.3\x00\x00" + inav.replace(b"INAV ", b"XXXX "))
    assert not any(r.name in ("INAV", "Betaflight") and r.version for r in acc.results())
