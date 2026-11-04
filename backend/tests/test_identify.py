import json
import shutil
import struct

from dfa.core.formats.cortexm import analyze_vector_table
from dfa.core.formats.ihex import IHexError, parse_ihex
from dfa.core.formats.px4json import ContainerError, parse_container
from dfa.core.identify import detect_format, detect_format_bytes, parse_uimage_header

import factory
import pytest


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
