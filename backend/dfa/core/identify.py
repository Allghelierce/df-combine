"""Content-based firmware identification.

File extensions are never trusted: the format is detected from magic bytes
and structure.  Platform detection (PX4, ArduPilot, ...) uses a registry of
signature sets so new drone platforms can be added without touching the
pipeline.
"""
from __future__ import annotations

import math
import re
import struct
from collections import Counter
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .formats.cortexm import analyze_vector_table
from .formats.ihex import looks_like_ihex
from .formats.px4json import looks_like_container

HEAD_BYTES = 64 * 1024


@dataclass
class FormatInfo:
    format: str  # machine readable id, see FORMAT_DESCRIPTIONS
    description: str
    container: bool  # whether the extractor knows how to unpack it
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


FORMAT_DESCRIPTIONS = {
    "elf": "ELF executable/object",
    "zip": "ZIP archive",
    "tar": "POSIX tar archive",
    "gzip": "gzip compressed data",
    "bzip2": "bzip2 compressed data",
    "xz": "xz compressed data",
    "ihex": "Intel HEX firmware image",
    "px4": "PX4 firmware container (.px4, JSON + zlib image)",
    "apj": "ArduPilot firmware container (.apj, JSON + zlib image)",
    "fw_json": "JSON firmware container (unknown vendor)",
    "squashfs": "SquashFS filesystem image",
    "ext": "ext2/3/4 filesystem image",
    "fat": "FAT filesystem image",
    "cpio": "cpio archive",
    "uimage": "U-Boot legacy uImage",
    "ubi": "UBI flash image",
    "ubifs": "UBIFS filesystem image",
    "jffs2": "JFFS2 filesystem image",
    "cortexm_raw": "Raw ARM Cortex-M flash image",
    "romfs": "ROMFS image (NuttX/Linux romfs)",
    "disk_image": "Partitioned disk image (MBR/GPT)",
    "dfu": "DfuSe (STM32 DFU) firmware file",
    "text": "Text file",
    "raw": "Unrecognised binary data",
    "lzma": "LZMA (alone/legacy) compressed data",
    "empty": "Empty file",
}

CONTAINER_FORMATS = {"zip", "tar", "gzip", "bzip2", "xz", "lzma", "ihex", "px4", "apj", "fw_json",
                     "squashfs", "ext", "fat", "cpio", "uimage", "dfu", "romfs", "disk_image", "ubi", "ubifs", "jffs2"}


def _fmt(name: str, **details) -> FormatInfo:
    return FormatInfo(format=name, description=FORMAT_DESCRIPTIONS[name],
                      container=name in CONTAINER_FORMATS, details=details)


def detect_format(path: Path) -> FormatInfo:
    size = path.stat().st_size
    if size == 0:
        return _fmt("empty")
    with path.open("rb") as fp:
        head = fp.read(HEAD_BYTES)
    return detect_format_bytes(head, size)


def detect_format_bytes(head: bytes, size: int) -> FormatInfo:
    if head.startswith(b"\x7fELF"):
        return _fmt("elf")
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return _fmt("zip")
    if len(head) >= 262 and head[257:262] == b"ustar":
        return _fmt("tar")
    if head.startswith(b"\x1f\x8b"):
        return _fmt("gzip")
    if head.startswith(b"BZh") and len(head) > 4 and head[3:4].isdigit():
        return _fmt("bzip2")
    if head.startswith(b"\xfd7zXZ\x00"):
        return _fmt("xz")
    if head[:4] in (b"hsqs", b"sqsh"):
        return _fmt("squashfs", endianness="little" if head[:4] == b"hsqs" else "big")
    if len(head) >= 1082 and head[1080:1082] == b"\x53\xef":
        return _fmt("ext")
    if head[:6] in (b"070701", b"070702", b"070707"):
        return _fmt("cpio", variant=head[:6].decode())
    if head[:4] == b"\x27\x05\x19\x56":
        return _fmt("uimage")
    if head[:4] == b"UBI#":
        return _fmt("ubi")
    if head[:4] == b"\x31\x18\x10\x06":
        return _fmt("ubifs")
    if head[:2] in (b"\x85\x19", b"\x19\x85"):
        return _fmt("jffs2")
    if head[:8] == b"-rom1fs-":
        return _fmt("romfs")
    if head[:5] == b"DfuSe":
        return _fmt("dfu")
    if len(head) >= 512 and head[510:512] == b"\x55\xaa" and (
        head[54:59] == b"FAT12" or head[54:59] == b"FAT16" or head[82:87] == b"FAT32"
    ):
        return _fmt("fat")
    if len(head) >= 512 and head[510:512] == b"\x55\xaa" and _plausible_mbr(head, size):
        return _fmt("disk_image")
    if looks_like_container(head):
        if b"PX4FWv1" in head:
            return _fmt("px4")
        if b"APJFWv1" in head:
            return _fmt("apj")
        return _fmt("fw_json")
    if looks_like_ihex(head):
        return _fmt("ihex")
    if _looks_like_lzma_alone(head):
        return _fmt("lzma")
    vt = analyze_vector_table(head)
    if vt is not None:
        return _fmt("cortexm_raw", initial_sp=hex(vt.initial_sp),
                    reset_handler=hex(vt.reset_handler), flash_base_guess=hex(vt.flash_base_guess))
    if _is_text(head):
        return _fmt("text")
    return _fmt("raw")


def _looks_like_lzma_alone(head: bytes) -> bool:
    """Legacy .lzma header: props byte, power-of-two dictionary size, 64-bit size (or -1)."""
    if len(head) < 13 or head[0] >= 225 or head[0] not in (0x5D, 0x6D, 0x5E):
        return False
    dict_size = struct.unpack_from("<I", head, 1)[0]
    size = struct.unpack_from("<Q", head, 5)[0]
    if dict_size < 1 << 12 or dict_size > 1 << 30 or dict_size & (dict_size - 1):
        return False
    return size == 0xFFFF_FFFF_FFFF_FFFF or 0 < size < 1 << 34


def _plausible_mbr(head: bytes, size: int) -> bool:
    if len(head) >= 520 and head[512:520] == b"EFI PART":
        return True
    found = 0
    for i in range(4):
        e = head[446 + i * 16 : 462 + i * 16]
        if e[4] == 0:
            continue
        if e[0] not in (0x00, 0x80):
            return False
        lba, sectors = struct.unpack("<II", e[8:16])
        if sectors == 0 or lba == 0 or lba * 512 >= size:
            return False
        found += 1
    return found > 0


def _is_text(head: bytes) -> bool:
    if not head:
        return False
    sample = head[:8192]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.95


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def file_entropy(path: Path, max_bytes: int = 8 * 1024**2) -> float:
    with path.open("rb") as fp:
        return round(shannon_entropy(fp.read(max_bytes)), 3)


# --------------------------------------------------------------------------
# Printable strings
# --------------------------------------------------------------------------
def iter_strings(path: Path, min_len: int = 6, max_bytes: int = 64 * 1024**2,
                 chunk: int = 4 * 1024**2) -> Iterator[tuple[int, str]]:
    """Yield (offset, ascii_string) pairs, reading at most ``max_bytes``."""
    pattern = re.compile(rb"[\x20-\x7e\t]{" + str(min_len).encode() + rb",}")
    read_total = 0
    carry = b""
    carry_off = 0
    with path.open("rb") as fp:
        while read_total < max_bytes:
            block = fp.read(min(chunk, max_bytes - read_total))
            if not block:
                break
            buf = carry + block
            base = carry_off
            read_total += len(block)
            last_end = 0
            for m in pattern.finditer(buf):
                if m.end() == len(buf):  # may continue in next chunk
                    break
                yield base + m.start(), m.group().decode("ascii")
                last_end = m.end()
            tail_start = max(last_end, len(buf) - 4096)
            m_tail = pattern.search(buf, tail_start)
            if m_tail and m_tail.end() == len(buf):
                carry = buf[m_tail.start():]
                carry_off = base + m_tail.start()
            else:
                carry = b""
                carry_off = base + len(buf)
        if carry and len(carry) >= min_len:
            yield carry_off, carry.decode("ascii", "replace")


# --------------------------------------------------------------------------
# Platform detection
# --------------------------------------------------------------------------
@dataclass
class PlatformSignature:
    name: str
    family: str  # "flight-controller" | "companion-linux" | "esc" | ...
    strong: list[bytes]  # any one of these is strong evidence
    weak: list[bytes]  # contribute partial evidence
    version_patterns: list[re.Pattern]
    vehicle_patterns: list[re.Pattern] = field(default_factory=list)


PLATFORMS: list[PlatformSignature] = [
    PlatformSignature(
        name="PX4",
        family="flight-controller",
        strong=[b"PX4FWv1", b"PX4 Autopilot", b"px4_platform", b"PX4_GIT_TAG", b"px4io"],
        weak=[b"NuttX", b"uORB", b"commander", b"ekf2", b"navigator", b"mc_att_control",
              b"/fs/microsd", b"sensors", b"nsh>", b"px4_", b"vehicle_status"],
        version_patterns=[
            re.compile(r"PX4[ _-]?(?:Autopilot)?[^\n]{0,24}?\bv?(\d+\.\d+\.\d+(?:-[\w.]+)?)"),
            re.compile(r"\bv(1\.\d{1,2}\.\d{1,2}(?:-(?:alpha|beta|rc)\d*)?)\b"),
        ],
    ),
    PlatformSignature(
        name="ArduPilot",
        family="flight-controller",
        strong=[b"APJFWv1", b"ArduCopter V", b"ArduPlane V", b"ArduRover V", b"ArduSub V",
                b"AntennaTracker V", b"AP_Periph", b"Blimp V",
                bytes([0x40, 0xA2, 0xE4, 0xF1, 0x64, 0x68, 0x91, 0x06])],  # AP app descriptor
        weak=[b"ArduPilot", b"ChibiOS", b"AP_HAL", b"ARMING_CHECK", b"SYSID_THISMAV",
              b"@PARAM", b"PreArm:", b"ArduCopter", b"ArduPlane"],
        version_patterns=[
            re.compile(r"(?:ArduCopter|ArduPlane|ArduRover|ArduSub|AntennaTracker|Blimp|AP_Periph)"
                       r"\s+V(\d+\.\d+\.\d+(?:-?[\w.]+)?)"),
        ],
        vehicle_patterns=[re.compile(r"(ArduCopter|ArduPlane|ArduRover|ArduSub|AntennaTracker|Blimp|AP_Periph)\b")],
    ),
    PlatformSignature(
        name="Betaflight",
        family="flight-controller",
        strong=[b"Betaflight", b"BTFL"],
        weak=[b"betaflight", b"CLI", b"MSP"],
        version_patterns=[re.compile(r"Betaflight\s*/?\s*\w*\s*(\d+\.\d+\.\d+)")],
    ),
    PlatformSignature(
        name="INAV",
        family="flight-controller",
        strong=[b"INAV/", b"INAV "],
        weak=[b"inav"],
        version_patterns=[re.compile(r"INAV/?\s*\w*\s*(\d+\.\d+\.\d+)")],
    ),
    PlatformSignature(
        name="Companion computer (Linux)",
        family="companion-linux",
        strong=[b"mavlink-router", b"mavlink-routerd", b"MAVProxy", b"mavproxy.py", b"ros2", b"mavros"],
        weak=[b"Linux version", b"BusyBox", b"/etc/init.d", b"MAVLink", b"mavlink"],
        version_patterns=[],
    ),
]


@dataclass
class PlatformGuess:
    name: str
    family: str
    confidence: str  # high | medium | low
    score: int
    evidence: list[str]
    version: str | None = None
    vehicle: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class PlatformAccumulator:
    """Streams data blocks through all platform signatures and keeps score."""

    def __init__(self) -> None:
        self.hits: dict[str, dict[bytes, int]] = {p.name: {} for p in PLATFORMS}
        self.versions: dict[str, Counter] = {p.name: Counter() for p in PLATFORMS}
        self.vehicles: dict[str, Counter] = {p.name: Counter() for p in PLATFORMS}
        self.hints: dict[str, list[str]] = {p.name: [] for p in PLATFORMS}

    def feed_bytes(self, block: bytes) -> None:
        for p in PLATFORMS:
            for sig in p.strong + p.weak:
                if sig not in self.hits[p.name] and sig in block:
                    self.hits[p.name][sig] = 1

    def feed_string(self, s: str) -> None:
        for p in PLATFORMS:
            for pat in p.version_patterns:
                m = pat.search(s)
                if m:
                    self.versions[p.name][m.group(1)] += 1
            for pat in p.vehicle_patterns:
                m = pat.search(s)
                if m:
                    self.vehicles[p.name][m.group(1)] += 1

    def hint(self, platform: str, evidence: str) -> None:
        """Strong out-of-band evidence (e.g. container magic) for a platform."""
        self.hints.setdefault(platform, []).append(evidence)

    def results(self) -> list[PlatformGuess]:
        out: list[PlatformGuess] = []
        for p in PLATFORMS:
            strong = [s for s in p.strong if s in self.hits[p.name]]
            weak = [s for s in p.weak if s in self.hits[p.name]]
            hints = self.hints.get(p.name, [])
            score = 10 * len(hints) + 4 * len(strong) + len(weak)
            if score < 3:
                continue
            if hints or len(strong) >= 2 or (strong and len(weak) >= 3):
                conf = "high"
            elif strong or len(weak) >= 5:
                conf = "medium"
            else:
                conf = "low"
            ev = hints + [f"signature '{_show(s)}'" for s in strong] + [f"string '{_show(s)}'" for s in weak]
            version = None
            if self.versions[p.name] and (strong or hints):
                version = self.versions[p.name].most_common(1)[0][0]
            vehicle = self.vehicles[p.name].most_common(1)[0][0] if self.vehicles[p.name] else None
            out.append(PlatformGuess(name=p.name, family=p.family, confidence=conf, score=score,
                                     evidence=ev[:12], version=version, vehicle=vehicle))
        out.sort(key=lambda g: -g.score)
        return out


def _show(sig: bytes) -> str:
    if all(32 <= b < 127 for b in sig):
        return sig.decode()
    return sig.hex(" ")


def scan_file_for_platform(path: Path, acc: PlatformAccumulator, max_bytes: int,
                           chunk: int = 4 * 1024**2) -> None:
    overlap = 32
    prev = b""
    read = 0
    with path.open("rb") as fp:
        while read < max_bytes:
            block = fp.read(min(chunk, max_bytes - read))
            if not block:
                break
            read += len(block)
            acc.feed_bytes(prev[-overlap:] + block)
            prev = block


# --------------------------------------------------------------------------
# Architecture helpers
# --------------------------------------------------------------------------
UIMAGE_ARCH = {2: "ARM", 3: "x86", 5: "MIPS", 7: "PowerPC", 22: "AArch64", 26: "RISC-V", 4: "IA64"}


def parse_uimage_header(head: bytes) -> dict | None:
    if len(head) < 64 or head[:4] != b"\x27\x05\x19\x56":
        return None
    (_magic, _hcrc, ts, size, load, ep, _dcrc, os_, arch, itype, comp) = struct.unpack(
        ">IIIIIIIBBBB", head[:32])
    name = head[32:64].split(b"\x00", 1)[0].decode("ascii", "replace")
    return {"timestamp": ts, "data_size": size, "load_address": hex(load), "entry_point": hex(ep),
            "os": os_, "arch": UIMAGE_ARCH.get(arch, f"id {arch}"), "image_type": itype,
            "compression": {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}.get(comp, str(comp)),
            "name": name}


AP_DESCRIPTOR_SIG = bytes([0x40, 0xA2, 0xE4, 0xF1, 0x64, 0x68, 0x91, 0x06])


def parse_ardupilot_descriptor(data: bytes, file_size: int) -> dict | None:
    """Parse ArduPilot's app_descriptor (written by the build's post-processing step).

    Layout: sig[8], image_crc1 u32, image_crc2 u32, image_size u32, git_hash u32,
    version_major u8, version_minor u8, board_id u16, reserved[8].  Fields are only
    reported when plausible; an unfilled descriptor (all zeros) is reported as present only.
    """
    i = data.find(AP_DESCRIPTOR_SIG)
    if i < 0 or i + 36 > len(data):
        return None
    crc1, crc2, size, git, vmaj, vmin, board = struct.unpack_from("<IIIIBBH", data, i + 8)
    out: dict = {"offset": hex(i)}
    if size and size <= file_size and vmaj < 20:
        out.update({"image_size": size, "git_hash": f"{git:08x}", "version": f"{vmaj}.{vmin}",
                    "board_id": board, "crc1": f"{crc1:08x}", "crc2": f"{crc2:08x}"})
    else:
        out["note"] = "descriptor present but not populated/plausible"
    return out
