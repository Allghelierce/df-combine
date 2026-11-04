"""Espressif (ESP32 family / ESP8266) firmware structures: application images and flash partition tables.

Layouts follow Espressif's public documentation and esptool (image header, extended header, segment table,
XOR checksum, optional SHA-256 digest, esp_app_desc_t) and ESP-IDF's partition table format.
"""
from __future__ import annotations

import hashlib
import struct

ESP_CHIPS = {0x0000: "ESP32", 0x0002: "ESP32-S2", 0x0005: "ESP32-C3", 0x0009: "ESP32-S3", 0x000C: "ESP32-C2",
             0x000D: "ESP32-C6", 0x0010: "ESP32-H2"}
RISCV_CHIPS = {"ESP32-C3", "ESP32-C2", "ESP32-C6", "ESP32-H2"}
ESP_APP_DESC_MAGIC = 0xABCD5432
ESP_CHECKSUM_SEED = 0xEF


def _esp_segments(data: bytes, pos: int, nseg: int) -> tuple[list[dict], int] | None:
    segs = []
    for _ in range(nseg):
        if pos + 8 > len(data):
            return None
        addr, size = struct.unpack_from("<II", data, pos)
        if pos + 8 + size > len(data) or not 0x3C000000 <= addr < 0x60000000:
            return None
        segs.append({"load_address": hex(addr), "size": size, "offset": pos + 8})
        pos += 8 + size
    if not any(s["size"] for s in segs):
        return None
    return segs, pos


def _esp_checksum(data: bytes, segs: list[dict], end: int) -> bool | None:
    at = end + 15 - end % 16  # esptool pads to 16 bytes and stores the checksum in the last byte
    if at >= len(data):
        return None
    c = ESP_CHECKSUM_SEED
    for seg in segs:
        c ^= _xor_bytes(data[seg["offset"]:seg["offset"] + seg["size"]])
    return c == data[at]


def _xor_bytes(b: bytes) -> int:
    """XOR of all bytes, by repeatedly folding the halves of one big integer (linear time)."""
    x, width = int.from_bytes(b, "little"), len(b)
    while width > 1:
        half = (width + 1) // 2
        x = (x & ((1 << (8 * half)) - 1)) ^ (x >> (8 * half))
        width = half
    return x & 0xFF


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("ascii", "replace").strip()


def esp_app_description(data: bytes, segs: list[dict]) -> dict | None:
    """ESP-IDF esp_app_desc_t (first bytes of the first flash-mapped data segment)."""
    for seg in segs[:2]:
        o = seg["offset"]
        if seg["size"] >= 256 and struct.unpack_from("<I", data, o)[0] == ESP_APP_DESC_MAGIC:
            return {"secure_version": struct.unpack_from("<I", data, o + 4)[0],
                    "version": _cstr(data[o + 16:o + 48]), "project_name": _cstr(data[o + 48:o + 80]),
                    "build_time": f"{_cstr(data[o + 96:o + 112])} {_cstr(data[o + 80:o + 96])}".strip(),
                    "idf_version": _cstr(data[o + 112:o + 144]), "elf_sha256": data[o + 144:o + 176].hex()}
    return None


def parse_esp_image(data: bytes) -> dict | None:
    """Espressif application image (magic 0xE9): ESP32-family layout with the 16-byte extended header,
    or the original ESP8266 layout. The layout whose segment chain and checksum are consistent wins."""
    if len(data) < 24 or data[0] != 0xE9:
        return None
    nseg, entry = data[1], struct.unpack_from("<I", data, 4)[0]
    if not 1 <= nseg <= 16 or not 0x40000000 <= entry < 0x50000000:
        return None
    candidates = []
    chip_id = struct.unpack_from("<H", data, 12)[0]
    if chip_id in ESP_CHIPS:
        r = _esp_segments(data, 24, nseg)
        if r:
            candidates.append((ESP_CHIPS[chip_id], r, data[23] == 1))
    r = _esp_segments(data, 8, nseg)
    if r:
        candidates.append(("ESP8266", r, False))
    best = None
    for chip, (segs, end), hashed in candidates:
        ok = _esp_checksum(data, segs, end)
        rank = (ok is True, ok is None)
        if best is None or rank > best[0]:
            best = (rank, chip, segs, end, hashed, ok)
    if best is None:
        return None
    _, chip, segs, end, hashed, ok = best
    out = {"chip": chip, "entry": hex(entry), "segments": segs, "checksum_valid": ok,
           "architecture": "RISC-V" if chip in RISCV_CHIPS else "Xtensa",
           "image_size": end + 16 - end % 16 + (32 if hashed else 0)}
    if hashed:
        body_end = end + 16 - end % 16
        digest = data[body_end:body_end + 32]
        out["sha256_valid"] = len(digest) == 32 and hashlib.sha256(data[:body_end]).digest() == digest
    app = esp_app_description(data, segs)
    if app:
        out["app"] = app
    return out


# ----------------------------------------------------------------------------- partition tables
PARTITION_TABLE_OFFSET = 0x8000
PARTITION_TABLE_MAX = 0xC00
_APP_SUBTYPES = {0x00: "factory", 0x20: "test", **{0x10 + i: f"ota_{i}" for i in range(16)}}
_DATA_SUBTYPES = {0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump", 0x04: "nvs_keys", 0x05: "efuse",
                  0x06: "undefined", 0x80: "esphttpd", 0x81: "fat", 0x82: "spiffs", 0x83: "littlefs"}


def parse_partition_table(table: bytes) -> dict | None:
    """ESP-IDF partition table: 32-byte entries (magic 0xAA50), optional MD5 entry (0xEBEB), 0xFF terminator."""
    parts: list[dict] = []
    md5_valid = None
    for pos in range(0, min(len(table), PARTITION_TABLE_MAX) - 31, 32):
        e = table[pos:pos + 32]
        if e[:2] == b"\xaa\x50":
            typ, sub = e[2], e[3]
            offset, size = struct.unpack_from("<II", e, 4)
            if size == 0 or offset % 0x1000 or offset < PARTITION_TABLE_OFFSET or offset + size > 1 << 30:
                return None
            label = e[12:28].split(b"\0", 1)[0].decode("ascii", "replace")
            flags = struct.unpack_from("<I", e, 28)[0]
            kind = {0: "app", 1: "data"}.get(typ, f"custom_{typ:#x}")
            sub_name = (_APP_SUBTYPES if typ == 0 else _DATA_SUBTYPES if typ == 1 else {}).get(sub, f"{sub:#x}")
            parts.append({"label": label, "type": kind, "subtype": sub_name, "offset": offset, "size": size,
                          "encrypted": bool(flags & 1), "readonly": bool(flags & 2)})
        elif e[:2] == b"\xeb\xeb":
            md5_valid = hashlib.md5(table[:pos], usedforsecurity=False).digest() == e[16:32]
            break
        elif e == b"\xff" * 32:
            break
        else:
            return None
    if not parts:
        return None
    return {"partitions": parts, "md5_valid": md5_valid}


def looks_like_flash_dump(head: bytes) -> bool:
    if len(head) < PARTITION_TABLE_OFFSET + 32 or head[PARTITION_TABLE_OFFSET:PARTITION_TABLE_OFFSET + 2] != b"\xaa\x50":
        return False
    t = PARTITION_TABLE_OFFSET
    return parse_partition_table(head[t:t + PARTITION_TABLE_MAX]) is not None


def image_header_plausible(head: bytes, size: int) -> bool:
    """Quick check used by format identification (the 0xE9 magic is a single byte)."""
    if len(head) < 32 or head[0] != 0xE9 or not 1 <= head[1] <= 16:
        return False
    if not 0x40000000 <= struct.unpack_from("<I", head, 4)[0] < 0x50000000:
        return False
    if len(head) >= size:  # whole image available: the layout must be consistent (checksum, or exact length)
        info = parse_esp_image(head)
        return bool(info) and (info["checksum_valid"] is True or info["image_size"] == size)
    for pos in (24, 8):  # ESP32-family extended header / ESP8266
        addr, seg = struct.unpack_from("<II", head, pos)
        if seg <= size and 0x3C000000 <= addr < 0x60000000 and (seg or pos == 24):
            return True
    return False
