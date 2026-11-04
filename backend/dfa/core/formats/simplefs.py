"""Pure-Python parsers for small, simple container formats.

* cpio (newc/crc "070701"/"070702" and odc "070707")
* romfs ("-rom1fs-", used by NuttX/PX4 to embed /etc init scripts)
* DfuSe (STM32 DFU files, "DfuSe" prefix)
* MBR / GPT partition tables (disk images such as Raspberry Pi companion images)

All parsers operate on bounded inputs and yield entries; they never write
files themselves - the extractor decides where (and whether) to write.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator


class FormatError(ValueError):
    pass


@dataclass
class Entry:
    name: str
    kind: str  # "file" | "dir" | "symlink" | "other"
    mode: int
    size: int
    offset: int  # data offset in the source stream (for files)
    link_target: str | None = None
    uid: int = 0
    gid: int = 0


# ---------------------------------------------------------------- cpio
def _kind_from_mode(mode: int) -> str:
    fmt = mode & 0o170000
    return {0o100000: "file", 0o040000: "dir", 0o120000: "symlink"}.get(fmt, "other")


def iter_cpio(fp: BinaryIO, total_size: int, max_entries: int) -> Iterator[Entry]:
    pos = 0
    count = 0
    while pos < total_size:
        fp.seek(pos)
        magic = fp.read(6)
        if magic in (b"070701", b"070702"):
            hdr = magic + fp.read(104)
            if len(hdr) < 110:
                raise FormatError("truncated cpio newc header")
            try:
                fields = [int(hdr[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
            except ValueError:
                raise FormatError("invalid cpio newc header") from None
            mode, uid, gid, filesize, namesize = fields[1], fields[2], fields[3], fields[6], fields[11]
            name_off = pos + 110
            data_off = (name_off + namesize + 3) & ~3
            next_pos = (data_off + filesize + 3) & ~3
        elif magic == b"070707":
            hdr = magic + fp.read(70)
            if len(hdr) < 76:
                raise FormatError("truncated cpio odc header")
            try:
                mode = int(hdr[18:24], 8)
                uid = int(hdr[24:30], 8)
                gid = int(hdr[30:36], 8)
                namesize = int(hdr[59:65], 8)
                filesize = int(hdr[65:76], 8)
            except ValueError:
                raise FormatError("invalid cpio odc header") from None
            name_off = pos + 76
            data_off = name_off + namesize
            next_pos = data_off + filesize
        else:
            raise FormatError(f"bad cpio magic at offset {pos}")
        if namesize > 4096 or data_off + filesize > total_size:
            raise FormatError("cpio entry exceeds archive bounds")
        fp.seek(name_off)
        name = fp.read(namesize).split(b"\x00", 1)[0].decode("utf-8", "replace")
        if name == "TRAILER!!!":
            return
        kind = _kind_from_mode(mode)
        link = None
        if kind == "symlink" and filesize <= 4096:
            fp.seek(data_off)
            link = fp.read(filesize).decode("utf-8", "replace")
        yield Entry(name=name, kind=kind, mode=mode & 0o7777, size=filesize, offset=data_off,
                    link_target=link, uid=uid, gid=gid)
        count += 1
        if count > max_entries:
            raise FormatError("too many cpio entries")
        if next_pos <= pos:
            raise FormatError("cpio parser made no progress")
        pos = next_pos


# ---------------------------------------------------------------- romfs
ROMFS_MAGIC = b"-rom1fs-"


def _romfs_name(fp: BinaryIO, off: int) -> tuple[str, int]:
    fp.seek(off)
    raw = b""
    while True:
        chunk = fp.read(16)
        if len(chunk) < 16:
            raise FormatError("truncated romfs name")
        raw += chunk
        if b"\x00" in chunk or len(raw) > 1024:
            break
    name = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return name, off + len(raw)


def romfs_size(head: bytes) -> int | None:
    if len(head) < 16 or head[:8] != ROMFS_MAGIC:
        return None
    return struct.unpack(">I", head[8:12])[0]


def iter_romfs(fp: BinaryIO, base: int, total_size: int, max_entries: int) -> Iterator[Entry]:
    fp.seek(base)
    hdr = fp.read(16)
    size = romfs_size(hdr)
    if size is None:
        raise FormatError("not a romfs image")
    size = min(size, total_size - base)
    _vol, first = _romfs_name(fp, base + 16)
    first -= base
    seen: set[int] = set()
    count = 0
    stack: list[tuple[int, str]] = [(first, "")]
    while stack:
        off, prefix = stack.pop()
        while off and off < size:
            if off in seen:
                raise FormatError("romfs loop detected")
            seen.add(off)
            fp.seek(base + off)
            h = fp.read(16)
            if len(h) < 16:
                raise FormatError("truncated romfs file header")
            nxt, spec, fsize, _csum = struct.unpack(">IIII", h)
            ftype = nxt & 0x7
            executable = bool(nxt & 0x8)
            name, data_off = _romfs_name(fp, base + off + 16)
            data_rel = data_off - base
            if data_rel + fsize > size and ftype == 2:
                raise FormatError("romfs file exceeds image bounds")
            path = f"{prefix}/{name}" if prefix else name
            if name not in (".", ".."):
                if ftype == 1:
                    yield Entry(name=path, kind="dir", mode=0o755, size=0, offset=0)
                    stack.append((spec & ~0xF, path))
                elif ftype == 2:
                    yield Entry(name=path, kind="file", mode=0o755 if executable else 0o644,
                                size=fsize, offset=data_off)
                elif ftype == 3:
                    fp.seek(data_off)
                    tgt = fp.read(min(fsize, 4096)).decode("utf-8", "replace")
                    yield Entry(name=path, kind="symlink", mode=0o777, size=0, offset=0, link_target=tgt)
                count += 1
                if count > max_entries:
                    raise FormatError("too many romfs entries")
            off = nxt & ~0xF


# ---------------------------------------------------------------- DfuSe
@dataclass
class DfuElement:
    target: int
    target_name: str
    address: int
    size: int
    offset: int


def parse_dfuse(fp: BinaryIO, total_size: int) -> tuple[dict, list[DfuElement]]:
    fp.seek(0)
    prefix = fp.read(11)
    if len(prefix) < 11 or prefix[:5] != b"DfuSe":
        raise FormatError("not a DfuSe file")
    version, image_size, targets = struct.unpack("<BIB", prefix[5:11])
    if targets > 255 or image_size > total_size:
        raise FormatError("invalid DfuSe header")
    pos = 11
    elements: list[DfuElement] = []
    for t in range(targets):
        fp.seek(pos)
        tp = fp.read(274)
        if len(tp) < 274 or tp[:6] != b"Target":
            raise FormatError("invalid DfuSe target prefix")
        alt = tp[6]
        named = struct.unpack("<I", tp[7:11])[0]
        tname = tp[11:266].split(b"\x00", 1)[0].decode("ascii", "replace") if named else ""
        tsize, nelem = struct.unpack("<II", tp[266:274])
        pos += 274
        end = pos + tsize
        if end > total_size or nelem > 4096:
            raise FormatError("DfuSe target exceeds file bounds")
        for _ in range(nelem):
            fp.seek(pos)
            eh = fp.read(8)
            if len(eh) < 8:
                raise FormatError("truncated DfuSe element")
            addr, size = struct.unpack("<II", eh)
            if pos + 8 + size > end:
                raise FormatError("DfuSe element exceeds target bounds")
            elements.append(DfuElement(target=alt, target_name=tname, address=addr, size=size, offset=pos + 8))
            pos += 8 + size
        pos = end
    meta = {"dfuse_version": version, "targets": targets}
    fp.seek(max(total_size - 16, 0))
    suffix = fp.read(16)
    if len(suffix) == 16 and suffix[8:11] == b"UFD":
        bcd_device, pid, vid = struct.unpack("<HHH", suffix[0:6])
        meta.update({"usb_vid": f"{vid:04x}", "usb_pid": f"{pid:04x}", "bcd_device": f"{bcd_device:04x}"})
    return meta, elements


# ---------------------------------------------------------------- partitions
@dataclass
class Partition:
    index: int
    type_id: str
    offset: int
    size: int
    name: str = ""


MBR_TYPES = {0x0B: "FAT32", 0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x06: "FAT16", 0x83: "Linux",
             0x82: "Linux swap", 0x05: "Extended", 0x0F: "Extended (LBA)", 0xEE: "GPT protective",
             0x01: "FAT12", 0x04: "FAT16 <32M", 0x07: "NTFS/exFAT"}


def parse_partitions(fp: BinaryIO, total_size: int) -> tuple[str, list[Partition]]:
    fp.seek(0)
    mbr = fp.read(512)
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
        raise FormatError("no partition table signature")
    fp.seek(512)
    if fp.read(8) == b"EFI PART":
        return "gpt", _parse_gpt(fp, total_size)
    parts: list[Partition] = []
    for i in range(4):
        e = mbr[446 + i * 16 : 462 + i * 16]
        status, ptype = e[0], e[4]
        lba, sectors = struct.unpack("<II", e[8:16])
        if ptype == 0 or sectors == 0:
            continue
        if status not in (0x00, 0x80):
            raise FormatError("invalid MBR partition status byte")
        off, size = lba * 512, sectors * 512
        if off >= total_size:
            raise FormatError("MBR partition starts beyond end of image")
        parts.append(Partition(index=i + 1, type_id=MBR_TYPES.get(ptype, f"0x{ptype:02x}"),
                               offset=off, size=min(size, total_size - off)))
    if not parts:
        raise FormatError("MBR has no partitions")
    return "mbr", parts


def _parse_gpt(fp: BinaryIO, total_size: int) -> list[Partition]:
    fp.seek(512)
    hdr = fp.read(92)
    entries_lba, n_entries, entry_size = struct.unpack("<QII", hdr[72:88])
    if entry_size < 128 or entry_size > 1024 or n_entries > 256:
        raise FormatError("unsupported GPT header values")
    parts: list[Partition] = []
    for i in range(n_entries):
        fp.seek(entries_lba * 512 + i * entry_size)
        e = fp.read(entry_size)
        if len(e) < 128 or e[:16] == b"\x00" * 16:
            continue
        first, last = struct.unpack("<QQ", e[32:48])
        name = e[56:128].decode("utf-16-le", "replace").rstrip("\x00")
        off = first * 512
        size = (last - first + 1) * 512
        if off >= total_size or last < first:
            continue
        type_guid = e[:16]
        tid = {bytes.fromhex("af3dc60f838472478e793d69d8477de4"): "Linux filesystem",
               bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b"): "EFI System",
               bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7"): "Microsoft basic data"}.get(type_guid, type_guid.hex())
        parts.append(Partition(index=i + 1, type_id=tid, offset=off, size=min(size, total_size - off), name=name))
    if not parts:
        raise FormatError("GPT has no partitions")
    return parts
