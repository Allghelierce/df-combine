"""Additional firmware formats: streaming decompressors (LZ4, Zstandard, lzop) and parsers for
CramFS, Android sparse images, Parrot PLF and DJI IM*H containers.

Every reader is bounded: decompressors are streamed (callers charge the extraction budget per
chunk) and use explicit memory/window limits; parsers validate offsets against the file size.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .simplefs import Entry, FormatError

CHUNK = 1024 * 1024
ZSTD_MAX_WINDOW = 1 << 27  # 128 MiB decoder window limit


# ----------------------------------------------------------------------------- decompressors
class _Reader:
    def __init__(self, path: Path) -> None:
        self.fp = path.open("rb")

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.fp.close()


class ZstdReader(_Reader):
    def __init__(self, path: Path) -> None:
        import zstandard
        super().__init__(path)
        dctx = zstandard.ZstdDecompressor(max_window_size=ZSTD_MAX_WINDOW)
        self.stream = dctx.stream_reader(self.fp, read_across_frames=True)

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(CHUNK)


class Lz4FrameReader(_Reader):
    MAGIC = b"\x04\x22\x4d\x18"

    def __init__(self, path: Path) -> None:
        import lz4.frame
        super().__init__(path)
        self._new = lz4.frame.LZ4FrameDecompressor
        self.d = self._new()
        self.pending = b""

    def read(self, size: int = -1) -> bytes:
        while True:
            if self.d.eof:
                rest = self.d.unused_data or b""
                if len(rest) < 4:
                    rest += self.fp.read(4 - len(rest))
                if rest[:4] != self.MAGIC:
                    return b""
                self.d, self.pending = self._new(), rest  # concatenated frame
            if self.d.needs_input:
                data, self.pending = self.pending or self.fp.read(64 * 1024), b""
                if not data:
                    raise EOFError("truncated LZ4 frame")
            else:
                data = b""
            out = self.d.decompress(data, max_length=CHUNK)
            if out:
                return out


class Lz4LegacyReader(_Reader):
    """Legacy LZ4 format (magic 0x184C2102) as used for compressed Linux kernels/initramfs."""

    BLOCK = 8 * 1024 * 1024

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        if self.fp.read(4) != b"\x02\x21\x4c\x18":
            raise FormatError("not a legacy LZ4 stream")

    def read(self, size: int = -1) -> bytes:
        import lz4.block
        while True:
            hdr = self.fp.read(4)
            if len(hdr) < 4:
                return b""
            n = struct.unpack("<I", hdr)[0]
            if n == 0x184C2102:  # next concatenated stream
                continue
            if n == 0 or n > self.BLOCK + 65536:
                return b""  # trailing data (e.g. kernel size field)
            block = self.fp.read(n)
            if len(block) < n:
                raise EOFError("truncated LZ4 legacy block")
            try:
                out = lz4.block.decompress(block, uncompressed_size=self.BLOCK)
            except Exception as exc:  # noqa: BLE001 - lz4 raises LZ4BlockError
                raise FormatError(f"corrupt LZ4 block: {exc}") from None
            if out:
                return out


class LzopReader(_Reader):
    """lzop files (LZO1X), parsed per the lzop file format."""

    MAGIC = b"\x89LZO\x00\r\n\x1a\n"
    F_ADLER32_D, F_ADLER32_C, F_H_EXTRA_FIELD, F_CRC32_D, F_CRC32_C, F_H_FILTER = 1, 2, 0x40, 0x100, 0x200, 0x800

    def __init__(self, path: Path) -> None:
        from lzallright import LZOCompressor
        super().__init__(path)
        self.lzo = LZOCompressor()
        if self.fp.read(9) != self.MAGIC:
            raise FormatError("not an lzop file")
        version, _lib, _need = struct.unpack(">HHH", self.fp.read(6))
        method, _level = self.fp.read(2)
        flags = struct.unpack(">I", self.fp.read(4))[0]
        if flags & self.F_H_FILTER:
            self.fp.read(4)
        self.fp.read(12)  # mode, mtime_low, mtime_high
        name_len = self.fp.read(1)[0]
        self.fp.read(name_len)
        self.fp.read(4)  # header checksum
        if flags & self.F_H_EXTRA_FIELD:
            extra = struct.unpack(">I", self.fp.read(4))[0]
            self.fp.read(extra + 4)
        if method not in (1, 2, 3):
            raise FormatError(f"unsupported lzop method {method}")
        self.flags = flags

    def read(self, size: int = -1) -> bytes:
        hdr = self.fp.read(4)
        if len(hdr) < 4:
            return b""
        dst_len = struct.unpack(">I", hdr)[0]
        if dst_len == 0:
            return b""
        if dst_len > 64 * 1024 * 1024:
            raise FormatError("lzop block too large")
        src_len = struct.unpack(">I", self.fp.read(4))[0]
        skip = 4 * bool(self.flags & self.F_ADLER32_D) + 4 * bool(self.flags & self.F_CRC32_D)
        if src_len < dst_len:
            skip += 4 * bool(self.flags & self.F_ADLER32_C) + 4 * bool(self.flags & self.F_CRC32_C)
        self.fp.read(skip)
        data = self.fp.read(src_len)
        if len(data) < src_len:
            raise EOFError("truncated lzop block")
        if src_len == dst_len:
            return data
        out = self.lzo.decompress(data, output_size_hint=dst_len)
        if len(out) != dst_len:
            raise FormatError("lzop block size mismatch")
        return out


# ----------------------------------------------------------------------------- CramFS
CRAMFS_MAGIC_LE = b"\x45\x3d\xcd\x28"
CRAMFS_SIG = b"Compressed ROMFS"


def cramfs_offset(head: bytes) -> int | None:
    for off in (0, 512):
        if head[off:off + 4] == CRAMFS_MAGIC_LE and head[off + 16:off + 32] == CRAMFS_SIG:
            return off
    return None


def iter_cramfs(fp: BinaryIO, total: int, max_entries: int, max_file: int):
    """Yield (Entry, data|None) for a little-endian CramFS image (zlib blocks)."""
    fp.seek(0)
    head = fp.read(1024)
    base = cramfs_offset(head)
    if base is None:
        raise FormatError("not a little-endian CramFS image")
    size, flags = struct.unpack_from("<II", head, base + 4)
    if flags & 0x00000400:  # CRAMFS_FLAG_EXT_BLOCK_POINTERS (direct pointers)
        raise FormatError("CramFS extended block pointers are not supported")
    count = [0]

    def inode_at(off: int) -> tuple[int, int, int, int, int, int]:
        fp.seek(off)
        raw = fp.read(12)
        if len(raw) < 12:
            raise FormatError("truncated CramFS inode")
        w0, w1, w2 = struct.unpack("<III", raw)
        mode, uid = w0 & 0xFFFF, w0 >> 16
        isize, gid = w1 & 0xFFFFFF, w1 >> 24
        namelen, offset = (w2 & 0x3F) * 4, (w2 >> 6) * 4
        return mode, uid, gid, isize, namelen, offset

    def read_file(offset: int, isize: int) -> bytes:
        nblocks = (isize + 4095) // 4096
        if offset + 4 * nblocks > total:
            raise FormatError("CramFS block table out of range")
        fp.seek(offset)
        ptrs = struct.unpack(f"<{nblocks}I", fp.read(4 * nblocks)) if nblocks else ()
        start = offset + 4 * nblocks
        out = bytearray()
        for p in ptrs:
            uncompressed = bool(p & 0x80000000)
            end = p & 0x3FFFFFFF
            if not start <= end <= total:
                raise FormatError("CramFS block pointer out of range")
            fp.seek(start)
            blk = fp.read(end - start)
            if uncompressed:
                out += blk
            elif blk:
                d = zlib.decompressobj()
                out += d.decompress(blk, 4096 + 1)
            start = end
            if len(out) > max_file:
                raise FormatError("CramFS file exceeds per-file limit")
        return bytes(out[:isize])

    def walk(dir_off: int, dir_size: int, prefix: str, depth: int):
        if depth > 64:
            raise FormatError("CramFS directory nesting too deep")
        pos, end = dir_off, dir_off + dir_size
        if end > total:
            raise FormatError("CramFS directory out of range")
        while pos < end:
            mode, uid, gid, isize, namelen, offset = inode_at(pos)
            fp.seek(pos + 12)
            name = fp.read(namelen).split(b"\x00", 1)[0].decode("utf-8", "replace")
            pos += 12 + namelen
            count[0] += 1
            if count[0] > max_entries:
                raise FormatError("too many CramFS entries")
            path = f"{prefix}/{name}" if prefix else name
            fmt = mode & 0o170000
            if fmt == 0o040000:
                yield Entry(path, "dir", mode & 0o7777, 0, 0, uid=uid, gid=gid), None
                if isize and offset:
                    yield from walk(offset, isize, path, depth + 1)
            elif fmt == 0o100000:
                yield Entry(path, "file", mode & 0o7777, isize, 0, uid=uid, gid=gid), read_file(offset, isize)
            elif fmt == 0o120000:
                target = read_file(offset, isize).decode("utf-8", "replace") if isize < 4096 else None
                yield Entry(path, "symlink", 0o777, 0, 0, link_target=target), None
            else:
                yield Entry(path, "other", mode & 0o7777, 0, 0), None

    mode, uid, gid, isize, namelen, offset = inode_at(base + 64)  # root inode follows the 64-byte header
    if size > total + 512:
        raise FormatError("CramFS size field exceeds file size")
    yield from walk(offset, isize, "", 0)


# ----------------------------------------------------------------------------- Android sparse
SPARSE_MAGIC = b"\x3a\xff\x26\xed"


@dataclass
class SparseInfo:
    block_size: int
    total_blocks: int
    total_chunks: int
    chunk_hdr: int
    file_hdr: int


def sparse_header(head: bytes) -> SparseInfo | None:
    if len(head) < 28 or head[:4] != SPARSE_MAGIC:
        return None
    _m, major, _minor, file_hdr, chunk_hdr, blk, blocks, chunks, _crc = struct.unpack("<IHHHHIIII", head[:28])
    if major != 1 or blk == 0 or blk % 4 or file_hdr < 28 or chunk_hdr < 12:
        return None
    return SparseInfo(blk, blocks, chunks, chunk_hdr, file_hdr)


# ----------------------------------------------------------------------------- Parrot PLF
PLF_MAGIC = 0x21464C50  # "PLF!"
PLF_SECTION_NAMES = {0x00: "zimage", 0x03: "initrd", 0x07: "bootparams_or_bootloader", 0x09: "file_action"}


@dataclass
class PlfSection:
    index: int
    type: int
    size: int
    load_addr: int
    uncompressed_size: int
    offset: int


def parse_plf(fp: BinaryIO, total: int) -> tuple[dict, list[PlfSection]]:
    """Header and section table of a Parrot PLF file (layout from the public plftool/libplf)."""
    fp.seek(0)
    hdr = fp.read(0x38)
    if len(hdr) < 0x38 or struct.unpack_from("<I", hdr, 0)[0] != PLF_MAGIC:
        raise FormatError("not a PLF file")
    (_m, hv, hsize, shsize, ftype, entry, plat, appl, hw, vmaj, vmin, vbug, lang, fsize) = struct.unpack("<14I", hdr)
    if not 0x38 <= hsize <= 4096 or shsize < 20 or fsize > total + 4096:
        raise FormatError("implausible PLF header")
    meta = {"header_version": hv, "file_type": {1: "executable", 2: "archive"}.get(ftype, ftype),
            "entry_point": hex(entry), "target_platform": plat, "target_application": appl,
            "hw_compat": hw, "version": f"{vmaj}.{vmin}.{vbug}", "language_zone": lang}
    sections = []
    pos = hsize
    while pos + shsize <= total and len(sections) < 4096:
        fp.seek(pos)
        sh = fp.read(20)
        stype, ssize, _crc, load, usize = struct.unpack("<5I", sh)
        data_off = pos + shsize
        if ssize == 0 and stype == 0 and usize == 0:
            break
        if data_off + ssize > total:
            raise FormatError("PLF section exceeds file size")
        sections.append(PlfSection(len(sections), stype, ssize, load, usize, data_off))
        pos = data_off + ssize + ((4 - (ssize & 3)) & 3)
    if not sections:
        raise FormatError("PLF file without sections")
    return meta, sections


def inflate_any(data: bytes, limit: int) -> bytes:
    """gzip, zlib or raw deflate (PLF sections use gzip-style compression)."""
    for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(data, limit + 1)
            if len(out) > limit:
                raise FormatError("decompressed section exceeds limit")
            if d.eof or out:
                return out
        except zlib.error:
            continue
    raise FormatError("section is not deflate/gzip compressed")


# ----------------------------------------------------------------------------- DJI IM*H
@dataclass
class ImahInfo:
    header_version: int
    header_size: int
    signature_size: int
    payload_size: int
    name: str
    module_type: str
    version: str
    date: str
    auth_key: str
    enc_key: str
    chunks: list[dict] = field(default_factory=list)


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("ascii", "replace")


def parse_imah(fp: BinaryIO, total: int) -> ImahInfo:
    """Parse the plaintext header and chunk table of a DJI IM*H module (layout per o-gs/dji-firmware-tools).

    Nothing is decrypted: only chunks that the header marks as plaintext (attrib bit 0, or an empty
    encryption key id) can be extracted by the caller.
    """
    fp.seek(0)
    h = fp.read(192)
    if len(h) < 192 or h[:4] != b"IM*H":
        raise FormatError("not an IM*H module")
    hv, size, hsize, ssize, psize, _tsize = struct.unpack_from("<II4xIIII", h, 4)
    auth_key, enc_key = h[40:44], h[44:48]
    name, mtype = _cstr(h[64:96]), _cstr(h[96:100])
    version, date = struct.unpack_from("<II", h, 100)
    chunk_num = struct.unpack_from("<I", h, 156)[0]
    if hsize < 192 or hsize > total or chunk_num > 256 or hsize < 192 + 32 * chunk_num:
        raise FormatError("implausible IM*H header")
    info = ImahInfo(hv, hsize, ssize, psize, name, mtype,
                    f"{version >> 24 & 0xff:02d}.{version >> 16 & 0xff:02d}.{version >> 8 & 0xff:02d}.{version & 0xff:02d}",
                    f"{date:08x}", _cstr(auth_key), _cstr(enc_key))
    fp.seek(192)
    for i in range(chunk_num):
        c = fp.read(32)
        cid = _cstr(c[0:4]) or f"{i:02d}"
        off, csize, attrib = struct.unpack_from("<III", c, 4)
        addr = struct.unpack_from("<Q", c, 16)[0]
        data_off = hsize + ssize + off
        plaintext = bool(attrib & 0x01) or enc_key == b"\x00\x00\x00\x00"
        info.chunks.append({"id": "".join(ch if ch.isalnum() else "_" for ch in cid), "offset": data_off,
                            "size": csize, "attrib": hex(attrib), "address": hex(addr), "plaintext": plaintext,
                            "in_bounds": data_off + csize <= total})
    return info
