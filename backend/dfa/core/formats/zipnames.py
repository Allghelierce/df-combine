"""Zip archives with an entry flagged UTF-8 (general-purpose bit 11) whose name is not valid UTF-8.

Python's zipfile decodes such names strictly, both in the central directory and in the entry's local
header, so a single one makes the whole archive unreadable: everything in it would go unanalysed
(``unzip`` extracts it fine). ``utf8_flag_fixes`` finds those entries; ``PatchedReader`` presents the
file with their UTF-8 flag cleared, so zipfile reads the names byte for byte (cp437), and the caller
shows them with ``\\xNN`` escapes like any other name that is not UTF-8. The file itself is not modified.
"""
from __future__ import annotations

import bisect
import io
import struct
from pathlib import Path

_EOCD, _CDH, _LFH = b"PK\x05\x06", b"PK\x01\x02", b"PK\x03\x04"
_UTF8_FLAG_HIGH = 0x08  # bit 11 of the little-endian flag field, in its second byte


def utf8_flag_fixes(path: Path) -> tuple[dict[int, int], dict[str, str]]:
    """({file offset: patched byte}, {name as zipfile reads it after patching: name to show}).

    Raises ValueError for a directory this does not walk (zip64, damaged)."""
    with path.open("rb") as fp:
        size = fp.seek(0, io.SEEK_END)
        tail_len = min(size, 65_535 + 22)
        fp.seek(size - tail_len)
        tail = fp.read(tail_len)
        pos = tail.rfind(_EOCD)
        if pos < 0 or tail_len - pos < 22:
            raise ValueError("zip end-of-central-directory record not found")
        _sig, _d, _cd, _n_disk, count, cd_size, cd_off, _c = struct.unpack_from("<4sHHHHIIH", tail, pos)
        if 0xFFFFFFFF in (cd_size, cd_off) or count == 0xFFFF:
            raise ValueError("zip64 archive with a UTF-8-flagged name that is not UTF-8")
        concat = size - tail_len + pos - cd_size - cd_off  # data prepended to the archive, as zipfile allows
        if concat < 0:
            raise ValueError("zip central directory lies outside the file")
        fp.seek(cd_off + concat)
        cd = fp.read(cd_size)
        patches: dict[int, int] = {}
        shown: dict[str, str] = {}
        i = 0
        for _ in range(count):
            if cd[i:i + 4] != _CDH or i + 46 > len(cd):
                raise ValueError("damaged zip central directory")
            (flags,) = struct.unpack_from("<H", cd, i + 8)
            nlen, elen, clen = struct.unpack_from("<HHH", cd, i + 28)
            (local,) = struct.unpack_from("<I", cd, i + 42)
            raw = cd[i + 46:i + 46 + nlen]
            if flags & 0x800 and not _is_utf8(raw):
                patches[cd_off + concat + i + 9] = (flags >> 8) & ~_UTF8_FLAG_HIGH & 0xFF
                fp.seek(local + concat)
                lfh = fp.read(30)
                if len(lfh) < 30 or lfh[:4] != _LFH:
                    raise ValueError("damaged zip local header")
                patches[local + concat + 7] = lfh[7] & ~_UTF8_FLAG_HIGH & 0xFF
                # as tarfile and os.walk decode names; safe_member_path escapes the bytes after its separator check
                shown[raw.decode("cp437")] = raw.decode("utf-8", "surrogateescape")
            i += 46 + nlen + elen + clen
    return patches, shown


def _is_utf8(raw: bytes) -> bool:
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


class PatchedReader(io.RawIOBase):
    """Read-only, seekable view of a file with a few single bytes replaced."""

    def __init__(self, path: Path, patches: dict[int, int]) -> None:
        super().__init__()
        self._fp = path.open("rb")
        self._offsets = sorted(patches)
        self._patches = patches

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._fp.seek(offset, whence)

    def tell(self) -> int:
        return self._fp.tell()

    def readinto(self, buf) -> int:  # noqa: ANN001 - any writable buffer
        start = self._fp.tell()
        n = self._fp.readinto(buf)
        if n:
            view = memoryview(buf).cast("B")
            lo = bisect.bisect_left(self._offsets, start)
            hi = bisect.bisect_left(self._offsets, start + n)
            for off in self._offsets[lo:hi]:
                view[off - start] = self._patches[off]
        return n or 0

    def close(self) -> None:
        self._fp.close()
        super().close()
