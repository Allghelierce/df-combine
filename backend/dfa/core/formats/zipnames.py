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
import zipfile
from pathlib import Path

_EOCD, _CDH, _LFH = b"PK\x05\x06", b"PK\x01\x02", b"PK\x03\x04"
_UTF8_FLAG_HIGH = 0x08  # bit 11 of the little-endian flag field, in its second byte


def utf8_flag_fixes(path: Path) -> tuple[dict[int, int], dict[str, str]]:
    """({file offset: patched byte}, {name as zipfile reads it after patching: name to show}).

    Raises ValueError for a directory this does not walk (damaged, truncated)."""
    with path.open("rb") as fp:
        start, cd_size, concat = _central_directory(fp)
        fp.seek(start)
        cd = fp.read(cd_size)
        if len(cd) != cd_size:
            raise ValueError("truncated zip central directory")
        patches: dict[int, int] = {}
        shown: dict[str, str] = {}
        i = 0
        while i < cd_size:  # walked as zipfile walks it: by size, not by the entry count the end record declares
            if cd[i:i + 4] != _CDH or i + 46 > len(cd):
                raise ValueError("damaged zip central directory")
            (flags,) = struct.unpack_from("<H", cd, i + 8)
            csize, usize = struct.unpack_from("<II", cd, i + 20)
            nlen, elen, clen = struct.unpack_from("<HHH", cd, i + 28)
            (local,) = struct.unpack_from("<I", cd, i + 42)
            raw = cd[i + 46:i + 46 + nlen]
            if flags & 0x800 and not _is_utf8(raw):
                if local == 0xFFFFFFFF:
                    local = _zip64_header_offset(cd[i + 46 + nlen:i + 46 + nlen + elen], usize, csize)
                patches[start + i + 9] = (flags >> 8) & ~_UTF8_FLAG_HIGH & 0xFF
                # a local header precedes the central directory; one claimed anywhere else is left unpatched (that
                # member cannot be read, the others can) - patching there could forge an end record (a decoy)
                if 0 <= local + concat <= start - 30:
                    fp.seek(local + concat)
                    lfh = fp.read(30)
                    if lfh[:4] == _LFH:
                        patches[local + concat + 7] = lfh[7] & ~_UTF8_FLAG_HIGH & 0xFF
                # as tarfile and os.walk decode names; safe_member_path escapes the bytes after its separator check
                shown[raw.decode("cp437")] = raw.decode("utf-8", "surrogateescape")
            i += 46 + nlen + elen + clen
        entries = cd.count(_CDH)  # an upper bound; zipfile must not read a directory elsewhere or a longer one
    with zipfile.ZipFile(PatchedReader(path, patches)) as zf:
        if zf.start_dir != start or len(zf.infolist()) > entries:
            raise ValueError("the patched archive reads a different central directory")
    return patches, shown


def _central_directory(fp) -> tuple[int, int, int]:  # noqa: ANN001 - a binary file
    """(start of the central directory, its size, bytes prepended to the archive), found the way the running
    zipfile finds them - zip64 end records included - so that the patches land where zipfile reads."""
    try:
        endrec = zipfile._EndRecData(fp)  # noqa: SLF001 - zipfile's own reading of the end records
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"zip end records unreadable ({exc})") from exc
    if not endrec:
        raise ValueError("zip end-of-central-directory record not found")
    size_cd, off_cd, loc = endrec[zipfile._ECD_SIZE], endrec[zipfile._ECD_OFFSET], endrec[zipfile._ECD_LOCATION]
    if endrec[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64:
        fp.seek(loc)
        if fp.read(4) == _EOCD:  # zipfile before the zip64 locator checks: the classic record's position
            loc -= zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator
    start = loc - size_cd  # = offset_cd + concat in zipfile
    if start < 0:
        raise ValueError("bad offset for the zip central directory")
    return start, size_cd, start - off_cd


def _zip64_header_offset(extra: bytes, usize: int, csize: int) -> int:
    """The local header offset from a zip64 extra field (0x0001), as zipfile's ZipInfo._decodeExtra reads it:
    the 64-bit fields present are those whose 32-bit counterparts are 0xFFFFFFFF, in this order."""
    i = 0
    while i + 4 <= len(extra):
        tp, ln = struct.unpack_from("<HH", extra, i)
        if tp == 1:
            skip = 8 * ((usize == 0xFFFFFFFF) + (csize == 0xFFFFFFFF))
            if i + 4 + skip + 8 > min(len(extra), i + 4 + ln):
                break
            return struct.unpack_from("<Q", extra, i + 4 + skip)[0]
        i += 4 + ln
    raise ValueError("zip64 extra field without the local header offset")


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
