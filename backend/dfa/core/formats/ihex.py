"""Intel HEX parser (bounded).

Converts an Intel HEX text file into a flat binary image.  Gaps are filled
with 0xFF (erased flash).  The address span is capped to prevent a tiny HEX
file from describing a multi-gigabyte image.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class IHexError(ValueError):
    pass


@dataclass
class IHexImage:
    base_address: int
    data: bytes
    start_address: int | None = None
    record_count: int = 0
    segments: list[tuple[int, int]] = field(default_factory=list)  # (addr, length)


def looks_like_ihex(head: bytes) -> bool:
    """Quick check on the first bytes of a file."""
    text = head.lstrip(b"\xef\xbb\xbf").lstrip()
    if not text.startswith(b":"):
        return False
    lines = [ln.strip() for ln in text.splitlines()[:8] if ln.strip()]
    if not lines:
        return False
    # The last line may be truncated by the head read; validate complete ones.
    checked = 0
    for ln in lines[:-1] or lines:
        try:
            _parse_line(ln.decode("ascii"))
        except (IHexError, UnicodeDecodeError):
            return False
        checked += 1
    return checked > 0


def _parse_line(line: str) -> tuple[int, int, int, bytes]:
    if not line.startswith(":"):
        raise IHexError("record does not start with ':'")
    try:
        raw = bytes.fromhex(line[1:])
    except ValueError as exc:
        raise IHexError(f"invalid hex digits: {exc}") from None
    if len(raw) < 5:
        raise IHexError("record too short")
    count, addr_hi, addr_lo, rtype = raw[0], raw[1], raw[2], raw[3]
    if len(raw) != count + 5:
        raise IHexError("record length mismatch")
    if (sum(raw) & 0xFF) != 0:
        raise IHexError("checksum mismatch")
    return rtype, (addr_hi << 8) | addr_lo, count, raw[4 : 4 + count]


def parse_ihex(text: bytes, max_span: int = 64 * 1024**2) -> IHexImage:
    chunks: dict[int, bytes] = {}
    upper = 0
    seg_base = 0
    start = None
    records = 0
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip().lstrip(b"\xef\xbb\xbf")
        if not line:
            continue
        try:
            rtype, addr, count, payload = _parse_line(line.decode("ascii"))
        except UnicodeDecodeError:
            raise IHexError(f"line {lineno}: non-ASCII data") from None
        except IHexError as exc:
            raise IHexError(f"line {lineno}: {exc}") from None
        records += 1
        if rtype == 0x00:
            absolute = upper + seg_base + addr
            chunks[absolute] = payload
        elif rtype == 0x01:
            break
        elif rtype == 0x02:
            seg_base = int.from_bytes(payload, "big") * 16
            upper = 0
        elif rtype == 0x04:
            upper = int.from_bytes(payload, "big") << 16
            seg_base = 0
        elif rtype in (0x03, 0x05):
            start = int.from_bytes(payload, "big")
        else:
            raise IHexError(f"line {lineno}: unknown record type {rtype:#x}")
    if not chunks:
        raise IHexError("no data records")
    lo = min(chunks)
    hi = max(a + len(d) for a, d in chunks.items())
    if hi - lo > max_span:
        raise IHexError(f"address span {hi - lo:#x} exceeds limit {max_span:#x}")
    image = bytearray(b"\xff" * (hi - lo))
    segments: list[tuple[int, int]] = []
    for a in sorted(chunks):
        d = chunks[a]
        image[a - lo : a - lo + len(d)] = d
        if segments and segments[-1][0] + segments[-1][1] == a:
            segments[-1] = (segments[-1][0], segments[-1][1] + len(d))
        else:
            segments.append((a, len(d)))
    return IHexImage(base_address=lo, data=bytes(image), start_address=start,
                     record_count=records, segments=segments)
