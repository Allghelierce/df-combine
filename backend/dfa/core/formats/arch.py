"""Instruction-set detection for raw binaries without headers (binwalk -A style opcode signatures).

Each architecture has a few very common, distinctive instruction encodings (function prologues,
returns). Counting them per architecture over the image gives a robust vote for code regions; the
result is only reported when one architecture clearly dominates.
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass

MAX_SCAN = 8 * 1024 * 1024
ANY = range(256)


def _sig(*parts: bytes | Iterable[int]) -> tuple[re.Pattern, float]:
    """Byte signature from literal bytes and byte-value sets. Returns the regex and the probability that it
    matches at a given offset of uniformly random data (used to discount chance matches)."""
    rx, p = b"", 1.0
    for part in parts:
        if isinstance(part, bytes):
            rx += re.escape(part)
            p /= 256 ** len(part)
            continue
        vals = sorted(set(part))
        rx += b"." if len(vals) == 256 else b"[" + b"".join(re.escape(bytes([v])) for v in vals) + b"]"
        p *= len(vals) / 256
    return re.compile(rx, re.S), p


# (architecture label, bits, endianness, signatures): common prologue/epilogue encodings
_SIGS: list[tuple[str, int, str, list[tuple[re.Pattern, float]]]] = [
    ("ARM (32-bit)", 32, "little", [_sig(range(0x40, 0x60), b"\x2d\xe9"),  # push {.., lr}
                                    _sig(b"\x1e\xff\x2f\xe1"),  # bx lr
                                    _sig(range(0x80, 0xA0), b"\xbd\xe8")]),  # pop {.., pc}
    ("ARM Thumb-2", 32, "little", [_sig(b"\x70\x47"),  # bx lr
                                   _sig(b"\xb5", ANY, ANY, ANY, b"\xbd"),  # push {.., lr}; insn; pop {.., pc}
                                   _sig(b"\x2d\xe9", ANY, range(0x40, 0x60)),  # push.w {.., lr}
                                   _sig(b"\xbd\xe8", ANY, range(0x80, 0xA0))]),  # pop.w {.., pc}
    ("AArch64", 64, "little", [_sig(b"\xc0\x03\x5f\xd6"),  # ret
                               _sig(b"\xfd\x7b", range(0x80, 0xC0), b"\xa9")]),  # stp x29, x30, [sp, #-n]!
    ("MIPS", 32, "big", [_sig(b"\x03\xe0\x00\x08"), _sig(b"\x27\xbd\xff")]),  # jr ra / addiu sp, sp, -n
    ("MIPS", 32, "little", [_sig(b"\x08\x00\xe0\x03"), _sig(b"\xff\xbd\x27")]),
    ("PowerPC", 32, "big", [_sig(b"\x4e\x80\x00\x20"), _sig(b"\x7c\x08\x02\xa6")]),  # blr / mflr r0
    ("x86-64", 64, "little", [_sig(b"\x55\x48\x89\xe5"), _sig(b"\xf3\x0f\x1e\xfa"),  # frame setup / endbr64
                              _sig(b"\x48\x83\xec"), _sig(b"\x48\x83\xc4")]),  # sub/add rsp, imm8
    ("x86", 32, "little", [_sig(b"\x55\x89\xe5"), _sig(b"\x5d\xc3")]),  # push ebp; mov ebp, esp / pop ebp; ret
    ("Xtensa", 32, "little", [_sig(b"\x36", (0x41, 0x61, 0x81, 0xA1, 0xC1, 0xE1), b"\x00"),  # entry a1, n
                              _sig(b"\x1d\xf0"),  # retw.n (windowed ABI, ESP32)
                              _sig(b"\x0d\xf0"),  # ret.n (call0 ABI, ESP8266)
                              _sig(b"\x12\xc1", range(0x80, 0x100))]),  # addi a1, a1, -n
    ("RISC-V", 32, "little", [_sig(b"\x67\x80\x00\x00"),  # ret
                              _sig(b"\x82\x80")]),  # c.ret
]


@dataclass
class ArchGuess:
    architecture: str
    bits: int
    endianness: str
    hits: int
    runner_up: str | None
    runner_up_hits: int
    scores: dict

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def guess_architecture(data: bytes, min_hits: int = 24, dominance: float = 2.5) -> ArchGuess | None:
    """Vote by instruction-signature counts. Each count is discounted by what uniformly random bytes of the
    same length would produce (plus six standard deviations), so compressed/encrypted data yields None."""
    data = data[:MAX_SCAN]
    if not data:
        return None
    hits: dict[tuple[str, int, str], int] = {}
    excess: dict[tuple[str, int, str], float] = {}
    for arch, bits, end, sigs in _SIGS:
        n = sum(len(rx.findall(data)) for rx, _ in sigs)
        expected = len(data) * sum(p for _, p in sigs)
        key = (arch, bits, end)
        hits[key] = n
        excess[key] = n - expected - 6 * math.sqrt(expected)
    ranked = sorted(excess.items(), key=lambda kv: -kv[1])
    (best, e1), (second, e2) = ranked[0], ranked[1]
    if e1 < min_hits or e1 < dominance * max(e2, 1.0):
        return None
    return ArchGuess(best[0], best[1], best[2], hits[best], f"{second[0]} ({second[2]})", hits[second],
                     {f"{a} ({e})": hits[(a, b, e)] for (a, b, e), _ in ranked[:6]})
