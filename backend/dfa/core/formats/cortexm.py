"""Heuristics for raw ARM Cortex-M flash images (STM32 et al.).

PX4 (NuttX) and ArduPilot (ChibiOS) flight controller firmware is almost
always a raw Cortex-M image starting with the vector table:
    word 0: initial main stack pointer (points into SRAM)
    word 1: reset handler address (Thumb => odd, points into flash)
Both values are checked against well known STM32 memory ranges.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

# (start, end) inclusive-exclusive ranges.
SRAM_RANGES = [
    (0x1000_0000, 0x1001_0000),  # STM32F4 CCM
    (0x2000_0000, 0x2010_0000),  # SRAM / DTCM
    (0x2400_0000, 0x2410_0000),  # STM32H7 AXI SRAM
    (0x3000_0000, 0x3005_0000),  # STM32H7 SRAM1-3
]
FLASH_RANGES = [
    (0x0000_0000, 0x0020_0000),  # aliased boot / generic Cortex-M (e.g. SAM, NXP)
    (0x0800_0000, 0x0820_0000),  # STM32 main flash
]


@dataclass
class VectorTableInfo:
    initial_sp: int
    reset_handler: int
    flash_base_guess: int
    valid_vectors: int


def _in(ranges: list[tuple[int, int]], v: int) -> bool:
    return any(lo <= v < hi for lo, hi in ranges)


def analyze_vector_table(data: bytes, base_address: int | None = None) -> VectorTableInfo | None:
    if len(data) < 64:
        return None
    sp, reset = struct.unpack_from("<II", data, 0)
    # Cortex-M ignores SP[1:0] on reset; real PX4 builds store e.g. 0x2002b962, so only require an even value.
    if not _in(SRAM_RANGES, sp) or sp % 2 != 0:
        return None
    if reset & 1 == 0 or not _in(FLASH_RANGES, reset & ~1):
        return None
    # Count plausible handlers among the first 16 exception vectors.
    valid = 0
    for i in range(1, 16):
        (v,) = struct.unpack_from("<I", data, i * 4)
        if v == 0 or (v & 1 and _in(FLASH_RANGES, v & ~1)):
            valid += 1
    if valid < 10:
        return None
    if base_address is None:
        base_address = 0x0800_0000 if reset >= 0x0800_0000 else 0
    return VectorTableInfo(initial_sp=sp, reset_handler=reset,
                           flash_base_guess=base_address, valid_vectors=valid)


def estimate_flash_base(data: bytes, max_words: int = 400_000) -> tuple[int, dict] | None:
    """Estimate the load address of a raw Cortex-M image.

    Candidates come from the vector table (reset handler / lowest handler rounded down to common
    bootloader boundaries); each is scored by how many 32-bit words in the image point exactly at
    the start of a printable string when the image is placed at that base (rbasefind-style).
    Returns (base, evidence) or None when the image has no plausible vector table.
    """
    vt = analyze_vector_table(data)
    if vt is None:
        return None
    vectors = [struct.unpack_from("<I", data, i * 4)[0] for i in range(1, min(len(data) // 4, 128))]
    handlers = [v & ~1 for v in vectors if v & 1 and _in(FLASH_RANGES, v & ~1)]
    lo = min(handlers) if handlers else vt.reset_handler & ~1
    cands: set[int] = set()
    for addr in (vt.reset_handler & ~1, lo):
        for align in (0x200, 0x400, 0x1000, 0x4000, 0x8000, 0x10000, 0x20000):
            base = addr & ~(align - 1)
            if all(base <= h < base + len(data) for h in handlers):
                cands.add(base)
    if not cands:
        return None
    # string start offsets
    starts: set[int] = set()
    run = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            run += 1
        else:
            if run >= 5:
                starts.add(i - run)
            run = 0
    words = struct.unpack_from(f"<{min(len(data) // 4, max_words)}I", data, 0)
    scores = {}
    for base in cands:
        end = base + len(data)
        scores[base] = sum(1 for w in words if base <= w < end and (w - base) in starts)
    conventional = (vt.reset_handler & ~1) & ~0x3FFF  # PX4/ArduPilot apps start on 16 KiB boundaries

    def tz(x: int) -> int:
        return (x & -x).bit_length() if x else 64

    best = max(sorted(cands), key=lambda b: (scores[b], b == conventional, tz(b)))
    return best, {"candidates": {hex(b): scores[b] for b in sorted(cands)}, "method": "vector table + string pointers"}
