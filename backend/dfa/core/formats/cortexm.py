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
    if not _in(SRAM_RANGES, sp) or sp % 4 != 0:
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
