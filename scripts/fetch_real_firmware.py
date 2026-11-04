#!/usr/bin/env python3
"""Download legitimate, publicly distributed drone firmware used by the real-firmware tests.

Only official open-source builds are listed (PX4 Autopilot, BSD-3-Clause, published by the PX4
project in its public firmware bucket that QGroundControl downloads from). Files are verified
against pinned SHA-256 hashes; nothing is committed to the repository.

Usage: python scripts/fetch_real_firmware.py [dest]   (default: fixtures/real)
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

BASE = "https://px4-travis.s3.amazonaws.com/Firmware/stable/"
SAMPLES = {
    # name: (sha256, size, description)
    "px4_fmu-v5_default.px4": ("b50b275507da4cb0e218c943c2aff5359e3f0914c18f6b563494b925c0a0e403", 1881838,
                               "PX4 v1.17.0 for FMUv5 (Pixhawk 4), official .px4 container"),
    "px4_fmu-v6x_default.px4": ("3206a5f445d85be730a4f6158d8fdd414b9cfab27fa84bbc05c6a6752deac284", 1824468,
                                "PX4 v1.17.0 for FMUv6X, official .px4 container"),
    "px4_fmu-v2_default.px4": ("114900817ba313645df853f0b9b916c69efac92d442c31360a44f925588de9d8", 989576,
                               "PX4 v1.17.0 for FMUv2 (Pixhawk 1), official .px4 container"),
    "ark_can-flow_canbootloader.px4": ("36394d7c70153cbc19ea77259fd5c3205fb263194134e62d0ce865e04103a202", 21687,
                                       "PX4 CAN bootloader for ARK Flow"),
    "px4_fmu-v2_default.elf": ("372115d6f53b76a024ef03de640ed5132a61c4b5bfe668cc5c447e4a322d917e", 22976388,
                               "PX4 v1.17.0 FMUv2 unstripped ELF (symbols + DWARF)"),
    "px4_fmu-v5_default.elf": ("4ff1bbb8b9ae1be361b2d5e0993fce4981bacf17373e34f20954bb4c0e219432", 47202280,
                               "PX4 v1.17.0 FMUv5 unstripped ELF (symbols + DWARF)"),
}


def fetch(dest: Path, names: list[str] | None = None) -> dict[str, Path]:
    dest.mkdir(parents=True, exist_ok=True)
    out = {}
    for name, (sha, size, desc) in SAMPLES.items():
        if names and name not in names:
            continue
        p = dest / name
        if not (p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == sha):
            print(f"downloading {name} ({size:,} bytes) - {desc}")
            tmp = p.with_suffix(p.suffix + ".part")
            with urllib.request.urlopen(BASE + name, timeout=300) as r, tmp.open("wb") as fp:  # noqa: S310
                while chunk := r.read(1 << 20):
                    fp.write(chunk)
            digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
            if digest != sha:
                tmp.unlink()
                raise SystemExit(f"checksum mismatch for {name}: {digest} (upstream file changed?)")
            tmp.rename(p)
        out[name] = p
    return out


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "fixtures" / "real"
    for n, p in fetch(target).items():
        print(f"ok {n} -> {p}")
