#!/usr/bin/env python3
"""Generate synthetic firmware samples (PX4/ArduPilot/companion/malicious) for demos and tests.

Usage: python scripts/generate_fixtures.py [output_dir]   (default: fixtures/generated)

All content is synthetic. "Private keys" are random bytes in PEM armour, not real keys.
No proprietary firmware is downloaded or included.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "tests"))
import factory  # noqa: E402

out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "fixtures" / "generated"
for key, path in factory.generate_all(out).items():
    print(f"{key:14s} {path.stat().st_size:>10,d}  {path}")
