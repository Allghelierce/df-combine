#!/usr/bin/env python3
"""Regenerate fixtures/regression/baseline.json from the analysis of the fetched real samples.

Run after an intentional behaviour change, review the diff, and commit it with the change:

    python scripts/fetch_real_firmware.py
    python scripts/update_regression_baseline.py
    git diff fixtures/regression/baseline.json
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from dfa.regression import SAMPLES, analyse  # noqa: E402

REAL = ROOT / "fixtures" / "real"
OUT = ROOT / "fixtures" / "regression" / "baseline.json"


def main() -> int:
    baseline = json.loads(OUT.read_text()) if OUT.exists() else {}
    for name in SAMPLES:
        p = REAL / name
        if not p.exists():
            print(f"skip {name} (not fetched)")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            baseline[name] = analyse(p, Path(tmp) / "work")
        print(f"ok   {name}: {baseline[name]['identification']['format']} / "
              f"{baseline[name]['identification']['platform']}, {sum(baseline[name]['findings'].values())} findings")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(baseline, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
