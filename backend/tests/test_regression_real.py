"""Regression suite over real, publicly distributed firmware (scripts/fetch_real_firmware.py).

Each sample's analysis signature must match fixtures/regression/baseline.json. When a change alters
results on purpose, regenerate the baseline with scripts/update_regression_baseline.py and review the diff.
Samples that are not fetched are skipped.
"""
import json
from pathlib import Path

import pytest

from dfa.regression import SAMPLES, analyse, diff

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "fixtures" / "real"
BASELINE = json.loads((ROOT / "fixtures" / "regression" / "baseline.json").read_text())


@pytest.mark.parametrize("name", SAMPLES)
def test_real_sample_matches_baseline(name, tmp_path):
    if not (REAL / name).exists():
        pytest.skip(f"{name} not fetched (python scripts/fetch_real_firmware.py)")
    assert name in BASELINE, f"no baseline for {name}; run scripts/update_regression_baseline.py"
    problems = diff(BASELINE[name], analyse(REAL / name, tmp_path / "work"))
    assert not problems, "\n".join(problems)


def test_baseline_covers_every_sample():
    assert sorted(BASELINE) == sorted(SAMPLES)
