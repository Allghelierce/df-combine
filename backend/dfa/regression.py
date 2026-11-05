"""Regression signatures for real firmware samples.

A signature captures what the analysis concluded about a sample - identification, extraction shape,
package inventory, components and the rules that fired - in a form that is stable across runs and
reviewable in a diff. ``fixtures/regression/baseline.json`` holds the signatures of the pinned public
samples (scripts/fetch_real_firmware.py); it is generated from actual analysis output by
``scripts/update_regression_baseline.py`` and must never be edited by hand to make a test pass.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

SAMPLES = [
    "px4_fmu-v2_default.px4", "px4_fmu-v5_default.px4", "px4_fmu-v6x_default.px4",
    "ark_can-flow_canbootloader.px4", "px4_fmu-v2_default.elf",
    "px4_v1.15.0_fmu-v5_default.px4", "px4_v1.16.2_fmu-v5_default.px4", "px4_v1.18.0-rc1_fmu-v6x_default.px4",
    "cubepilot_cubeorange_default.px4", "holybro_kakuteh7_default.px4",
    "debian11-armhf-rootfs-20210816.tar.gz", "alpine3.15.0-arm64-rootfs.tar.gz",
    "esp/bootloader_esp32.bin", "esp/bootloader_esp32c3.bin", "esp/esp8266_deepsleep.bin",
    "esp/esp_idf_blink_esp32s2.bin", "esp/partitions_singleapp.bin",
    "ardupilot/fmuv3_bl.bin", "ardupilot/MatekH743_bl.bin", "ardupilot/Pixhawk6X_bl.bin",
    "ardupilot/CubeOrange_bl.bin", "ardupilot/CubeOrange_bl.hex",
    "ardupilot/sitl-linux-copter-3.2.1.tar.gz", "ardupilot/sitl-linux-copter-3.3.tar.gz",
    "ardupilot/sitl-linux-plane-3.3.0.tar.gz", "ardupilot/sitl-linux-rover-2.50.tar.gz",
    "betaflight/betaflight_4.3.2_STM32F405.hex", "betaflight/betaflight_4.3.2_STM32H743.hex",
    "inav/inav_7.1.2_MATEKF405.hex", "inav/inav_7.1.2_MATEKH743.hex", "inav/inav_6.1.1_MATEKF405.hex",
    "inav/inav_9.1.0_MATEKF405.hex",
]


def signature(manifest: dict) -> dict:
    ident = manifest["identification"]
    arts = manifest["extraction"]["artifacts"]
    inv = manifest.get("packages") or {}
    return {
        "identification": {k: ident.get(k) for k in ("format", "platform", "platform_version", "vehicle_type",
                                                      "architecture", "bits", "endianness", "os_hint", "board_id",
                                                      "board_name")},
        "extraction": {
            "artifacts": len(arts),
            "formats": dict(sorted(Counter(a["format"] for a in arts).items())),
            "failed": sorted(a["name"] for a in arts if a.get("extraction") == "failed")[:20],
            "limits_hit": sorted(set(manifest["extraction"].get("limits_hit", []))),
        },
        "packages": {"distro": (inv.get("distro") or {}).get("id"), "count": len(inv.get("packages", [])),
                     "owned_files": len(inv.get("owners") or {})},
        "components": sorted(f"{c['name']} {c['version']}" for c in manifest.get("components", [])),
        "findings": dict(sorted(Counter(f"{f['source_tool']}:{f['rule_id']}" for f in manifest["findings"]).items())),
    }


def diff(expected: dict, actual: dict, path: str = "") -> list[str]:
    out = []
    for k in sorted(set(expected) | set(actual)):
        e, a = expected.get(k), actual.get(k)
        p = f"{path}.{k}" if path else k
        if isinstance(e, dict) and isinstance(a, dict):
            out += diff(e, a, p)
        elif e != a:
            out.append(f"{p}: expected {e!r}, got {a!r}")
    return out


def analyse(sample: Path, work: Path) -> dict:
    from .core.analyze import run
    from .core.limits import Limits
    return signature(run(sample, sample.name, work, Limits()))
