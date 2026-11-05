#!/usr/bin/env python3
"""Download legitimate, publicly distributed firmware used by the real-firmware tests.

Only official open-source builds are listed: PX4 Autopilot (BSD-3-Clause, published by the PX4 project in
the public firmware bucket that QGroundControl downloads from), ArduPilot's prebuilt bootloaders that are
committed in the ArduPilot repository (GPL-3.0, tag Copter-4.5.7), ArduPilot vehicle builds for SITL
(software-in-the-loop) that DroneKit publishes in its public asset bucket for `dronekit-sitl` (GPL-3.0;
x86-64 Linux ELF programs - analysed statically, never run), official Betaflight and INAV release builds
from the projects' GitHub releases (GPL-3.0), and the Espressif image fixtures that ship with esptool's own
test suite (GPL-2.0, tag v4.8.1). Files are verified against pinned SHA-256 hashes; nothing is committed to
the repository.

Usage: python scripts/fetch_real_firmware.py [dest]   (default: fixtures/real)
"""
from __future__ import annotations

import hashlib
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = "https://px4-travis.s3.amazonaws.com/Firmware/stable/"
ESPTOOL = "https://raw.githubusercontent.com/espressif/esptool/v4.8.1/test/images/"
APBL = "https://raw.githubusercontent.com/ArduPilot/ardupilot/Copter-4.5.7/Tools/bootloaders/"
APSITL = "https://dronekit-assets.s3.amazonaws.com/sitl/"
BETAFLIGHT = "https://github.com/betaflight/betaflight/releases/download/"
INAV = "https://github.com/iNavFlight/inav/releases/download/"
SAMPLES = {
    # name: (sha256, size, description[, url]) - url is a base (ending in '/') or the file's full URL
    "px4_fmu-v5_default.px4": ("b50b275507da4cb0e218c943c2aff5359e3f0914c18f6b563494b925c0a0e403", 1881838,
                               "PX4 v1.17.0 for FMUv5 (Pixhawk 4), official .px4 container"),
    "px4_fmu-v6x_default.px4": ("3206a5f445d85be730a4f6158d8fdd414b9cfab27fa84bbc05c6a6752deac284", 1824468,
                                "PX4 v1.17.0 for FMUv6X, official .px4 container"),
    "px4_fmu-v2_default.px4": ("114900817ba313645df853f0b9b916c69efac92d442c31360a44f925588de9d8", 989576,
                               "PX4 v1.17.0 for FMUv2 (Pixhawk 1), official .px4 container"),
    "ark_can-flow_canbootloader.px4": ("36394d7c70153cbc19ea77259fd5c3205fb263194134e62d0ce865e04103a202", 21687,
                                       "PX4 CAN bootloader for ARK Flow"),
    # STM32H7 boards (128 KiB bootloader sector: application at 0x08020000)
    "cubepilot_cubeorange_default.px4": ("153f7532061bb79c99209e174d2383d65a8a85ac033578f984f9ee70d74c3076",
                                         1806473, "PX4 v1.17.0 for CubePilot CubeOrange (STM32H7)"),
    "holybro_kakuteh7_default.px4": ("0cb298edc1872ed56d89f4d6473375e03ec7f19abbe77896d083385bd2c1e56f", 1665724,
                                     "PX4 v1.17.0 for Holybro Kakute H7 (STM32H743)"),
    # earlier official releases of the same board (versioned folders of the same bucket)
    "px4_v1.15.0_fmu-v5_default.px4": (
        "792eb47d9241a279b83e532f3a24c99833e10856b6c4f35eb23c46bca7f64a66", 1897294,
        "PX4 v1.15.0 for FMUv5 ('threaded' CROMFS directory lists)",
        "https://px4-travis.s3.amazonaws.com/Firmware/v1.15.0/px4_fmu-v5_default.px4"),
    "px4_v1.16.2_fmu-v5_default.px4": (
        "0eda4323502126a2ee0a017a3e5b1e024327db5fc19b82cd0bb5562331a1bdfe", 1909718,
        "PX4 v1.16.2 for FMUv5", "https://px4-travis.s3.amazonaws.com/Firmware/v1.16.2/px4_fmu-v5_default.px4"),
    "px4_v1.18.0-rc1_fmu-v6x_default.px4": (
        "88c438c85d3b9432696b70f37a05fa82607097d8d3da9b01dc6d2182babf853c", 1830972,
        "PX4 v1.18.0-rc1 for FMUv6X (NuttX 12.12.0; bootloader and xz metadata in its CROMFS)",
        "https://px4-travis.s3.amazonaws.com/Firmware/v1.18.0-rc1/px4_fmu-v6x_default.px4"),
    "px4_fmu-v2_default.elf": ("372115d6f53b76a024ef03de640ed5132a61c4b5bfe668cc5c447e4a322d917e", 22976388,
                               "PX4 v1.17.0 FMUv2 unstripped ELF (symbols + DWARF)"),
    "px4_fmu-v5_default.elf": ("4ff1bbb8b9ae1be361b2d5e0993fce4981bacf17373e34f20954bb4c0e219432", 47202280,
                               "PX4 v1.17.0 FMUv5 unstripped ELF (symbols + DWARF)"),
    "esp/bootloader_esp32.bin": ("914a9797c100fd51a4845c2bfcd9f2206f2a72552c697531090dc6df41e1e90e", 7888,
                                 "ESP-IDF 2nd-stage bootloader for ESP32 (esptool test fixture)", ESPTOOL),
    "esp/bootloader_esp32c3.bin": ("ec4834595c67a4d353c2516df35e37f9152bb4de12d4d4671fe35a08b51cc9d5", 17744,
                                   "ESP-IDF bootloader for ESP32-C3, RISC-V, SHA-256 appended", ESPTOOL),
    "esp/esp8266_deepsleep.bin": ("ea4ecfa2cf39210dcf0e030cd994952b63dad03b681e4eb0141bf6fc5ebfe902", 297632,
                                  "Arduino ESP8266 application (eboot + app image)", ESPTOOL),
    "esp/esp_idf_blink_esp32s2.bin": ("a62c4d60cfab37953fd76124fa93ea5bafa3e2962fd75ad933b2a75b4d941d12", 182368,
                                      "ESP-IDF v5.0 'blink' application for ESP32-S2", ESPTOOL),
    "esp/partitions_singleapp.bin": ("88449960589ae349edd5afe868b7ef6a3592fbe79b161c14267d2811f157ec8a", 96,
                                     "ESP-IDF partition table (single factory app)", ESPTOOL),
    # Official ArduPilot bootloader builds committed in the ArduPilot repository (GPL-3.0)
    "ardupilot/fmuv3_bl.bin": ("f3c082aa26ed42e40fb799b47b3b08e04814c5e73421763750bea0b7264fa8fe", 16256,
                               "ArduPilot AP_Bootloader for fmuv3 (Pixhawk 1/2.4.8, STM32F4)", APBL),
    "ardupilot/MatekH743_bl.bin": ("1097d07f6090a3d755a7ce67cd799810a24d043a1d51440b578245424981fa1b", 17404,
                                   "ArduPilot AP_Bootloader for Matek H743 (STM32H7)", APBL),
    "ardupilot/Pixhawk6X_bl.bin": ("d544bc268682587007b00a065497dd0c82e7a6b4199f2d3d12a3de6c83197bf6", 38848,
                                   "ArduPilot AP_Bootloader for Pixhawk 6X", APBL),
    "ardupilot/CubeOrange_bl.bin": ("37957c99bd035aa378a6f28309cd94e36e8371f331b828dee5d232a927df2052", 38800,
                                    "ArduPilot AP_Bootloader for CubeOrange", APBL),
    "ardupilot/CubeOrange_bl.hex": ("13006870ecb150cd7667a27261d9db48c35fe8f5e74d4fb145b7ae46771ccd45", 106728,
                                    "ArduPilot AP_Bootloader for CubeOrange (Intel HEX)", APBL),
    # ArduPilot vehicle firmware built for SITL (dronekit-sitl's public bucket): ./apm (x86-64 ELF),
    # default.parm and default_eeprom.bin. Older releases; they exercise vehicle/version identification.
    "ardupilot/sitl-linux-copter-3.2.1.tar.gz": (
        "8ffa1390fb779a3a70f69ee5fd454e344576717451e83a1105be806ef4b3fdef", 870400,
        "ArduCopter 3.2.1 SITL build ('ArduCopter V3.2.1')", APSITL + "copter/"),
    "ardupilot/sitl-linux-copter-3.3.tar.gz": (
        "c975ae44174c3fb897255b7c9dc6606a3e2cde9f8506e4cc99da023bd17a7c91", 849920,
        "ArduCopter 3.3 SITL build ('APM:Copter V3.3')", APSITL + "copter/"),
    "ardupilot/sitl-linux-plane-3.3.0.tar.gz": (
        "067f599aa9afe7a23406dc8d09e7298727b44a8fe9e185a8c2baf0eba68fe9aa", 757760,
        "ArduPlane 3.3.0 SITL build", APSITL + "plane/"),
    "ardupilot/sitl-linux-rover-2.50.tar.gz": (
        "3b00c6dc0c3cbaccb812dbd99220544b3bcf6c19cfafb284c88fd674c147c869", 655360,
        "ArduRover 2.50 SITL build ('ArduRover v2.50')", APSITL + "rover/"),
    # Official Betaflight (unified-target MCU builds) and INAV (per-board) release builds, Intel HEX
    "betaflight/betaflight_4.3.2_STM32F405.hex": (
        "d5020c655f6d722ee085490dcfd96a799d5c45a9842754fe167ad9ddcc683812", 1501011,
        "Betaflight 4.3.2 for STM32F405 (official release)", BETAFLIGHT + "4.3.2/"),
    "betaflight/betaflight_4.3.2_STM32H743.hex": (
        "4e7dc985e26acd7b1e4a15f36a7c6b4c91c00ea44dbea473cd5c7c35e53572c8", 1601416,
        "Betaflight 4.3.2 for STM32H743 (official release)", BETAFLIGHT + "4.3.2/"),
    "betaflight/betaflight_4.5.1_STM32F405.hex": (
        "a2e366a2422b0b78ec37c2e4e88335c9f382694c49b99ca79306c362affe0729", 1576755,
        "Betaflight 4.5.1 for STM32F405 (official release; build information with the CLI version line)",
        BETAFLIGHT + "4.5.1/"),
    "inav/inav_7.1.2_MATEKF405.hex": (
        "b7e6be9d846817474417992d3429ab1cfda1cc6b22fda99a6be51209045fae16", 1660770,
        "INAV 7.1.2 for Matek F405 (official release; initial SP in CCM RAM)", INAV + "7.1.2/"),
    "inav/inav_7.1.2_MATEKH743.hex": (
        "43b8aa7d10bf8eae5ca7454102e08c06d80890492bfdc56600a7d610ccc7b24c", 1722249,
        "INAV 7.1.2 for Matek H743 (official release)", INAV + "7.1.2/"),
    "inav/inav_6.1.1_MATEKF405.hex": (
        "e32ccea58504e183de505c92c24dd1ebff8b6f2c9c49173a6e719e22ae78ef1c", 1530180,
        "INAV 6.1.1 for Matek F405 (official release)", INAV + "6.1.1/"),
    "inav/inav_9.1.0_MATEKF405.hex": (
        "e0cab3e31f05eb6e53d4f75fd3369bc90b02297baecb4182532b34bc28972017", 1757494,
        "INAV 9.1.0 for Matek F405 (official release; version and target before the CLI format string)",
        INAV + "9.1.0/"),
}


def download(src: str, tmp: Path, attempts: int = 5) -> None:
    """GitHub's release CDN and S3 sometimes answer 5xx/429 or drop the connection; such errors are retried
    with backoff (2, 4, 8, 16 s). Anything else, or the last failure, stops with the URL named."""
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(src, timeout=300) as r, tmp.open("wb") as fp:  # noqa: S310
                while chunk := r.read(1 << 20):
                    fp.write(chunk)
            return
        except urllib.error.HTTPError as exc:
            if (exc.code < 500 and exc.code != 429) or attempt == attempts:
                raise SystemExit(f"download of {src} failed: HTTP {exc.code} {exc.reason}") from None
            reason = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt == attempts:
                raise SystemExit(f"download of {src} failed: {exc}") from None
            reason = str(exc)
        print(f"  attempt {attempt} failed ({reason}); retrying in {2 ** attempt}s", flush=True)
        time.sleep(2 ** attempt)


def fetch(dest: Path, names: list[str] | None = None) -> dict[str, Path]:
    dest.mkdir(parents=True, exist_ok=True)
    out = {}
    for name, (sha, size, desc, *url) in SAMPLES.items():
        if names and name not in names:
            continue
        p = dest / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if not (p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == sha):
            print(f"downloading {name} ({size:,} bytes) - {desc}", flush=True)
            tmp = p.with_suffix(p.suffix + ".part")
            src = url[0] if url and not url[0].endswith("/") else (url[0] if url else BASE) + Path(name).name
            download(src, tmp)
            digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
            if digest != sha:
                tmp.unlink()
                raise SystemExit(f"checksum mismatch for {name}: {digest} (upstream file changed?)")
            tmp.rename(p)
        out[name] = p
    return out


if __name__ == "__main__":
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1].startswith("-")):
        print(__doc__)  # no options: '--help' is not a destination directory
        raise SystemExit(0 if sys.argv[1:] in (["-h"], ["--help"]) else 2)
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "fixtures" / "real"
    for n, p in fetch(target).items():
        print(f"ok {n} -> {p}")
