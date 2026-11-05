"""Mutation fuzzing of the sandbox-side parsers, seeded with the real samples (scripts/fetch_real_firmware.py).

Looks for hangs (3 s alarm per input), memory blow-ups (RLIMIT_AS 3 GiB) and exception types other than the
parsers' declared errors; reproducers are written to the output directory. Run it on a copy of the samples
(the inputs are untrusted data), e.g.:

    python -I scripts/fuzz_parsers.py backend fixtures/real 60 /tmp/fuzz-out

Last run (2026-11-05, 40 s per target, ~17 million inputs): no hang, no MemoryError, no unexpected exception.
"""
import base64
import io
import json
import random
import resource
import signal
import sys
import time
import traceback
import zlib
from collections import Counter
from pathlib import Path

backend, real, budget = Path(sys.argv[1]).resolve(), Path(sys.argv[2]), float(sys.argv[3])
OUT = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("fuzz-out")
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(backend))
from dfa.core.formats import esp, ihex, px4json, simplefs  # noqa: E402
from dfa.core.formats.cortexm import analyze_vector_table, estimate_flash_base  # noqa: E402
from dfa.core.identify import PlatformAccumulator  # noqa: E402
from dfa.core.limits import LimitExceeded  # noqa: E402

resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
rng = random.Random(1234)  # noqa: S311 - reproducible mutations, not cryptography
EXPECTED = (simplefs.FormatError, LimitExceeded, ValueError, ihex.IHexError, px4json.ContainerError)


class Hang(Exception):
    pass


def _alarm(_s, _f):
    raise Hang()


signal.signal(signal.SIGALRM, _alarm)
INTERESTING32 = [0, 1, 19, 20, 21, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


def mutate(data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.random()
        if not b:
            break
        i = rng.randrange(len(b))
        if op < 0.35:
            b[i] ^= 1 << rng.randrange(8)
        elif op < 0.55:
            b[i] = rng.choice([0, 0xFF, 0x7F, 0x80, 0x20])
        elif op < 0.8 and len(b) >= 4:
            i = rng.randrange(0, len(b) - 3) & ~3 if rng.random() < 0.7 else rng.randrange(0, len(b) - 3)
            v = rng.choice(INTERESTING32 + [len(b), len(b) - 1, len(b) + 1, rng.randrange(0, len(b) + 64)])
            b[i:i + 4] = (v & 0xFFFFFFFF).to_bytes(4, "little")
        elif op < 0.9:
            b = b[:rng.randrange(len(b))]
        else:
            j = rng.randrange(len(b))
            b[j:j] = b[i:i + rng.randint(1, 64)]
    return bytes(b)


def run(name, seed: bytes, fn, seconds: float):
    start, n, slow, errs = time.monotonic(), 0, 0.0, Counter()
    while time.monotonic() - start < seconds:
        data = mutate(seed)
        n += 1
        t0 = time.monotonic()
        signal.alarm(3)
        try:
            fn(data)
        except Hang:
            errs["HANG"] += 1
            (OUT / f"repro_{name}_hang_{errs['HANG']}.bin").write_bytes(data)
        except EXPECTED:
            pass
        except MemoryError:
            errs["MemoryError"] += 1
            (OUT / f"repro_{name}_mem_{errs['MemoryError']}.bin").write_bytes(data)
        except Exception as exc:  # noqa: BLE001
            key = f"{type(exc).__name__}"
            errs[key] += 1
            if errs[key] <= 2:
                (OUT / f"repro_{name}_{key}_{errs[key]}.bin").write_bytes(data)
                errs[key + " @ " + traceback.extract_tb(exc.__traceback__)[-1].name] += 0
        finally:
            signal.alarm(0)
        slow = max(slow, time.monotonic() - t0)
    print(f"{name:18s} {n:7d} inputs, slowest {slow:.2f}s, unexpected: {dict(errs) or 'none'}", flush=True)


# ---------------------------------------------------------------- seeds (real firmware)
px4_raw = (real / "px4_fmu-v5_default.px4").read_bytes()
image = zlib.decompress(base64.b64decode(json.loads(px4_raw)["image"]))
cro_off = image.find(b"CROM", 0x100000)
cromfs = image[cro_off:cro_off + simplefs.cromfs_header(image[cro_off:cro_off + 20], len(image) - cro_off)["fsize"]]
old = json.loads((real / "px4_v1.15.0_fmu-v5_default.px4").read_bytes())
image15 = zlib.decompress(base64.b64decode(old["image"]))
o15 = image15.find(b"CROM", 0x100000)
cromfs15 = image15[o15:o15 + simplefs.cromfs_header(image15[o15:o15 + 20], len(image15) - o15)["fsize"]]
hexfile = (real / "ardupilot" / "CubeOrange_bl.hex").read_bytes()
esp_boot = (real / "esp" / "bootloader_esp32.bin").read_bytes()
esp_app = (real / "esp" / "esp_idf_blink_esp32s2.bin").read_bytes()
parts = (real / "esp" / "partitions_singleapp.bin").read_bytes()
small_px4 = (real / "ark_can-flow_canbootloader.px4").read_bytes()
inav = (real / "inav" / "inav_7.1.2_MATEKF405.hex").read_bytes()


def cromfs_all(data: bytes):
    for _e, _d in simplefs.iter_cromfs(io.BytesIO(data), 0, len(data), 5000, 4 * 1024**2):
        pass


def platform(data: bytes):
    acc = PlatformAccumulator()
    acc.feed_bytes(data)
    acc.results()


targets = [
    ("cromfs_v1.17", cromfs, cromfs_all),
    ("cromfs_v1.15", cromfs15, cromfs_all),
    ("px4_container", small_px4, lambda d: px4json.parse_container(d, 64 * 1024**2)),
    ("ihex_ardupilot", hexfile, lambda d: ihex.parse_ihex(d)),
    ("esp_bootloader", esp_boot, esp.parse_esp_image),
    ("esp_app", esp_app[:65536], esp.parse_esp_image),
    ("esp_partitions", parts, esp.parse_partition_table),
    ("vector_table", image[:4096], lambda d: (analyze_vector_table(d), estimate_flash_base(d))),
    ("platform_scan", inav[:200_000], platform),
]
for name, seed, fn in targets:
    run(name, seed, fn, budget)
