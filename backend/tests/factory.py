"""Synthetic firmware fixture factory.

Everything produced here is synthetic: there is no proprietary vendor
firmware, and the "private keys" are random base64 inside PEM armour (they
are NOT valid keys).  The images only mimic the *structure* of PX4/ArduPilot
artefacts (container JSON, Cortex-M vector table, version strings, ROMFS
init scripts, default parameter files) so that the analyzer can be tested
end to end.
"""
from __future__ import annotations

import base64
import gzip
import io
import json
import os
import random
import shutil
import struct
import subprocess
import tarfile
import zipfile
import zlib
from pathlib import Path

RNG = random.Random(1337)


def fake_pem(kind: str = "RSA PRIVATE KEY", lines: int = 12) -> str:
    """PEM-armoured random bytes. NOT a real key - for detector tests only."""
    body = base64.b64encode(bytes(RNG.getrandbits(8) for _ in range(48 * lines))).decode()
    wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN {kind}-----\n{wrapped}\n-----END {kind}-----\n"


def cortexm_image(strings: list[str], flash_base: int = 0x0800_8000, size: int = 96 * 1024,
                  embedded: list[bytes] | None = None) -> bytes:
    """A fake Cortex-M flash image: vector table + padding + strings + blobs."""
    reset = flash_base + 0x201  # Thumb bit set
    vectors = [0x2002_0000, reset] + [flash_base + 0x301 + 8 * i for i in range(14)]
    img = bytearray(struct.pack("<16I", *vectors))
    img += bytes(RNG.getrandbits(8) for _ in range(2048))  # "code"
    for s in strings:
        img += s.encode() + b"\x00"
        img += bytes(RNG.getrandbits(8) for _ in range(64))
    for blob in embedded or []:
        img += b"\x00" * (-len(img) % 16) + blob
    if len(img) < size:
        img += b"\xff" * (size - len(img))
    return bytes(img)


def romfs(files: dict[str, bytes], volume: str = "NSHInitVol") -> bytes:
    """Build a minimal Linux/NuttX ROMFS image containing a flat /etc tree."""
    def pad16(b: bytes) -> bytes:
        return b + b"\x00" * (-len(b) % 16)

    def name(n: str) -> bytes:
        return pad16(n.encode() + b"\x00")

    # Layout: superblock, then a directory "etc" whose children are the files.
    sb = b"-rom1fs-" + b"\x00" * 8 + name(volume)
    entries = []
    # compute offsets
    off = len(sb)
    dir_hdr_len = 16 + len(name("etc"))
    etc_off = off
    child_off = etc_off + dir_hdr_len
    blobs = []
    cur = child_off
    items = list(files.items())
    for i, (fn, data) in enumerate(items):
        hdr_len = 16 + len(name(fn))
        total = hdr_len + len(pad16(data))
        nxt = cur + total if i < len(items) - 1 else 0
        blobs.append((cur, fn, data, nxt))
        cur += total
    out = bytearray(sb)
    out += struct.pack(">IIII", 0 | 1, child_off, 0, 0) + name("etc")
    for pos, fn, data, nxt in blobs:
        assert len(out) == pos
        out += struct.pack(">IIII", nxt | 2 | 8, 0, len(data), 0) + name(fn) + pad16(data)
    struct.pack_into(">I", out, 8, len(out))
    del entries
    return bytes(out)


PX4_RCS = b"""#!/bin/sh
# PX4 startup script (synthetic test fixture)
set VEHICLE_TYPE mc
param set-default SYS_AUTOSTART 4001
param set CBRK_IO_SAFETY 22027
param set CBRK_USB_CHK 197848
param set MAV_BROADCAST 1
mavlink start -x -u 14556 -r 1000000
"""

AP_DEFAULTS = b"""# ArduPilot default parameters (synthetic test fixture)
ARMING_CHECK 0
BRD_SAFETYENABLE 0
SERIAL1_PROTOCOL 2
"""


def px4_container(path: Path) -> Path:
    strings = ["PX4 Autopilot v1.14.3", "NuttX-11.0.0", "uORB", "px4io", "commander", "ekf2", "navigator",
               "NuttShell (NSH) NuttX-11.0.0", "nsh> ", "/fs/microsd", "vehicle_status", "mc_att_control",
               "http://telemetry.example-drone-cloud.test/upload"]
    image = cortexm_image(strings, embedded=[romfs({"rcS": PX4_RCS})])
    doc = {
        "board_id": 50, "magic": "PX4FWv1", "description": "Firmware for the PX4FMUv5 board (synthetic)",
        "image": base64.b64encode(zlib.compress(image, 9)).decode(), "build_time": 1700000000,
        "summary": "PX4FMUv5", "version": "0.1", "image_size": len(image), "image_maxsize": 2080768,
        "git_identity": "v1.14.3-synthetic", "board_revision": 0,
    }
    path.write_text(json.dumps(doc, indent=1))
    return path


def ardupilot_image() -> bytes:
    strings = ["ArduCopter V4.5.7 (deadbeef)", "ChibiOS: 0123abcd", "AP_HAL", "PreArm: Compass not calibrated",
               "SYSID_THISMAV", "ARMING_CHECK", "@PARAM/defaults.parm"]
    defaults_gz = gzip.compress(AP_DEFAULTS, mtime=0)
    app_desc = bytes([0x40, 0xA2, 0xE4, 0xF1, 0x64, 0x68, 0x91, 0x06]) + struct.pack(
        "<IIIIBBH", 0x11111111, 0x22222222, 64 * 1024, 0xDEADBEEF, 4, 5, 9) + b"\x00" * 8
    return cortexm_image(strings, flash_base=0x0800_4000, embedded=[app_desc, defaults_gz])


def apj_container(path: Path) -> Path:
    image = ardupilot_image()
    doc = {
        "board_id": 9, "magic": "APJFWv1", "description": "Firmware for a STM32F427xx board (synthetic)",
        "image": base64.b64encode(zlib.compress(image, 9)).decode(), "summary": "Pixhawk1",
        "version": "0.1", "image_size": len(image), "board_revision": 0, "git_identity": "deadbeef",
        "flash_total": 2080768, "flash_free": 1000000,
    }
    path.write_text(json.dumps(doc, indent=1))
    return path


def intel_hex(data: bytes, base: int) -> bytes:
    lines = []
    upper = None
    for off in range(0, len(data), 16):
        addr = base + off
        if addr >> 16 != upper:
            upper = addr >> 16
            rec = bytes([2, 0, 0, 4]) + struct.pack(">H", upper)
            lines.append(":" + rec.hex().upper() + f"{(-sum(rec)) & 0xFF:02X}")
        chunk = data[off:off + 16]
        rec = bytes([len(chunk), (addr >> 8) & 0xFF, addr & 0xFF, 0]) + chunk
        lines.append(":" + rec.hex().upper() + f"{(-sum(rec)) & 0xFF:02X}")
    lines.append(":00000001FF")
    return ("\n".join(lines) + "\n").encode()


def ardupilot_hex(path: Path) -> Path:
    path.write_bytes(intel_hex(ardupilot_image(), 0x0800_4000))
    return path


VULN_C = r"""
#include <stdio.h>
#include <string.h>
char *gets(char *s);
int main(int argc, char **argv) {
    char buf[32];
    printf("OpenSSL 1.0.2k  26 Jan 2017\n");
    gets(buf);
    strcpy(buf, argc > 1 ? argv[1] : "x");
    puts(buf);
    return 0;
}
"""


def build_vuln_elf(out: Path) -> Path | None:
    """Compile a deliberately unhardened ELF (never executed by the analyzer)."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        return None
    src = out.with_suffix(".c")
    src.write_text(VULN_C)
    cmd = [cc, "-w", "-O0", "-fno-stack-protector", "-no-pie", "-z", "execstack", "-Wl,-z,norelro",
           "-o", str(out), str(src)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
    except (subprocess.SubprocessError, OSError):
        return None
    finally:
        src.unlink(missing_ok=True)
    return out


def companion_rootfs(root: Path) -> Path:
    """A small Linux companion-computer root filesystem with known weaknesses."""
    files = {
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\npilot:x:1000:1000::/home/pilot:/bin/sh\n"
                      "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n",
        "etc/shadow": "root::19000:0:99999:7:::\npilot:$1$abcdefgh$0123456789abcdefghijkl:19000:0:99999:7:::\n"
                      "daemon:*:19000:0:99999:7:::\n",
        "etc/hostapd/hostapd.conf": "interface=wlan0\nssid=DRONE-AP\nwpa=2\nwpa_passphrase=drone1234\n",
        "etc/ssh/sshd_config": "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n",
        "etc/ssh/ssh_host_rsa_key": fake_pem("RSA PRIVATE KEY"),
        "etc/inittab": "::sysinit:/etc/init.d/rcS\n::respawn:/usr/sbin/telnetd -F -l /bin/sh\n",
        "etc/init.d/rcS": "#!/bin/sh\nmount -a\n/usr/bin/mavlink-routerd &\n"
                          "mavproxy.py --master=/dev/ttyAMA0 --out=udpbcast:192.168.4.255:14550 &\n",
        "etc/mavlink-router/main.conf": "[General]\nTcpServerPort=5760\nReportStats=false\n\n"
                                        "[UartEndpoint fc]\nDevice=/dev/ttyAMA0\nBaud=921600\n\n"
                                        "[UdpEndpoint gcs]\nMode=Server\nAddress=0.0.0.0\nPort=14550\n",
        "etc/app/cloud.conf": "api_url=https://api.example.test\napi_key=tok_synthetic_0123456789abcdef\n"
                              "password=admin\n",
        "etc/os-release": 'NAME="SyntheticDroneOS"\nVERSION="1.0"\n',
        "root/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake vendor@factory\n",
        "usr/lib/libssl.so.1.0.0": b"\x00\x01OpenSSL 1.0.1e 11 Feb 2013\x00padding".decode("latin-1"),
        "bin/busybox": "\x00BusyBox v1.31.1 (2020-01-01 00:00:00 UTC) multi-call binary.\x00",
        "lib/modules/version.txt": "Linux version 4.14.98 (builder@host) (gcc version 8.3.0) #1 SMP\n",
    }
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="latin-1")
    for d in ("sbin", "usr/bin", "tmp", "var"):
        (root / d).mkdir(parents=True, exist_ok=True)
    elf = build_vuln_elf(root / "usr/bin/flightd")
    if elf is None:
        (root / "usr/bin/flightd").write_bytes(b"#!/bin/sh\necho no-compiler\n")
    os.chmod(root / "bin/busybox", 0o4755)
    os.chmod(root / "etc/app/cloud.conf", 0o666)
    return root


def tar_gz(src_dir: Path, out: Path) -> Path:
    with tarfile.open(out, "w:gz") as tf:
        for p in sorted(src_dir.rglob("*")):
            tf.add(p, arcname=str(p.relative_to(src_dir)), recursive=False)
        # A symlink entry: must be recorded, never materialised.
        ti = tarfile.TarInfo("etc/resolv.conf")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/tmp/resolv.conf"
        tf.addfile(ti)
    return out


def zip_dir(src_dir: Path, out: Path) -> Path:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src_dir.rglob("*")):
            if p.is_file():
                zf.write(p, str(p.relative_to(src_dir)))
    return out


def squashfs_image(src_dir: Path, out: Path) -> Path | None:
    tool = shutil.which("mksquashfs")
    if not tool:
        return None
    subprocess.run([tool, str(src_dir), str(out), "-noappend", "-quiet", "-no-progress", "-all-root"],
                   check=True, capture_output=True, timeout=120)
    return out


def ext4_image(src_dir: Path, out: Path, size_mb: int = 8) -> Path | None:
    tool = shutil.which("mkfs.ext4") or (Path("/usr/sbin/mkfs.ext4") if Path("/usr/sbin/mkfs.ext4").exists() else None)
    if not tool:
        return None
    with out.open("wb") as fp:
        fp.truncate(size_mb * 1024 * 1024)
    subprocess.run([str(tool), "-q", "-F", "-d", str(src_dir), str(out)], check=True, capture_output=True, timeout=120)
    return out


def _mtd_tool(name: str) -> str | None:
    return shutil.which(name) or (f"/usr/sbin/{name}" if Path(f"/usr/sbin/{name}").exists() else None)


def ubi_image(src_dir: Path, out: Path) -> Path | None:
    mkfs, ubinize = _mtd_tool("mkfs.ubifs"), _mtd_tool("ubinize")
    if not (mkfs and ubinize):
        return None
    ubifs = out.with_suffix(".ubifs")
    subprocess.run([mkfs, "-q", "-r", str(src_dir), "-m", "2048", "-e", "129024", "-c", "128", "-o", str(ubifs)],
                   check=True, capture_output=True, timeout=120)
    cfg = out.with_suffix(".cfg")
    cfg.write_text(f"[ubifs]\nmode=ubi\nimage={ubifs}\nvol_id=0\nvol_type=dynamic\nvol_name=rootfs\n"
                   "vol_flags=autoresize\n")
    subprocess.run([ubinize, "-o", str(out), "-m", "2048", "-p", "128KiB", "-s", "512", str(cfg)],
                   check=True, capture_output=True, timeout=120)
    cfg.unlink()
    ubifs.unlink()
    return out


def jffs2_image(src_dir: Path, out: Path) -> Path | None:
    mkfs = _mtd_tool("mkfs.jffs2")
    if not mkfs:
        return None
    subprocess.run([mkfs, "-r", str(src_dir), "-o", str(out), "-e", "128KiB"], check=True, capture_output=True,
                   timeout=120)
    return out


def mbr_disk(partition_image: Path, out: Path) -> Path:
    data = partition_image.read_bytes()
    lba = 2048
    sectors = (len(data) + 511) // 512
    mbr = bytearray(512)
    entry = struct.pack("<B3sB3sII", 0x80, b"\x00\x02\x00", 0x83, b"\x00\x00\x00", lba, sectors)
    mbr[446:462] = entry
    mbr[510:512] = b"\x55\xaa"
    with out.open("wb") as fp:
        fp.write(mbr)
        fp.write(b"\x00" * (lba * 512 - 512))
        fp.write(data)
        fp.write(b"\x00" * (sectors * 512 - len(data)))
    return out


# ------------------------------------------------------------ malicious inputs
def zip_slip(out: Path) -> Path:
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("../../../../tmp/dfa_evil.txt", "pwned")
        zf.writestr("/etc/absolute.txt", "abs")
        zf.writestr("ok/readme.txt", "fine")
    return out


def tar_traversal(out: Path) -> Path:
    with tarfile.open(out, "w") as tf:
        for name, data in [("../escape.txt", b"x"), ("/abs/path.txt", b"y"), ("safe/file.txt", b"z")]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        ti = tarfile.TarInfo("safe/link_to_root")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/"
        tf.addfile(ti)
        ti = tarfile.TarInfo("safe/hardlink")
        ti.type = tarfile.LNKTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)
        ti = tarfile.TarInfo("safe/dev_mem")
        ti.type = tarfile.CHRTYPE
        ti.devmajor, ti.devminor = 1, 1
        tf.addfile(ti)
    return out


def zip_bomb(out: Path, size_mb: int = 50) -> Path:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        with zf.open("zeros.bin", "w") as fp:
            chunk = b"\x00" * (1024 * 1024)
            for _ in range(size_mb):
                fp.write(chunk)
    return out


def gzip_bomb(out: Path, size_mb: int = 50) -> Path:
    with gzip.open(out, "wb", compresslevel=9) as fp:
        chunk = b"\x00" * (1024 * 1024)
        for _ in range(size_mb):
            fp.write(chunk)
    return out


def nested_archive(out: Path, depth: int = 8) -> Path:
    data = b"innermost"
    name = "inner.txt"
    for i in range(depth):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(name, data)
        data, name = buf.getvalue(), f"level{i}.zip"
    out.write_bytes(data)
    return out


def generate_all(dest: Path) -> dict[str, Path]:
    dest.mkdir(parents=True, exist_ok=True)
    out: dict[str, Path] = {}
    out["px4"] = px4_container(dest / "px4_fmu-v5_synthetic.px4")
    out["apj"] = apj_container(dest / "arducopter_synthetic.apj")
    out["hex"] = ardupilot_hex(dest / "arducopter_synthetic.hex")
    out["apj_bin"] = dest / "arducopter_synthetic.bin"
    out["apj_bin"].write_bytes(ardupilot_image())
    rootdir = dest / "_rootfs"
    if rootdir.exists():
        shutil.rmtree(rootdir)
    companion_rootfs(rootdir)
    out["tar_gz"] = tar_gz(rootdir, dest / "companion_rootfs.tar.gz")
    out["zip"] = zip_dir(rootdir, dest / "companion_update.zip")
    sq = squashfs_image(rootdir, dest / "companion_rootfs.squashfs")
    if sq:
        out["squashfs"] = sq
    for key, fn, name in (("ubi", ubi_image, "companion_rootfs.ubi"), ("jffs2", jffs2_image, "companion_rootfs.jffs2")):
        img = fn(rootdir, dest / name)
        if img:
            out[key] = img
    ext = ext4_image(rootdir, dest / "companion_rootfs.ext4")
    if ext:
        out["ext4"] = ext
        out["disk_img"] = mbr_disk(ext, dest / "companion_sdcard.img")
    # A "2.0" release of the companion image: some issues fixed, one new.
    (rootdir / "etc/shadow").write_text("root:!:19000:0:99999:7:::\npilot:!:19000:0:99999:7:::\n")
    (rootdir / "etc/inittab").write_text("::sysinit:/etc/init.d/rcS\n")
    (rootdir / "bin/busybox").write_text("\x00BusyBox v1.36.1 (2024-01-01) multi-call binary.\x00", encoding="latin-1")
    (rootdir / "etc/app/debug.conf").write_text("admin_password=letmein\n")
    out["tar_gz_v2"] = tar_gz(rootdir, dest / "companion_rootfs_v2.tar.gz")
    elf = rootdir / "usr/bin/flightd"
    if elf.read_bytes()[:4] == b"\x7fELF":
        out["elf"] = dest / "flightd.elf"
        shutil.copy(elf, out["elf"])
    shutil.rmtree(rootdir)
    out["zip_slip"] = zip_slip(dest / "malicious_zip_slip.zip")
    out["tar_traversal"] = tar_traversal(dest / "malicious_tar_traversal.tar")
    out["nested"] = nested_archive(dest / "malicious_nested.zip")
    out["random"] = dest / "random_encrypted.bin"
    out["random"].write_bytes(bytes(RNG.getrandbits(8) for _ in range(256 * 1024)))
    return out


def ext_duplicate_entry_attack(out: Path, victim: Path) -> Path | None:
    """ext2 image whose directory holds a symlink 'aa' -> <victim> and a *regular file also named 'aa'*.

    Extractors that create the symlink and then write the second entry by name (debugfs rdump) write
    through the link to <victim>. Built by creating 'aa' (link) + 'ab' (file) and patching the dirent name.
    """
    mkfs = shutil.which("mke2fs") or ("/usr/sbin/mke2fs" if Path("/usr/sbin/mke2fs").exists() else None)
    if not mkfs:
        return None
    src = out.parent / (out.name + ".src")
    src.mkdir(parents=True, exist_ok=True)
    (src / "aa").symlink_to(victim)
    (src / "ab").write_text("PWNED-BY-FIRMWARE\n")
    with out.open("wb") as fp:
        fp.truncate(1024 * 1024)
    subprocess.run([mkfs, "-q", "-F", "-t", "ext2", "-d", str(src), str(out)], check=True, capture_output=True,
                   timeout=60)
    data = bytearray(out.read_bytes())
    i = data.find(b"\x02\x01ab")  # name_len=2, file_type=regular, name="ab"
    if i < 0:
        return None
    data[i + 2:i + 4] = b"aa"
    out.write_bytes(bytes(data))
    shutil.rmtree(src)
    return out


def cromfs(files: dict[str, bytes]) -> bytes:
    """Minimal NuttX CROMFS volume (uncompressed LZF type-0 blocks) containing /init.d/<files>.

    As in real volumes (verified against PX4 v1.17 images), cv_root points to the first entry of
    the root directory list; directory nodes point (cn_child) to their first entry.
    """
    import struct as st
    items = list(files.items())
    n_nodes = 1 + len(items)
    nodes_end = 20 + 20 * n_nodes
    name_table, blob = {}, bytearray()
    for n in ["init.d"] + [k for k, _ in items]:
        name_table[n] = nodes_end + len(blob)
        blob += n.encode() + b"\x00"
    data_off = nodes_end + len(blob)
    blocks, block_off = bytearray(), {}
    for k, v in items:
        block_off[k] = data_off + len(blocks)
        for i in range(0, len(v), 512):
            chunk = v[i:i + 512]
            blocks += b"ZV\x00" + st.pack(">H", len(chunk)) + chunk
    fsize = data_off + len(blocks)
    out = bytearray(st.pack("<IHHIII", 0x4D4F5243, n_nodes, len(items), 20, fsize, 512))
    out += st.pack("<HHIIII", 0o40555, 0, name_table["init.d"], 0, 0, 40)  # root list: one directory
    for i, (k, v) in enumerate(items):
        peer = 40 + 20 * (i + 1) if i + 1 < len(items) else 0
        out += st.pack("<HHIIII", 0o100444, 0, name_table[k], len(v), peer, block_off[k])
    out += blob + blocks
    assert len(out) == fsize
    return bytes(out)
