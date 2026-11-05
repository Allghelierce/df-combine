"""Safe, recursive firmware unpacker.

Security properties (all enforced here, independent of the outer sandbox):

* Member names are normalised and confined to the output directory; absolute
  paths, ``..`` components, NUL bytes and over-long names are rejected.
* Symlinks, hardlinks, device nodes and FIFOs are never materialised.  They
  are recorded in the manifest (``links``) for analysis instead.
* Every byte written and every file created is charged to an
  :class:`ExtractionBudget` (total size, per-file size, file count, nesting
  depth, compression ratio).  Exceeding a limit aborts that container and is
  reported as a warning; the rest of the analysis continues.
* Data is streamed - declared sizes in archive headers are never trusted.
* External unpackers (unsquashfs, debugfs, mtools) run with rlimits, a
  timeout and a watchdog on the output directory size, and their output tree
  is sanitised afterwards.
* Nothing extracted is ever executed.
"""
from __future__ import annotations

import bz2
import hashlib
import lzma
import os
import resource
import shutil
import stat
import struct
import subprocess
import tarfile
import time
import zipfile
import zlib
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .formats import more, px4json
from .formats.ihex import parse_ihex
from .formats.simplefs import (
    FormatError,
    cromfs_header,
    iter_cpio,
    iter_cromfs,
    iter_romfs,
    parse_dfuse,
    parse_partitions,
    romfs_size,
)
from .identify import FormatInfo, detect_format, parse_uimage_header
from .limits import ExtractionBudget, LimitExceeded, Limits

COPY_CHUNK = 1024 * 1024
MAX_NAME = 255
MAX_PATH_DEPTH = 64


class UnsafePath(ValueError):
    pass


@dataclass
class Artifact:
    id: int
    path: str  # relative to the extraction root ("files/..."); "<input>" for the upload
    name: str
    size: int
    sha256: str
    format: str
    format_description: str
    parent_id: int | None
    depth: int
    origin: str  # input | extracted | decoded | carved | partition
    mode: int | None = None  # original permission bits from the container, if known
    uid: int | None = None
    gid: int | None = None
    details: dict = field(default_factory=dict)
    extraction: str | None = None  # None | "ok" | "partial" | "failed" | "skipped" | "unsupported"
    extraction_note: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LinkRecord:
    artifact_parent: int
    path: str
    kind: str  # symlink | hardlink | device | fifo | socket
    target: str | None


@dataclass
class ExtractionResult:
    artifacts: list[Artifact] = field(default_factory=list)
    links: list[LinkRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    container_metadata: dict = field(default_factory=dict)
    filesystems: list[dict] = field(default_factory=list)
    limits_hit: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


# ----------------------------------------------------------------- helpers
def safe_member_path(name: str) -> PurePosixPath:
    """Normalise an archive member name to a safe relative path."""
    if "\x00" in name:
        raise UnsafePath("NUL byte in member name")
    name = name.replace("\\", "/")
    # Windows drive letters ("C:foo") are treated as absolute.
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        raise UnsafePath(f"absolute (drive) path: {name!r}")
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise UnsafePath(f"path traversal component in {name!r}")
        if len(part.encode("utf-8", "replace")) > MAX_NAME:
            raise UnsafePath("member name component too long")
        parts.append(part)
    if not parts:
        raise UnsafePath("empty member name")
    if len(parts) > MAX_PATH_DEPTH:
        raise UnsafePath("member path too deep")
    return PurePosixPath(*parts)


def _confined(base: Path, rel: PurePosixPath) -> Path:
    target = base.joinpath(*rel.parts)
    base_r = base.resolve()
    # Parent may not exist yet; resolve the deepest existing ancestor.
    probe = target
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if probe.is_symlink():
        raise UnsafePath("symlink in output path")
    if not str(probe.resolve()).startswith(str(base_r)):
        raise UnsafePath("path escapes extraction directory")
    return target


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(COPY_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _sanitize_component(name: str) -> str:
    keep = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:80]
    return keep or "blob"


# ----------------------------------------------------------------- extractor
class Extractor:
    def __init__(self, work_dir: Path, limits: Limits | None = None,
                 progress: Callable[[str], None] | None = None) -> None:
        self.work_dir = work_dir
        self.root = work_dir / "files"
        self.root.mkdir(parents=True, exist_ok=True)
        self.limits = limits or Limits()
        self.budget = ExtractionBudget(self.limits)
        self.result = ExtractionResult()
        self._next_id = 0
        self._paths: dict[int, Path] = {}
        self._pending_meta: dict[str, dict] = {}
        self._tree_roots: dict[int, tuple[Path, bool]] = {}  # artifact id -> (root, written by external tool)
        self._registered: set[int] = set()
        # Unpackers that may follow links they create themselves are only allowed inside the container sandbox.
        self.in_container = os.environ.get("DFA_IN_SANDBOX") == "1"
        self._progress = progress or (lambda msg: None)
        self._external_tools = {t: shutil.which(t) for t in ("unsquashfs", "debugfs", "mcopy",
                                                             "ubireader_extract_files", "jefferson", "fsck.erofs")}

    # ---- public -----------------------------------------------------------
    def run(self, input_path: Path, original_name: str) -> ExtractionResult:
        t0 = time.monotonic()
        info = detect_format(input_path)
        root = self._register(input_path, "<input>", original_name, info, None, 0, "input")
        self._process(root)
        self.result.stats = {
            "artifacts": len(self.result.artifacts),
            "bytes_written": self.budget.bytes_written,
            "files_created": self.budget.files_created,
            "duration_s": round(time.monotonic() - t0, 3),
            "external_tools": {k: bool(v) for k, v in self._external_tools.items()},
        }
        return self.result

    def path_of(self, artifact_id: int) -> Path:
        return self._paths[artifact_id]

    # ---- registration -----------------------------------------------------
    def _register(self, path: Path, rel: str, name: str, info: FormatInfo, parent: int | None,
                  depth: int, origin: str, **kw) -> Artifact:
        art = Artifact(id=self._next_id, path=rel, name=name, size=path.stat().st_size,
                       sha256=_sha256(path), format=info.format,
                       format_description=info.description, parent_id=parent, depth=depth,
                       origin=origin, details=dict(info.details), **kw)
        self._next_id += 1
        self._paths[art.id] = path
        self.result.artifacts.append(art)
        return art

    def _out_dir(self, art: Artifact) -> Path:
        d = self.root / f"{art.id:05d}_{_sanitize_component(art.name)}.d"
        d.mkdir(parents=True, exist_ok=False)
        self._tree_roots.setdefault(art.id, (d, False))
        return d

    def _rel(self, p: Path) -> str:
        return str(p.relative_to(self.work_dir))

    # ---- writing ----------------------------------------------------------
    def _write_stream(self, src: BinaryIO, dest: Path, max_bytes: int | None = None,
                      compressed_size: int | None = None, label: str = "") -> int:
        """Copy a stream to ``dest`` while charging the budget."""
        self.budget.charge_file()
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        written = 0
        limit = self.limits.max_file_bytes if max_bytes is None else min(max_bytes, self.limits.max_file_bytes)
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = src.read(COPY_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit:
                        raise LimitExceeded(f"'{label or dest.name}' exceeds per-file size limit ({limit} bytes)")
                    self.budget.charge_bytes(len(chunk), file_total=written)
                    if compressed_size is not None:
                        self.budget.check_ratio(compressed_size, written, label or dest.name)
                    out.write(chunk)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        return written

    def _member_write(self, art: Artifact, name: str, src: BinaryIO, dest: Path,
                      compressed_size: int | None = None) -> bool:
        """Write one archive member; path collisions reject the member instead of aborting the archive."""
        try:
            self._write_stream(src, dest, compressed_size=compressed_size, label=name)
            return True
        except (FileExistsError, NotADirectoryError, IsADirectoryError) as exc:
            self.result.warnings.append(f"{art.name}: rejected member {name!r}: path collision ({type(exc).__name__})")
            return False

    def _write_bytes(self, data: bytes, dest: Path) -> None:
        import io
        self._write_stream(io.BytesIO(data), dest)

    def _child(self, parent: Artifact, path: Path, name: str, origin: str, **kw) -> Artifact:
        info = detect_format(path)
        return self._register(path, self._rel(path), name, info, parent.id, parent.depth + 1, origin, **kw)

    # ---- recursion --------------------------------------------------------
    def _process(self, art: Artifact) -> None:
        handler = HANDLERS.get(art.format)
        carve = art.format in ("raw", "cortexm_raw") and art.size >= 4096
        if handler is None and not carve:
            return
        if art.depth >= self.limits.max_depth:
            art.extraction = "skipped"
            art.extraction_note = f"maximum nesting depth ({self.limits.max_depth}) reached"
            self.result.warnings.append(f"{art.name}: {art.extraction_note}")
            self.result.limits_hit.append("max_depth")
            return
        self._progress(f"unpacking {art.name} ({art.format})")
        children: list[Artifact] = []
        try:
            if handler is not None:
                children = handler(self, art)
            else:
                children = self._carve(art)
                if not children:
                    return
            art.extraction = "ok"
        except LimitExceeded as exc:
            art.extraction = "partial"
            art.extraction_note = f"limit exceeded: {exc}"
            self.result.warnings.append(f"{art.name}: {art.extraction_note}")
            self.result.limits_hit.append(str(exc))
            children = self._salvage(art)
        except UnsupportedFormat as exc:
            art.extraction = "unsupported"
            art.extraction_note = str(exc)
            self.result.warnings.append(f"{art.name}: {exc}")
            return
        except Exception as exc:  # noqa: BLE001 - any parser error is contained to this container
            art.extraction = "failed"
            art.extraction_note = f"{type(exc).__name__}: {str(exc)[:300]}"
            self.result.warnings.append(f"{art.name}: extraction failed ({art.extraction_note})")
            children = self._salvage(art)
        for child in children:
            if self.budget.files_created > self.limits.max_files:
                break
            self._process(child)

    def _salvage(self, art: Artifact) -> list[Artifact]:
        """After a failure, register whatever was safely written so it is still analysed."""
        children = [a for a in self.result.artifacts if a.parent_id == art.id]
        if children or art.id in self._registered or art.id not in self._tree_roots:
            return children
        root, external = self._tree_roots[art.id]
        if not root.exists():
            return children
        try:
            if external:
                self._sanitize_tree(art, root)
            return self._register_tree(art, root)
        except Exception as exc:  # noqa: BLE001
            self.result.warnings.append(f"{art.name}: could not salvage partial output ({exc})")
            return [a for a in self.result.artifacts if a.parent_id == art.id]

    # ---- tree registration for directory-producing handlers --------------
    def _register_tree(self, parent: Artifact, out_dir: Path) -> list[Artifact]:
        self._registered.add(parent.id)
        children = []
        for dirpath, dirnames, filenames in os.walk(out_dir):
            dirnames.sort()
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if p.is_symlink() or not p.is_file():
                    continue
                rel_inside = "/" + str(p.relative_to(out_dir))
                meta = self._pending_meta.pop(str(p), {})
                children.append(self._child(parent, p, rel_inside, "extracted", **meta))
        return children

    def _note_meta(self, path: Path, **meta) -> None:
        self._pending_meta[str(path)] = meta

    def _record_link(self, parent: Artifact, name: str, kind: str, target: str | None) -> None:
        if len(self.result.links) < 50_000:
            self.result.links.append(LinkRecord(parent.id, name, kind, target))

    def _record_fs(self, parent: Artifact, fs_type: str, out_dir: Path, **extra) -> None:
        self.result.filesystems.append({"artifact_id": parent.id, "type": fs_type,
                                        "root": self._rel(out_dir), "name": parent.name, **extra})

    # ---- handlers ----------------------------------------------------------
    def h_zip(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with zipfile.ZipFile(src) as zf:
            infos = zf.infolist()
            if len(infos) > self.limits.max_files:
                raise LimitExceeded(f"zip declares {len(infos)} entries (limit {self.limits.max_files})")
            for zi in infos:
                mode = (zi.external_attr >> 16) & 0xFFFF
                if zi.is_dir():
                    continue
                if stat.S_ISLNK(mode):
                    target = zf.read(zi)[:4096].decode("utf-8", "replace") if zi.file_size <= 4096 else None
                    self._record_link(art, zi.filename, "symlink", target)
                    continue
                if zi.flag_bits & 0x1:
                    self.result.warnings.append(f"{art.name}: encrypted member '{zi.filename}' skipped")
                    continue
                try:
                    rel = safe_member_path(zi.filename)
                    dest = _confined(out, rel)
                except UnsafePath as exc:
                    self.result.warnings.append(f"{art.name}: rejected member {zi.filename!r}: {exc}")
                    continue
                if dest.exists():
                    self.result.warnings.append(f"{art.name}: duplicate member {zi.filename!r} skipped")
                    continue
                with zf.open(zi) as member:
                    if not self._member_write(art, zi.filename, member, dest, compressed_size=max(zi.compress_size, 1)):
                        continue
                self._note_meta(dest, mode=(mode & 0o7777) or None)
        self._record_fs(art, "zip", out)
        return self._register_tree(art, out)

    def h_tar(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with tarfile.open(src, mode="r:") as tf:
            count = 0
            for ti in tf:
                count += 1
                if count > self.limits.max_files:
                    raise LimitExceeded(f"tar has more than {self.limits.max_files} entries")
                if ti.isdir():
                    continue
                if ti.issym() or ti.islnk():
                    self._record_link(art, ti.name, "symlink" if ti.issym() else "hardlink", ti.linkname[:4096])
                    continue
                if not ti.isreg():
                    kind = "device" if (ti.ischr() or ti.isblk()) else "fifo" if ti.isfifo() else "other"
                    self._record_link(art, ti.name, kind, None)
                    continue
                try:
                    rel = safe_member_path(ti.name)
                    dest = _confined(out, rel)
                except UnsafePath as exc:
                    self.result.warnings.append(f"{art.name}: rejected member {ti.name!r}: {exc}")
                    continue
                if dest.exists():
                    self.result.warnings.append(f"{art.name}: duplicate member {ti.name!r} skipped")
                    continue
                fobj = tf.extractfile(ti)
                if fobj is None:
                    continue
                if not self._member_write(art, ti.name, fobj, dest):
                    continue
                self._note_meta(dest, mode=ti.mode & 0o7777, uid=ti.uid, gid=ti.gid)
        self._record_fs(art, "tar", out)
        return self._register_tree(art, out)

    def _decompress(self, art: Artifact, opener: Callable[[Path], BinaryIO], suffixes: Iterable[str]) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        base = Path(art.name).name or "data"
        for suf in suffixes:
            if base.lower().endswith(suf):
                base = base[: -len(suf)] + (".tar" if suf in (".tgz", ".tbz2", ".txz") else "")
                break
        else:
            base = base + ".decompressed"
        dest = out / _sanitize_component(base)
        with opener(src) as stream:
            self._write_stream(stream, dest, compressed_size=art.size, label=art.name)
        return [self._child(art, dest, base, "decoded")]

    def h_gzip(self, art: Artifact) -> list[Artifact]:
        import gzip
        return self._decompress(art, lambda p: gzip.open(p, "rb"), (".gz", ".tgz"))

    def h_bzip2(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, lambda p: bz2.open(p, "rb"), (".bz2", ".tbz2"))

    def h_xz(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, lambda p: _LzmaReader(p, lzma.FORMAT_XZ), (".xz", ".txz"))

    def h_lzma(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, lambda p: _LzmaReader(p, lzma.FORMAT_ALONE), (".lzma", ".lz"))

    def h_zstd(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, more.ZstdReader, (".zst", ".zstd"))

    def h_lz4(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, more.Lz4FrameReader, (".lz4",))

    def h_lz4_legacy(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, more.Lz4LegacyReader, (".lz4",))

    def h_lzop(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, more.LzopReader, (".lzo",))

    def h_cramfs(self, art: Artifact) -> list[Artifact]:
        import io
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with src.open("rb") as fp:
            for e, data in more.iter_cramfs(fp, art.size, self.limits.max_files, self.limits.max_file_bytes):
                if e.kind == "file" and data is not None:
                    self._materialize_entry(art, out, io.BytesIO(data), e)
                elif e.kind != "dir":
                    self._record_link(art, e.name, e.kind, e.link_target)
        self._record_fs(art, "cramfs", out, image_artifact=art.id)
        return self._register_tree(art, out)

    def h_android_sparse(self, art: Artifact) -> list[Artifact]:
        """Expand an Android sparse image; DONT_CARE chunks become holes (no disk usage)."""
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with src.open("rb") as fp:
            info = more.sparse_header(fp.read(28))
            if info is None:
                raise FormatError("invalid Android sparse header")
            full = info.block_size * info.total_blocks
            if full > self.limits.max_file_bytes:
                raise LimitExceeded(f"expanded sparse image ({full} bytes) exceeds per-file limit")
            art.details.update({"block_size": info.block_size, "blocks": info.total_blocks, "chunks": info.total_chunks})
            dest = out / "image.raw"
            self.budget.charge_file()
            pos = info.file_hdr
            with dest.open("xb") as o:
                for _ in range(info.total_chunks):
                    fp.seek(pos)
                    ch = fp.read(12)
                    if len(ch) < 12:
                        raise FormatError("truncated sparse chunk header")
                    ctype, _r, nblk, tsize = struct.unpack("<HHII", ch)
                    data_off, length = pos + info.chunk_hdr, nblk * info.block_size
                    if o.tell() + length > full:
                        raise FormatError("sparse chunks exceed declared image size")
                    if ctype == 0xCAC1:  # RAW
                        fp.seek(data_off)
                        left = length
                        while left:
                            chunk = fp.read(min(COPY_CHUNK, left))
                            if not chunk:
                                raise FormatError("truncated sparse RAW chunk")
                            self.budget.charge_bytes(len(chunk))
                            o.write(chunk)
                            left -= len(chunk)
                    elif ctype == 0xCAC2:  # FILL
                        fp.seek(data_off)
                        pattern = fp.read(4) * (COPY_CHUNK // 4)
                        left = length
                        while left:
                            n = min(len(pattern), left)
                            self.budget.charge_bytes(n)
                            o.write(pattern[:n])
                            left -= n
                    elif ctype == 0xCAC3:  # DONT_CARE
                        o.seek(length, 1)
                    elif ctype != 0xCAC4:  # CRC32 chunks carry no data
                        raise FormatError(f"unknown sparse chunk type {ctype:#x}")
                    pos += tsize
                o.truncate(full)
        return [self._child(art, dest, "image.raw", "decoded")]

    def h_parrot_plf(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        children = []
        with src.open("rb") as fp:
            meta, sections = more.parse_plf(fp, art.size)
            art.details.update(meta)
            art.details["sections"] = [{"index": sec.index, "type": hex(sec.type), "size": sec.size,
                                        "uncompressed": sec.uncompressed_size, "load_address": hex(sec.load_addr)}
                                       for sec in sections[:200]]
            for sec in sections:
                fp.seek(sec.offset)
                data = fp.read(sec.size)
                if sec.uncompressed_size:
                    data = more.inflate_any(data, min(sec.uncompressed_size, self.limits.max_file_bytes))
                    self.budget.check_ratio(max(sec.size, 1), len(data), f"PLF section {sec.index}")
                kind = more.PLF_SECTION_NAMES.get(sec.type, "section")
                name = f"section_{sec.index:03d}_{sec.type:02x}_{kind}.bin"
                self._write_bytes(data, out / name)
                c = self._child(art, out / name, name, "decoded")
                c.details["load_address"] = hex(sec.load_addr)
                children.append(c)
        return children

    def h_dji_imah(self, art: Artifact) -> list[Artifact]:
        """Extract plaintext chunks of a DJI IM*H module. Encrypted chunks are never decrypted."""
        src = self.path_of(art.id)
        with src.open("rb") as fp:
            info = more.parse_imah(fp, art.size)
            art.details.update({"module_name": info.name, "module_type": info.module_type,
                                "module_version": info.version, "date": info.date, "auth_key_id": info.auth_key,
                                "enc_key_id": info.enc_key or "(none)", "header_version": info.header_version,
                                "chunks": info.chunks[:64]})
            plain = [c for c in info.chunks if c["plaintext"] and c["in_bounds"] and c["size"]]
            if not plain:
                raise UnsupportedFormat(
                    f"DJI IM*H module '{info.name}': payload is encrypted (key id '{info.enc_key}'); it is not "
                    "decrypted - only header metadata was analysed")
            out = self._out_dir(art)
            children = []
            for c in plain:
                name = f"chunk_{c['id']}.bin"
                fp.seek(c["offset"])
                self._write_stream(_Bounded(fp, c["size"]), out / name, label=name)
                ch = self._child(art, out / name, name, "decoded")
                ch.details["load_address"] = c["address"]
                children.append(ch)
        return children

    def h_erofs(self, art: Artifact) -> list[Artifact]:
        tool = self._container_only("fsck.erofs", "EROFS image")
        out = self._out_dir(art)
        dest = out / "root"
        self._tree_roots[art.id] = (out, True)
        self._run_tool(art, [tool, f"--extract={dest}", "--no-preserve", str(self.path_of(art.id))], out)
        self._sanitize_tree(art, out)
        root = dest if dest.exists() else out
        self._record_fs(art, "erofs", root, image_artifact=art.id)
        return self._register_tree(art, root)

    def h_esp_image(self, art: Artifact) -> list[Artifact]:
        from .formats.esp import parse_esp_image
        src = self.path_of(art.id)
        if art.size > 64 * 1024**2:
            raise LimitExceeded("ESP image larger than 64 MiB")
        data = src.read_bytes()
        info = parse_esp_image(data)
        if info is None:
            raise FormatError("invalid Espressif image segment table")
        art.details.update({"esp_chip": info["chip"], "entry_point": info["entry"],
                            "esp_architecture": info["architecture"], "segments": info["segments"],
                            "checksum_valid": info["checksum_valid"], "image_size": info["image_size"]})
        for k in ("sha256_valid", "app"):
            if k in info:
                art.details["esp_app" if k == "app" else k] = info[k]
        if info["checksum_valid"] is False:
            self.result.warnings.append(f"{art.name}: Espressif image checksum mismatch (corrupt or modified)")
        out = self._out_dir(art)
        children = []
        for i, seg in enumerate(info["segments"]):
            if not seg["size"]:
                continue
            name = f"segment{i}_{seg['load_address']}.bin"
            self._write_bytes(data[seg["offset"]:seg["offset"] + seg["size"]], out / name)
            c = self._child(art, out / name, name, "decoded")
            c.details["load_address"] = seg["load_address"]
            c.details["arch_hint"] = info["architecture"]
            children.append(c)
        # Images can be followed by further images (e.g. ESP8266 Arduino builds: eboot, then the app at 0x1000).
        tail = data[info["image_size"]:]
        rest = info["image_size"] + len(tail) - len(tail.lstrip(b"\xff\xaa\x00"))  # skip flash padding
        rest -= rest % 16
        if len(data) - rest >= 64:
            name = f"trailing@{rest:#x}.bin"
            self._write_bytes(data[rest:], out / name)
            c = self._child(art, out / name, name, "carved")
            c.details["carved_offset"] = hex(rest)
            children.append(c)
        return children

    def h_esp_flash(self, art: Artifact) -> list[Artifact]:
        from .formats import esp
        src = self.path_of(art.id)
        out = self._out_dir(art)
        children = []
        with src.open("rb") as fp:
            fp.seek(esp.PARTITION_TABLE_OFFSET)
            table = esp.parse_partition_table(fp.read(esp.PARTITION_TABLE_MAX))
            if table is None:
                raise FormatError("invalid ESP-IDF partition table at 0x8000")
            art.details["partitions"] = table["partitions"]
            art.details["partition_table_md5_valid"] = table["md5_valid"]
            for boot in (0x1000, 0x0):  # ESP32/ESP32-S2 boot from 0x1000, newer chips from 0x0
                fp.seek(boot)
                if fp.read(1) == b"\xe9":
                    fp.seek(boot)
                    self._write_stream(_Bounded(fp, esp.PARTITION_TABLE_OFFSET - boot), out / "bootloader.bin",
                                       label="bootloader.bin")
                    c = self._child(art, out / "bootloader.bin", "bootloader.bin", "partition")
                    c.details["flash_offset"] = hex(boot)
                    children.append(c)
                    break
            notes = []
            for i, p in enumerate(table["partitions"]):
                label = f"{_sanitize_component(p['label']) or 'partition'}"
                if p["encrypted"]:
                    notes.append(f"{p['label']}: flash-encrypted partition, not analysed")
                    continue
                if p["offset"] >= art.size:
                    notes.append(f"{p['label']}: beyond the end of the dump")
                    continue
                size = min(p["size"], art.size - p["offset"])
                fp.seek(p["offset"])
                if _all_erased(fp, size):
                    notes.append(f"{p['label']}: erased (all 0xFF)")
                    continue
                name = f"{i:02d}_{label}.{p['type']}-{p['subtype']}.bin"
                fp.seek(p["offset"])
                self._write_stream(_Bounded(fp, size), out / name, label=name)
                c = self._child(art, out / name, name, "partition")
                c.details["esp_partition"] = p
                children.append(c)
            if notes:
                art.details["partition_notes"] = notes
        return children

    def h_ihex(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        if art.size > 256 * 1024**2:
            raise LimitExceeded("Intel HEX file larger than 256 MiB")
        img = parse_ihex(src.read_bytes(), max_span=min(self.limits.max_file_bytes, 64 * 1024**2))
        out = self._out_dir(art)
        dest = out / "image.bin"
        self._write_bytes(img.data, dest)
        art.details.update({"base_address": hex(img.base_address), "records": img.record_count,
                            "segments": [(hex(a), n) for a, n in img.segments[:32]],
                            "start_address": hex(img.start_address) if img.start_address is not None else None})
        child = self._child(art, dest, "image.bin", "decoded")
        child.details["load_address"] = hex(img.base_address)
        return [child]

    def h_fw_json(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        if art.size > 128 * 1024**2:
            raise LimitExceeded("JSON firmware container larger than 128 MiB")
        cont = px4json.parse_container(src.read_bytes(), self.limits.max_file_bytes)
        art.details.update({"container_platform": cont.platform, **cont.metadata})
        self.result.container_metadata[str(art.id)] = {"platform": cont.platform, **cont.metadata}
        out = self._out_dir(art)
        children = []
        for name, data in cont.images.items():
            dest = out / name
            self._write_bytes(data, dest)
            children.append(self._child(art, dest, name, "decoded"))
        return children

    def h_uimage(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        with src.open("rb") as fp:
            hdr = parse_uimage_header(fp.read(64))
            if hdr is None:
                raise FormatError("invalid uImage header")
            art.details.update(hdr)
            size = min(hdr["data_size"], art.size - 64)
            fp.seek(64)
            out = self._out_dir(art)
            ext = {"gzip": ".gz", "bzip2": ".bz2", "lzma": ".lzma"}.get(hdr["compression"], ".bin")
            dest = out / f"payload{ext}"
            self._write_stream(_Bounded(fp, size), dest, label="uImage payload")
        return [self._child(art, dest, f"payload{ext}", "decoded")]

    def h_cpio(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with src.open("rb") as fp:
            entries = list(iter_cpio(fp, art.size, self.limits.max_files))
            for e in entries:
                self._materialize_entry(art, out, fp, e)
        self._record_fs(art, "cpio", out)
        return self._register_tree(art, out)

    def h_romfs(self, art: Artifact, base: int = 0) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with src.open("rb") as fp:
            for e in list(iter_romfs(fp, base, art.size, self.limits.max_files)):
                self._materialize_entry(art, out, fp, e)
        self._record_fs(art, "romfs", out)
        return self._register_tree(art, out)

    def h_cromfs(self, art: Artifact) -> list[Artifact]:
        import io
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with src.open("rb") as fp:
            hdr = cromfs_header(fp.read(20), art.size)
            if hdr:
                art.details.update({"cromfs_" + k: v for k, v in hdr.items()})
            for e, data in iter_cromfs(fp, 0, art.size, self.limits.max_files, self.limits.max_file_bytes):
                if e.kind == "file" and data is not None:
                    self._materialize_entry(art, out, io.BytesIO(data), e)
                elif e.kind != "dir":
                    self._record_link(art, e.name, e.kind, None)
        self._record_fs(art, "cromfs", out)
        return self._register_tree(art, out)

    def _materialize_entry(self, art: Artifact, out: Path, fp: BinaryIO, e) -> None:
        if e.kind == "dir":
            return
        if e.kind != "file":
            self._record_link(art, e.name, e.kind, e.link_target)
            return
        try:
            rel = safe_member_path(e.name)
            dest = _confined(out, rel)
        except UnsafePath as exc:
            self.result.warnings.append(f"{art.name}: rejected member {e.name!r}: {exc}")
            return
        if dest.exists():
            return
        fp.seek(e.offset)
        if self._member_write(art, e.name, _Bounded(fp, e.size), dest):
            self._note_meta(dest, mode=e.mode, uid=e.uid, gid=e.gid)

    def h_dfu(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        children = []
        with src.open("rb") as fp:
            meta, elements = parse_dfuse(fp, art.size)
            art.details.update(meta)
            for el in elements:
                name = f"target{el.target}_{el.address:08x}.bin"
                dest = out / name
                fp.seek(el.offset)
                self._write_stream(_Bounded(fp, el.size), dest, label=name)
                c = self._child(art, dest, name, "decoded")
                c.details["load_address"] = hex(el.address)
                if el.target_name:
                    c.details["target_name"] = el.target_name
                children.append(c)
        return children

    def h_disk_image(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        children = []
        with src.open("rb") as fp:
            scheme, parts = parse_partitions(fp, art.size)
            art.details["partition_table"] = scheme
            art.details["partitions"] = [asdict(p) for p in parts]
            for p in parts:
                name = f"partition{p.index}_{_sanitize_component(p.type_id)}.img"
                dest = out / name
                fp.seek(p.offset)
                self._write_stream(_Bounded(fp, p.size), dest, label=name)
                children.append(self._child(art, dest, name, "partition"))
        return children

    # ---- external filesystem tools ----------------------------------------
    def _run_tool(self, art: Artifact, cmd: list[str], out: Path, env: dict | None = None) -> None:
        limit_file = self.limits.max_file_bytes
        remaining = self.budget.remaining_bytes

        def preexec() -> None:  # pragma: no cover - runs in child
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit_file, limit_file))
            resource.setrlimit(resource.RLIMIT_CPU, (self.limits.tool_timeout_s, self.limits.tool_timeout_s + 5))
            os.setsid()

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                preexec_fn=preexec, env={"PATH": os.environ.get("PATH", ""), **(env or {})})
        deadline = time.monotonic() + self.limits.tool_timeout_s
        reason = None
        while proc.poll() is None:
            time.sleep(0.25)
            if time.monotonic() > deadline:
                reason = f"{cmd[0]} timed out after {self.limits.tool_timeout_s}s"
            elif _dir_size(out) > remaining:
                reason = f"{cmd[0]} output exceeded remaining extraction budget"
            if reason:
                proc.kill()
                proc.wait()
                break
        output = (proc.stdout.read() if proc.stdout else b"")[-4000:].decode("utf-8", "replace")
        art.details["tool_output_tail"] = output[-800:]
        if reason:
            raise LimitExceeded(reason)
        if proc.returncode not in (0, None):
            # Partial output is still useful; record and keep going.
            self.result.warnings.append(f"{art.name}: {cmd[0]} exited with status {proc.returncode}")

    def _sanitize_tree(self, art: Artifact, out: Path) -> None:
        """Remove links/special files created by external tools, clamp modes, then charge the budget.

        Links are removed in a first pass so a budget error can never leave links behind."""
        regular: list[tuple[Path, os.stat_result]] = []
        for dirpath, dirnames, filenames in os.walk(out, followlinks=False):
            for name in list(dirnames) + filenames:
                p = Path(dirpath) / name
                rel = "/" + str(p.relative_to(out))
                st = p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    try:
                        target = os.readlink(p)[:4096]
                    except OSError:
                        target = None
                    self._record_link(art, rel, "symlink", target)
                    p.unlink()
                    if name in dirnames:
                        dirnames.remove(name)
                elif stat.S_ISDIR(st.st_mode):
                    os.chmod(p, 0o755)
                elif stat.S_ISREG(st.st_mode):
                    os.chmod(p, 0o644)
                    regular.append((p, st))
                else:
                    kind = "device" if (stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode)) else "fifo"
                    self._record_link(art, rel, kind, None)
                    p.unlink()
        for p, st in regular:
            self._pending_meta.setdefault(str(p), {"mode": st.st_mode & 0o7777})
            self.budget.charge_file()
            self.budget.charge_bytes(st.st_size, file_total=st.st_size)

    def _need_tool(self, tool: str, fs: str) -> str:
        path = self._external_tools.get(tool)
        if not path:
            raise UnsupportedFormat(f"{fs} detected but '{tool}' is not installed in the extraction "
                                    f"environment; filesystem contents were not extracted")
        return path

    def h_squashfs(self, art: Artifact) -> list[Artifact]:
        tool = self._need_tool("unsquashfs", "SquashFS")
        if not self.in_container and not _unsquashfs_safe(tool):
            raise UnsupportedFormat("SquashFS detected but the host unsquashfs is older than 4.5.1 (symlink "
                                    "traversal fixes); use the container sandbox to extract it")
        out = self._out_dir(art)
        dest = out / "root"
        self._tree_roots[art.id] = (out, True)
        self._run_tool(art, [tool, "-no-xattrs", "-ignore-errors", "-quiet", "-no-progress", "-d", str(dest),
                             str(self.path_of(art.id))], out)
        self._sanitize_tree(art, out)
        root = dest if dest.exists() else out
        self._record_fs(art, "squashfs", root, image_artifact=art.id)
        return self._register_tree(art, root)

    def h_ext(self, art: Artifact) -> list[Artifact]:
        """ext2/3/4 via debugfs, without 'rdump'.

        rdump materialises symlinks and then writes later entries *through* them (a crafted image with
        duplicate directory entries can write outside the extraction root).  Instead the tree is listed
        with 'ls -p' and each regular file is written with 'dump' to a path we created and confined.
        """
        tool = self._need_tool("debugfs", "ext2/3/4 filesystem")
        out = self._out_dir(art)
        dest = out / "root"
        dest.mkdir()
        self._tree_roots[art.id] = (dest, False)
        files = self._ext_list(art, tool)
        self._record_fs(art, "ext", dest, image_artifact=art.id)
        planned: list[tuple[str, Path, int, dict]] = []
        reserved = 0
        over_budget = None
        for path, mode, uid, gid, size in files:
            try:
                target = _confined(dest, safe_member_path(path))
            except UnsafePath as exc:
                self.result.warnings.append(f"{art.name}: rejected member {path!r}: {exc}")
                continue
            if size > self.limits.max_file_bytes:
                self.result.warnings.append(f"{art.name}: {path} skipped ({size} bytes exceeds per-file limit)")
                self.result.limits_hit.append("max_file_bytes")
                continue
            if reserved + size > self.budget.remaining_bytes or self.budget.files_created + len(planned) >= self.limits.max_files:
                over_budget = f"ext image content exceeds remaining extraction budget at {path}"
                break
            if target.exists():
                self.result.warnings.append(f"{art.name}: duplicate entry {path!r} skipped")
                continue
            reserved += size
            planned.append((path, target, size, {"mode": mode & 0o7777, "uid": uid, "gid": gid}))
        seen_targets: set[str] = set()
        batch: list[str] = []
        todo = []
        for path, target, size, meta in planned:
            if str(target) in seen_targets:
                continue
            seen_targets.add(str(target))
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
            except (FileExistsError, NotADirectoryError):
                self.result.warnings.append(f"{art.name}: rejected member {path!r}: path collision")
                continue
            batch.append(f'dump "{path}" "{target}"\n')
            todo.append((target, size, meta))
        for i in range(0, len(batch), 2000):
            self._debugfs(art, tool, batch[i:i + 2000])
        for target, _size, meta in todo:
            try:
                st = target.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(st.st_mode):
                target.unlink()
                continue
            os.chmod(target, 0o644)
            self.budget.charge_file()
            self.budget.charge_bytes(st.st_size, file_total=st.st_size)
            self._note_meta(target, **meta)
        if over_budget:
            raise LimitExceeded(over_budget)
        return self._register_tree(art, dest)

    def _debugfs(self, art: Artifact, tool: str, commands: list[str]) -> str:
        cmdfile = self.work_dir / f".debugfs_{art.id}.cmd"
        cmdfile.write_text("".join(commands))
        limit_file = self.limits.max_file_bytes
        cpu = self.limits.tool_timeout_s

        def preexec() -> None:  # pragma: no cover - runs in child
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit_file, limit_file))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))

        try:
            proc = subprocess.run([tool, "-f", str(cmdfile), str(self.path_of(art.id))], capture_output=True,
                                  timeout=self.limits.tool_timeout_s, stdin=subprocess.DEVNULL, preexec_fn=preexec)
        except subprocess.TimeoutExpired:
            raise LimitExceeded(f"debugfs timed out after {self.limits.tool_timeout_s}s") from None
        finally:
            cmdfile.unlink(missing_ok=True)
        return proc.stdout.decode("utf-8", "replace")

    def _ext_list(self, art: Artifact, tool: str) -> list[tuple[str, int, int, int, int]]:
        """Breadth-first listing via 'ls -p'. Returns regular files as (path, mode, uid, gid, size)."""
        files: list[tuple[str, int, int, int, int]] = []
        seen_dirs: set[str] = set()
        level = ["/"]
        depth = 0
        entries = 0
        while level and depth <= MAX_PATH_DEPTH:
            out = self._debugfs(art, tool, [f'ls -p "{d}"\n' for d in level])
            nxt: list[str] = []
            current = None
            for line in out.splitlines():
                if line.startswith("debugfs: ls -p "):
                    current = line[len("debugfs: ls -p "):].strip()
                    if len(current) >= 2 and current[0] == current[-1] == '"':
                        current = current[1:-1]
                    continue
                parts = line.split("/")
                if current is None or len(parts) < 7 or parts[0] != "":
                    continue
                try:
                    ino, mode, uid, gid = int(parts[1]), int(parts[2], 8), int(parts[3]), int(parts[4])
                    size = int(parts[6]) if parts[6] else 0
                except ValueError:
                    continue
                name = parts[5]
                if name in (".", "..", ""):
                    continue
                path = (current.rstrip("/") + "/" + name)
                if any(c in name for c in '"\\\n\r') or not name.isprintable():
                    self.result.warnings.append(f"{art.name}: entry with unsupported characters skipped: {name!r}")
                    continue
                entries += 1
                if entries > self.limits.max_files:
                    self.result.limits_hit.append("max_files")
                    return files
                if stat.S_ISDIR(mode):
                    key = f"{ino}"
                    if key not in seen_dirs:
                        seen_dirs.add(key)
                        nxt.append(path)
                elif stat.S_ISREG(mode):
                    files.append((path, mode, uid, gid, size))
                elif stat.S_ISLNK(mode):
                    self._record_link(art, path, "symlink", None)
                else:
                    kind = "device" if (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)) else "fifo"
                    self._record_link(art, path, kind, None)
            level = nxt[:20000]
            depth += 1
        return files

    def h_fat(self, art: Artifact) -> list[Artifact]:
        tool = self._need_tool("mcopy", "FAT filesystem")
        out = self._out_dir(art)
        dest = out / "root"
        dest.mkdir()
        self._tree_roots[art.id] = (dest, True)
        self._run_tool(art, [tool, "-s", "-n", "-p", "-i", str(self.path_of(art.id)), "::/", str(dest)], out,
                       env={"MTOOLS_SKIP_CHECK": "1"})
        self._sanitize_tree(art, out)
        self._record_fs(art, "fat", dest, image_artifact=art.id)
        return self._register_tree(art, dest)

    def _container_only(self, tool: str, fs: str) -> str:
        path = self._need_tool(tool, fs)
        if not self.in_container:
            raise UnsupportedFormat(f"{fs} detected; '{tool}' is only run inside the container sandbox because it "
                                    "may follow links it creates (scan ran without container isolation)")
        return path

    def h_ubi(self, art: Artifact) -> list[Artifact]:
        tool = self._container_only("ubireader_extract_files", "UBI/UBIFS image")
        out = self._out_dir(art)
        dest = out / "root"
        self._tree_roots[art.id] = (out, True)
        self._run_tool(art, [tool, "-k", "-o", str(dest), str(self.path_of(art.id))], out)
        self._sanitize_tree(art, out)
        root = _single_child_root(dest)
        self._record_fs(art, "ubifs", root, image_artifact=art.id)
        return self._register_tree(art, root)

    def h_jffs2(self, art: Artifact) -> list[Artifact]:
        tool = self._container_only("jefferson", "JFFS2 image")
        out = self._out_dir(art)
        dest = out / "root"
        self._tree_roots[art.id] = (out, True)
        self._run_tool(art, [tool, "-d", str(dest), str(self.path_of(art.id))], out)
        self._sanitize_tree(art, out)
        root = dest if dest.exists() else out
        self._record_fs(art, "jffs2", root, image_artifact=art.id)
        return self._register_tree(art, root)

    def h_unsupported(self, art: Artifact) -> list[Artifact]:
        raise UnsupportedFormat(f"{art.format_description}: unpacking this format is not supported yet")

    # ---- carving -----------------------------------------------------------
    def _carve(self, art: Artifact) -> list[Artifact]:
        """Carve well-delimited embedded objects out of raw images."""
        src = self.path_of(art.id)
        found: list[tuple[int, int, str]] = []  # (offset, length, kind)
        with src.open("rb") as fp:
            for off, kind in _scan_magics(fp, art.size, self.limits.max_carves_per_file * 8):
                if off == 0:
                    continue
                if any(o <= off < o + ln for o, ln, _ in found):
                    continue
                length = _carve_length(fp, off, kind, art.size)
                if length and kind in ("gz", "xz"):
                    length = _stream_length(fp, off, kind, self.limits.max_file_bytes)
                if length:
                    found.append((off, length, kind))
                if len(found) >= self.limits.max_carves_per_file:
                    self.result.limits_hit.append("max_carves_per_file")
                    break
            if not found:
                return []
            out = self._out_dir(art)
            children = []
            for off, length, kind in found:
                name = f"carved_{off:08x}.{kind}"
                dest = out / name
                fp.seek(off)
                if kind in ("gz", "xz"):
                    reader = _GzipMemberReader(fp) if kind == "gz" else _XzStreamReader(fp)
                    try:
                        self._write_stream(reader, dest, compressed_size=max(length, 1), label=name)
                    except (zlib.error, lzma.LZMAError, EOFError) as exc:
                        dest.unlink(missing_ok=True)
                        self.result.warnings.append(f"{art.name}: {kind} stream at {off:#x} invalid ({exc})")
                        continue
                    name = name[: -len(kind) - 1] + (".gunzipped" if kind == "gz" else ".unxz")
                    new = dest.with_name(name)
                    dest.rename(new)
                    dest = new
                else:
                    self._write_stream(_Bounded(fp, length), dest, label=name)
                c = self._child(art, dest, name, "carved")
                c.details["carved_offset"] = hex(off)
                children.append(c)
        art.details["carved_objects"] = len(children)
        return children


class UnsupportedFormat(Exception):
    pass


class _Bounded:
    """File wrapper that yields at most ``n`` bytes from the current position."""

    def __init__(self, fp: BinaryIO, n: int) -> None:
        self.fp, self.left = fp, max(n, 0)

    def read(self, size: int = -1) -> bytes:
        if self.left <= 0:
            return b""
        size = self.left if size < 0 else min(size, self.left)
        data = self.fp.read(size)
        self.left -= len(data)
        return data


LZMA_MEMLIMIT = 256 * 1024**2


class _LzmaReader:
    """Streaming xz/lzma reader with a decoder memory limit (huge dictionary sizes are rejected)."""

    def __init__(self, path: Path, fmt: int) -> None:
        self.fp = path.open("rb")
        self.fmt = fmt
        self.d = lzma.LZMADecompressor(format=fmt, memlimit=LZMA_MEMLIMIT)
        self.pending = b""

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.fp.close()

    def read(self, size: int = -1) -> bytes:
        while True:
            if self.d.eof:
                if self.fmt != lzma.FORMAT_XZ:
                    return b""
                rest = self.d.unused_data + self.pending
                self.pending = b""
                if not rest.strip(b"\0"):
                    rest += self.fp.read(64 * 1024)
                    if not rest.strip(b"\0"):
                        return b""
                self.d = lzma.LZMADecompressor(format=self.fmt, memlimit=LZMA_MEMLIMIT)  # concatenated stream
                self.pending = rest
            if self.d.needs_input:
                data = self.pending or self.fp.read(64 * 1024)
                self.pending = b""
                if not data:
                    raise EOFError("truncated LZMA stream")
            else:
                data = b""
            out = self.d.decompress(data, COPY_CHUNK)
            if out:
                return out


class _XzStreamReader:
    """Decompress exactly one xz stream starting at the current position (memory-limited)."""

    def __init__(self, fp: BinaryIO) -> None:
        self.fp = fp
        self.d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LZMA_MEMLIMIT)

    def read(self, size: int = -1) -> bytes:
        while not self.d.eof:
            if self.d.needs_input:
                data = self.fp.read(64 * 1024)
                if not data:
                    raise EOFError("truncated xz stream")
            else:
                data = b""
            out = self.d.decompress(data, COPY_CHUNK)
            if out:
                return out
        return b""


def _stream_length(fp: BinaryIO, off: int, kind: str, max_out: int) -> int | None:
    """Compressed length of the gzip/xz stream at ``off`` (test-decode, output discarded and capped)."""
    fp.seek(off)
    if kind == "gz":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    else:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LZMA_MEMLIMIT)
    consumed = 0
    produced = 0
    try:
        while True:
            if kind == "xz" and not d.needs_input:
                chunk = b""
            else:
                chunk = fp.read(64 * 1024)
                if not chunk:
                    return None
            consumed += len(chunk)
            out = d.decompress(chunk, COPY_CHUNK)
            produced += len(out)
            if kind == "gz":
                while d.unconsumed_tail and produced <= max_out:
                    out = d.decompress(d.unconsumed_tail, COPY_CHUNK)
                    produced += len(out)
            if produced > max_out:
                return None
            if d.eof:
                return consumed - len(d.unused_data)
    except (zlib.error, lzma.LZMAError, EOFError, MemoryError):
        return None


class _GzipMemberReader:
    """Decompress exactly one gzip member starting at the current position."""

    def __init__(self, fp: BinaryIO) -> None:
        self.fp = fp
        self.d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.tail = b""
        self.done = False

    def read(self, size: int = -1) -> bytes:
        while not self.done:
            data = self.tail or self.fp.read(64 * 1024)
            if not data:
                raise EOFError("truncated gzip stream")
            out = self.d.decompress(data, COPY_CHUNK)
            self.tail = self.d.unconsumed_tail
            if self.d.eof:
                self.done = True
            if out:
                return out
        return b""


CARVE_MAGICS = {
    b"hsqs": "squashfs",
    b"\x1f\x8b\x08": "gz",
    b"\x27\x05\x19\x56": "uimage",
    b"-rom1fs-": "romfs",
    b"CROM": "cromfs",
    b"\xfd7zXZ\x00": "xz",
    b"070701": "cpio",
    b"\x7fELF": "elf",
}


def _scan_magics(fp: BinaryIO, size: int, max_hits: int):
    chunk = 4 * 1024**2
    overlap = 16
    pos = 0
    hits = 0
    while pos < size:
        fp.seek(pos)
        block = fp.read(chunk + overlap)
        if not block:
            break
        found = []
        for magic, kind in CARVE_MAGICS.items():
            start = 0
            while True:
                i = block.find(magic, start)
                if i < 0 or i >= chunk:
                    break
                found.append((pos + i, kind))
                start = i + 1
                if len(found) > max_hits:
                    break
        for item in sorted(found):
            yield item
            hits += 1
            if hits >= max_hits:
                return
        pos += chunk


def _all_erased(fp: BinaryIO, size: int) -> bool:
    left = size
    while left > 0:
        chunk = fp.read(min(COPY_CHUNK, left))
        if not chunk:
            break
        if chunk.count(0xFF) != len(chunk):
            return False
        left -= len(chunk)
    return True


def _carve_length(fp: BinaryIO, off: int, kind: str, size: int) -> int | None:
    fp.seek(off)
    head = fp.read(128)
    if kind == "squashfs":
        if len(head) < 96:
            return None
        major = struct.unpack_from("<H", head, 28)[0]
        bytes_used = struct.unpack_from("<Q", head, 40)[0]
        if major != 4 or not (96 < bytes_used <= size - off):
            return None
        return bytes_used
    if kind == "uimage":
        hdr = parse_uimage_header(head)
        if not hdr:
            return None
        if zlib.crc32(head[:4] + b"\x00\x00\x00\x00" + head[8:64]) & 0xFFFFFFFF != struct.unpack(">I", head[4:8])[0]:
            return None
        n = 64 + hdr["data_size"]
        return n if off + n <= size else None
    if kind == "romfs":
        n = romfs_size(head)
        return n if n and 32 <= n <= size - off else None
    if kind == "cromfs":
        hdr = cromfs_header(head, size - off)
        return hdr["fsize"] if hdr else None
    if kind == "xz":
        return size - off  # upper bound; the reader stops at the end of the stream
    if kind == "gz":
        flags = head[3] if len(head) > 3 else 0xFF
        if flags & 0xE0:
            return None
        return size - off  # upper bound; reader stops at end of member
    if kind == "cpio":
        fp.seek(off)
        window = fp.read(min(size - off, 64 * 1024**2))
        end = window.find(b"TRAILER!!!")
        if end < 0:
            return None
        return min(((end + 10 + 511) // 512) * 512, len(window))
    if kind == "elf":
        if len(head) < 64 or head[4] not in (1, 2) or head[5] not in (1, 2) or head[6] != 1:
            return None
        end = "<" if head[5] == 1 else ">"
        if head[4] == 1:
            shoff = struct.unpack_from(end + "I", head, 32)[0]
            shentsize, shnum = struct.unpack_from(end + "HH", head, 46)
        else:
            shoff = struct.unpack_from(end + "Q", head, 40)[0]
            shentsize, shnum = struct.unpack_from(end + "HH", head, 58)
        n = shoff + shentsize * shnum
        if shnum == 0 or shentsize == 0 or not (64 < n <= size - off):
            return None
        return n
    return None


def _single_child_root(dest: Path) -> Path:
    """ubi_reader writes <dest>/<image-seq>/<volume>/...; descend while there is exactly one directory."""
    root = dest
    for _ in range(3):
        if not root.is_dir():
            return dest if dest.exists() else dest.parent
        kids = list(root.iterdir())
        if len(kids) == 1 and kids[0].is_dir() and not (root / "etc").exists():
            root = kids[0]
        else:
            break
    return root


_UNSQUASHFS_OK: dict[str, bool] = {}


def _unsquashfs_safe(tool: str) -> bool:
    """unsquashfs < 4.5.1 is affected by symlink traversal (CVE-2021-40153/CVE-2021-41072)."""
    if tool not in _UNSQUASHFS_OK:
        import re
        try:
            out = subprocess.run([tool, "-version"], capture_output=True, timeout=10).stdout.decode("ascii", "replace")
        except (subprocess.SubprocessError, OSError):
            out = ""
        m = re.search(r"version (\d+)\.(\d+)(?:\.(\d+))?", out)
        ver = tuple(int(x or 0) for x in m.groups()) if m else (0, 0, 0)
        _UNSQUASHFS_OK[tool] = ver >= (4, 5, 1)
    return _UNSQUASHFS_OK[tool]


def _dir_size(path: Path) -> int:
    total = 0
    for dirpath, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return total


HANDLERS: dict[str, Callable[[Extractor, Artifact], list[Artifact]]] = {
    "zip": Extractor.h_zip,
    "tar": Extractor.h_tar,
    "gzip": Extractor.h_gzip,
    "bzip2": Extractor.h_bzip2,
    "xz": Extractor.h_xz,
    "lzma": Extractor.h_lzma,
    "zstd": Extractor.h_zstd,
    "lz4": Extractor.h_lz4,
    "lz4_legacy": Extractor.h_lz4_legacy,
    "lzop": Extractor.h_lzop,
    "cramfs": Extractor.h_cramfs,
    "erofs": Extractor.h_erofs,
    "android_sparse": Extractor.h_android_sparse,
    "parrot_plf": Extractor.h_parrot_plf,
    "dji_imah": Extractor.h_dji_imah,
    "esp_image": Extractor.h_esp_image,
    "esp_flash": Extractor.h_esp_flash,
    "ihex": Extractor.h_ihex,
    "px4": Extractor.h_fw_json,
    "apj": Extractor.h_fw_json,
    "fw_json": Extractor.h_fw_json,
    "uimage": Extractor.h_uimage,
    "cpio": Extractor.h_cpio,
    "romfs": Extractor.h_romfs,
    "cromfs": Extractor.h_cromfs,
    "dfu": Extractor.h_dfu,
    "disk_image": Extractor.h_disk_image,
    "squashfs": Extractor.h_squashfs,
    "ext": Extractor.h_ext,
    "fat": Extractor.h_fat,
    "ubi": Extractor.h_ubi,
    "ubifs": Extractor.h_ubi,
    "jffs2": Extractor.h_jffs2,
}

__all__ = ["Extractor", "Artifact", "ExtractionResult", "safe_member_path", "UnsafePath"]
