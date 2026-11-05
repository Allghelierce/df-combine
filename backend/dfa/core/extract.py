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
import contextlib
import hashlib
import json
import lzma
import os
import re
import resource
import shutil
import stat
import struct
import subprocess
import tarfile
import threading
import time
import zipfile
import zlib
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .formats import more, px4json, zipnames
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
from .identify import HEAD_BYTES, FormatInfo, detect_format, detect_format_bytes, parse_uimage_header
from .limits import ExtractionBudget, LimitExceeded, Limits
from .text import escape_surrogates

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
    # Windows separators first; then bytes that are not UTF-8 become a literal "\xNN" (after, so it stays one name)
    name = escape_surrogates(name.replace("\\", "/"))
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


_NOT_PADDING = re.compile(rb"[^\x00\xff]")


class _SkipCountingTarInfo(tarfile.TarInfo):
    """Counts the blocks tarfile skips with ignore_zeros (zero blocks, damaged headers) on its TarFile."""

    @classmethod
    def fromtarfile(cls, tarfile_):  # noqa: ANN001, ANN206 - tarfile's own signature
        try:
            return super().fromtarfile(tarfile_)
        except (tarfile.EOFHeaderError, tarfile.InvalidHeaderError):
            tarfile_.dfa_skipped_blocks = getattr(tarfile_, "dfa_skipped_blocks", 0) + 1
            raise


def _unused_name(directory: Path, name: str) -> Path:
    p = directory / name
    n = 1
    while os.path.lexists(p):
        p = directory / f"{name}~{n}"
        n += 1
    return p


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
        self._dir_meta: dict[int, dict[str, tuple[int, int, int]]] = {}  # container -> dir -> (mode, uid, gid)
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
        self._write_mode_images()
        self.result.stats = {
            "artifacts": len(self.result.artifacts),
            "bytes_written": self.budget.bytes_written,
            "files_created": self.budget.files_created,
            "duration_s": round(time.monotonic() - t0, 3),
            "external_tools": {k: bool(v) for k, v in self._external_tools.items()},
        }
        return self.result

    # ---- permission images for FwAnalyzer ---------------------------------
    def _write_mode_images(self) -> None:
        """An extracted tree has normalised modes (setuid bits are never applied), so FwAnalyzer cannot check
        permissions on it. For root filesystems whose original metadata is known (tar, ext) write a cpio (newc)
        archive that carries modes and owners as header fields; FwAnalyzer reads it in cpio image mode.
        Also for SquashFS, whose original metadata comes from 'unsquashfs -lln'."""
        for fs in self.result.filesystems:
            if fs["type"] not in ("tar", "ext") and not fs.get("unix_modes"):  # zip made on Unix, listed SquashFS
                continue
            root = self.work_dir / fs["root"]
            if not (root / "etc").is_dir() or not ((root / "bin").exists() or (root / "usr").is_dir()):
                continue
            try:
                fs["mode_image"], fs["mode_image_skipped"] = self._write_cpio(fs["artifact_id"], root)
            except (OSError, LimitExceeded) as exc:
                self.result.warnings.append(f"{fs['name']}: no permission image for FwAnalyzer ({exc})")
            special = {"/" + d: m for d, (m, _u, _g) in sorted(self._dir_meta.get(fs["artifact_id"], {}).items())
                       if m & 0o7002}  # setuid/setgid/sticky or world-writable directories (original modes)
            if special:
                fs["special_dirs"] = dict(list(special.items())[:500])

    def _write_cpio(self, parent_id: int, root: Path) -> tuple[str, int]:
        ok_name = re.compile(r"^[^\s\x00-\x1f\x7f]+$")  # FwAnalyzer parses 'cpio -tv' listings by whitespace
        skipped = 0
        entries: list[tuple[str, int, int, int, bytes | Path]] = []  # (name, mode, uid, gid, data)
        dmeta = self._dir_meta.get(parent_id, {})
        dirs = set(dmeta)  # recorded directories include empty ones (e.g. /tmp), which extraction never creates
        for dirpath, dirnames, _files in os.walk(root):
            dirs.update(str((Path(dirpath) / d).relative_to(root)) for d in dirnames)
        entries.append((".", 0o040755, 0, 0, b""))  # FwAnalyzer's cpio backend needs the root entry
        for rel in dirs:
            mode, uid, gid = dmeta.get(rel, (0o755, 0, 0))
            entries.append((rel, 0o040000 | mode, uid, gid, b""))
        for a in self.result.artifacts:
            if a.parent_id != parent_id or a.origin != "extracted":
                continue
            rel = a.name.lstrip("/")
            p = self._paths[a.id]
            entries.append((rel, 0o100000 | (a.mode if a.mode is not None else 0o644), a.uid or 0, a.gid or 0, p))
        for ln in self.result.links:
            if ln.artifact_parent == parent_id and ln.kind == "symlink" and ln.target:
                with contextlib.suppress(UnsafePath):
                    rel = str(safe_member_path(ln.path)).strip("/")
                    entries.append((rel, 0o120777, 0, 0, ln.target.encode("utf-8", "replace")[:4096]))
        dest = root.parent / f"{root.name}.modes.cpio"
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        written = 0
        with os.fdopen(fd, "wb") as out:
            def put(name: str, mode: int, uid: int, gid: int, size: int, ino: int) -> None:
                nonlocal written
                raw = name.encode("utf-8", "replace") + b"\0"
                hdr = b"070701" + b"".join(b"%08X" % v for v in (ino, mode, uid, gid, 1, 0, size, 0, 0, 0, 0,
                                                                 len(raw), 0))
                blob = hdr + raw
                blob += b"\0" * (-len(blob) % 4)
                out.write(blob)
                written += len(blob)
            for ino, (name, mode, uid, gid, data) in enumerate(sorted(entries, key=lambda e: e[0]), 1):
                if not ok_name.match(name):
                    skipped += 1
                    continue
                if isinstance(data, Path):
                    size = data.stat().st_size
                    put(name, mode, uid, gid, size, ino)
                    with data.open("rb") as src:
                        while chunk := src.read(COPY_CHUNK):
                            out.write(chunk)
                            self.budget.charge_bytes(len(chunk))
                    pad = -size % 4
                else:
                    put(name, mode, uid, gid, len(data), ino)
                    out.write(data)
                    pad = -len(data) % 4
                out.write(b"\0" * pad)
            put("TRAILER!!!", 0, 0, 0, 0, 0)
        return self._rel(dest), skipped

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
        if art.format == "elf" and not _is_mcu_elf(self.path_of(art.id)):
            for child in self._elf_overlay(art):  # ordinary ELF files are analysed as they are; data appended
                self._process(child)              # after their own data (an overlay) is looked at on its own
            return
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
                if art.format in DECLARED_SIZE_FORMATS:  # data after the image: an overlay, another partition
                    children += self._after_declared_size(art)
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

    def _after_declared_size(self, art: Artifact) -> list[Artifact]:
        path = self.path_of(art.id)
        with path.open("rb") as fp:
            end = _declared_image_size(art.format, fp.read(4096))
        if not end or end >= art.size:
            return []
        return self._trailing_data(art, path, end, f"the {art.format_description} ({end:,} bytes declared)")

    def _elf_overlay(self, art: Artifact) -> list[Artifact]:
        """Data appended after an executable's own data: self-extracting and packed programs (PyInstaller, pkg)
        carry their payload there, and so can a dropper. A signed kernel module's appended signature is known
        and only recorded."""
        path = self.path_of(art.id)
        with path.open("rb") as fp:
            end = _elf_data_end(fp, art.size)
            if end is None or end >= art.size:
                return []
            fp.seek(art.size - len(MODULE_SIG_MARKER))
            if fp.read() == MODULE_SIG_MARKER:
                art.details["module_signature_bytes"] = art.size - end
                return []
        return self._trailing_data(art, path, end, "the ELF file's own data")

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
            self.result.links.append(LinkRecord(parent.id, escape_surrogates(name), kind,
                                                None if target is None else escape_surrogates(target)))

    def _record_fs(self, parent: Artifact, fs_type: str, out_dir: Path, **extra) -> None:
        self.result.filesystems.append({"artifact_id": parent.id, "type": fs_type,
                                        "root": self._rel(out_dir), "name": parent.name, **extra})

    # ---- handlers ----------------------------------------------------------
    def h_zip(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        with contextlib.ExitStack() as stack:
            shown: dict[str, str] = {}
            try:
                zf = stack.enter_context(zipfile.ZipFile(src))
            except UnicodeDecodeError:  # an entry flagged UTF-8 whose name is not: read such names as bytes
                patches, shown = zipnames.utf8_flag_fixes(src)
                zf = stack.enter_context(zipfile.ZipFile(stack.enter_context(zipnames.PatchedReader(src, patches))))
                self.result.warnings.append(f"{art.name}: {len(shown)} member name(s) flagged UTF-8 are not UTF-8 "
                                            "(shown with \\xNN escapes)")
            infos = zf.infolist()
            if len(infos) > self.limits.max_files:
                raise LimitExceeded(f"zip declares {len(infos)} entries (limit {self.limits.max_files})")
            # Unix modes are only meaningful for archives made on Unix (create_system 3); others carry none
            unix = bool(infos) and sum(1 for zi in infos if zi.create_system == 3) * 2 > len(infos)
            for zi in infos:
                name = shown.get(zi.orig_filename, zi.filename)
                mode = (zi.external_attr >> 16) & 0xFFFF if unix else 0
                if zi.is_dir():
                    if unix:
                        with contextlib.suppress(UnsafePath):
                            d = str(safe_member_path(name)).strip("/")
                            if d and d != ".":
                                self._dir_meta.setdefault(art.id, {})[d] = ((mode & 0o7777) or 0o755, 0, 0)
                    continue
                if stat.S_ISLNK(mode):
                    target = zf.read(zi)[:4096].decode("utf-8", "replace") if zi.file_size <= 4096 else None
                    self._record_link(art, name, "symlink", target)
                    continue
                if zi.flag_bits & 0x1:
                    self.result.warnings.append(f"{art.name}: encrypted member {name!r} skipped")
                    continue
                try:
                    rel = safe_member_path(name)
                    dest = _confined(out, rel)
                except UnsafePath as exc:
                    self.result.warnings.append(f"{art.name}: rejected member {name!r}: {exc}")
                    continue
                if dest.exists():
                    self.result.warnings.append(f"{art.name}: duplicate member {name!r} skipped")
                    continue
                with zf.open(zi) as member:
                    if not self._member_write(art, name, member, dest, compressed_size=max(zi.compress_size, 1)):
                        continue
                self._note_meta(dest, mode=(mode & 0o7777) or None)
        self._record_fs(art, "zip", out, **({"unix_modes": True} if unix else {}))
        return self._register_tree(art, out)

    def h_tar(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        # ignore_zeros: keep reading after an end-of-archive marker (concatenated archives) and past a damaged
        # header; tarfile would otherwise stop silently there, leaving everything after it unanalysed.
        with tarfile.open(src, mode="r:", ignore_zeros=True, tarinfo=_SkipCountingTarInfo) as tf:
            count = 0
            skipped = seen = 0  # blocks skipped before a member (trailing end-of-archive padding is not counted)
            end = 0  # where the last member's data ends: anything after it but padding is analysed on its own
            for ti in tf:
                count += 1
                end = max(end, ti.offset_data + (-(-ti.size // 512) * 512 if ti.isreg() else 0))
                if count > self.limits.max_files:
                    raise LimitExceeded(f"tar has more than {self.limits.max_files} entries")
                skipped, seen = skipped + getattr(tf, "dfa_skipped_blocks", 0) - seen, getattr(tf, "dfa_skipped_blocks", 0)
                if ti.isdir():
                    with contextlib.suppress(UnsafePath):
                        d = str(safe_member_path(ti.name)).strip("/")
                        if d and d != ".":
                            self._dir_meta.setdefault(art.id, {})[d] = (ti.mode & 0o7777, ti.uid, ti.gid)
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
        if skipped:
            self.result.warnings.append(f"{art.name}: {skipped * 512} bytes skipped between members (an "
                                        "end-of-archive marker or a damaged header); the members after them were "
                                        "extracted too")
        self._record_fs(art, "tar", out)
        children = self._register_tree(art, out)
        if end < art.size:  # e.g. an image appended after the archive's end-of-archive marker
            children += self._trailing_data(art, src, end, "the tar archive")
        return children

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
            trailing = getattr(stream, "trailing_offset", None)
        children = [self._child(art, dest, base, "decoded")]
        if trailing is not None:
            children += self._trailing_data(art, src, trailing, "the compressed data")
        return children

    def _trailing_data(self, art: Artifact, src: Path, off: int, what: str) -> list[Artifact]:
        """Data after the last stream or archive: flash padding (0xFF/0x00) is ignored, anything else is
        analysed as an artifact of its own instead of being dropped (it may be another image). It is written
        to a directory of its own, so it never appears inside an extracted root filesystem."""
        with src.open("rb") as fp:
            fp.seek(off)
            pos, data_at = off, None
            while chunk := fp.read(COPY_CHUNK):
                if m := _NOT_PADDING.search(chunk):
                    data_at = pos + m.start()
                    break
                pos += len(chunk)
            if data_at is None:
                if art.size > off:
                    art.details["trailing_padding_bytes"] = art.size - off
                return []
            if art.size - data_at <= 8:  # a size field or checksum after the data (kernel images), not content
                art.details["trailing_bytes"] = art.size - off
                return []
            # start after the padding, or back on the 4 KiB boundary when only zeros lie in between (an image placed
            # on an erase block may begin with zeros itself: ext's boot block); prefer whichever starts a known format
            cand = max(off, data_at - data_at % 4096)
            fp.seek(cand)
            zeros_only = not fp.read(data_at - cand).strip(b"\x00")
            off = data_at
            for start in dict.fromkeys((data_at, cand) if zeros_only else (data_at,)):
                fp.seek(start)
                if detect_format_bytes(fp.read(HEAD_BYTES), art.size - start).format not in ("raw", "text", "empty"):
                    off = start
                    break
            size = art.size - off
            name = f"trailing_{off:08x}.bin"
            tdir = self.root / f"{art.id:05d}_trailing.d"
            tdir.mkdir()
            dest = tdir / name
            fp.seek(off)
            self._write_stream(_Bounded(fp, size), dest, label=name)
        self.result.warnings.append(f"{art.name}: {size} bytes after {what} are not padding; "
                                    f"analysed separately as {name}")
        child = self._child(art, dest, name, "carved")
        child.details["carved_offset"] = hex(off)
        return [child]

    def h_gzip(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, lambda p: _ConcatenatedStreams(p, b"\x1f\x8b", _GzipMemberReader),
                                (".gz", ".tgz"))

    def h_bzip2(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, lambda p: _ConcatenatedStreams(p, b"BZh", _Bz2StreamReader), (".bz2", ".tbz2"))

    def h_xz(self, art: Artifact) -> list[Artifact]:
        return self._decompress(art, lambda p: _ConcatenatedStreams(p, b"\xfd7zXZ\x00", _XzStreamReader),
                                (".xz", ".txz"))

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

    def h_mcu_elf(self, art: Artifact) -> list[Artifact]:
        """Flash image of a bare-metal Cortex-M ELF (PX4/ArduPilot/NuttX builds), laid out by load address like
        'objcopy -O binary', plus its function symbols: bare-metal tools analyse the image with the exact load
        address, and their findings can be mapped back to function names."""
        from elftools.elf.elffile import ELFFile
        src = self.path_of(art.id)
        with src.open("rb") as fp:
            elf = ELFFile(fp)
            loads = [(s["p_paddr"], s["p_filesz"], s["p_offset"]) for s in elf.iter_segments()
                     if s["p_type"] == "PT_LOAD" and s["p_filesz"] > 0]
            if not loads:
                raise FormatError("no loadable segments")
            base = min(p for p, _, _ in loads)
            end = max(p + n for p, n, _ in loads)
            if end - base > 64 * 1024**2 or any(off + n > art.size for _, n, off in loads):
                raise LimitExceeded("ELF load segments span more than 64 MiB or exceed the file")
            image = bytearray(b"\xff" * (end - base))
            for paddr, filesz, off in loads:
                fp.seek(off)
                image[paddr - base:paddr - base + filesz] = fp.read(filesz)
            symbols = []
            tab = elf.get_section_by_name(".symtab")
            if tab is not None and hasattr(tab, "iter_symbols"):
                for sym in tab.iter_symbols():
                    if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] and sym.name:
                        symbols.append([sym["st_value"] & ~1, int(sym["st_size"]), sym.name[:200]])
                        if len(symbols) >= 200_000:
                            break
        out = self._out_dir(art)
        self._write_bytes(bytes(image), out / "flash.bin")
        child = self._child(art, out / "flash.bin", "flash.bin", "decoded")
        child.details.update({"load_address": hex(base), "derived_from_elf": True})
        if symbols:
            symbols.sort()
            readable = demangle([s[2] for s in symbols])
            for s in symbols:
                if s[2] in readable:
                    s.append(readable[s[2]])
            self._write_bytes(json.dumps(symbols, separators=(",", ":")).encode(), out / "symbols.json")
            child.details["symbol_map"] = self._rel(out / "symbols.json")
            child.details["symbol_count"] = len(symbols)
        return [child]

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
        children = [self._child(art, dest, f"payload{ext}", "decoded")]
        if 64 + size < art.size:  # e.g. the root filesystem after the kernel in a sysupgrade-style image
            children += self._trailing_data(art, src, 64 + size, "the uImage payload")
        return children

    def h_cpio(self, art: Artifact) -> list[Artifact]:
        src = self.path_of(art.id)
        out = self._out_dir(art)
        state: dict = {}
        with src.open("rb") as fp:
            entries = list(iter_cpio(fp, art.size, self.limits.max_files, state))
            for e in entries:
                self._materialize_entry(art, out, fp, e)
        self._record_fs(art, "cpio", out)
        children = self._register_tree(art, out)
        if state.get("trailing_offset") is not None:  # e.g. the compressed main archive of an initramfs
            children += self._trailing_data(art, src, state["trailing_offset"], "the cpio archive")
        return children

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
                if (clean := escape_surrogates(name)) != name:  # not UTF-8: rename so disk and manifest agree
                    q = _unused_name(Path(dirpath), clean)
                    os.rename(p, q)  # renames a link itself, never its target
                    if name in dirnames:
                        dirnames[dirnames.index(name)] = q.name
                    p, name = q, q.name
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
        listed = self._squashfs_modes(art, tool, root)
        self._record_fs(art, "squashfs", root, image_artifact=art.id, **({"unix_modes": True} if listed else {}))
        children = self._register_tree(art, root)
        with self.path_of(art.id).open("rb") as fp:
            end = _carve_length(fp, 0, "squashfs", art.size)
        if end and end < art.size:  # e.g. OpenWrt's writable overlay after the SquashFS in the rootfs partition
            children += self._trailing_data(art, self.path_of(art.id), end, "the SquashFS image")
        return children

    def _squashfs_modes(self, art: Artifact, tool: str, root: Path) -> bool:
        """Original modes and owners from 'unsquashfs -lln'. Extraction by an unprivileged user, as in the
        sandbox, drops setuid/setgid bits and owners, so the permission checks (built-in and FwAnalyzer) saw
        none in SquashFS root filesystems. Streams the listing with an entry cap and a deadline."""
        cpu = self.limits.tool_timeout_s

        def preexec() -> None:  # pragma: no cover - runs in child
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
            os.setsid()

        files: dict[str, tuple[int, int, int]] = {}
        dirs: dict[str, tuple[int, int, int]] = {}
        complete = False
        proc = subprocess.Popen([tool, "-lln", "-no-xattrs", str(self.path_of(art.id))], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, preexec_fn=preexec,
                                env={"PATH": os.environ.get("PATH", "")})
        timer = threading.Timer(self.limits.tool_timeout_s, proc.kill)
        timer.start()
        try:
            assert proc.stdout is not None
            for n, raw in enumerate(proc.stdout):
                if n > self.limits.max_files + 1:
                    break
                m = _LS_LINE.match(raw.rstrip(b"\n"))
                if not m or b"/" not in m.group(4):
                    continue  # the root line itself, device numbers, names with newlines
                mode = _ls_mode(m.group(1).decode("ascii"))
                rel = escape_surrogates(m.group(4).split(b"/", 1)[1].decode("utf-8", "surrogateescape"))
                if mode is None or not rel or any(part in ("", ".", "..") for part in rel.split("/")):
                    continue
                if stat.S_ISREG(mode):
                    files[rel] = (mode & 0o7777, int(m.group(2)), int(m.group(3)))
                elif stat.S_ISDIR(mode):
                    dirs[rel] = (mode & 0o7777, int(m.group(2)), int(m.group(3)))
            else:
                complete = proc.wait() == 0
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        if not complete:
            self.result.warnings.append(f"{art.name}: no original permissions (unsquashfs listing incomplete)")
            return False
        for rel, (mode, uid, gid) in files.items():
            key = str(root / rel)
            if key in self._pending_meta:  # only files the tree walk recorded: a listed "../x" matches nothing
                self._pending_meta[key] = {"mode": mode, "uid": uid, "gid": gid}
        self._dir_meta.setdefault(art.id, {}).update(dirs)
        return True

    def h_ext(self, art: Artifact) -> list[Artifact]:
        """ext2/3/4 via debugfs, without 'rdump'.

        rdump materialises symlinks and then writes later entries *through* them (a crafted image with
        duplicate directory entries can write outside the extraction root).  Instead the tree is listed
        with 'ls -p' and each regular file is written with 'dump', by inode number, to a name we chose; it
        is then moved to its confined path, so no name from the image ever appears in a debugfs command.
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
        for path, mode, uid, gid, size, ino in files:
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
            planned.append((path, target, size, {"mode": mode & 0o7777, "uid": uid, "gid": gid}, ino))
        seen_targets: set[str] = set()
        batch: list[str] = []
        todo = []
        staging = out / ".dump"  # debugfs writes by inode to names we chose; files are moved into place after
        staging.mkdir()
        for n, (path, target, size, meta, ino) in enumerate(planned):
            if str(target) in seen_targets:
                continue
            seen_targets.add(str(target))
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
            except (FileExistsError, NotADirectoryError):
                self.result.warnings.append(f"{art.name}: rejected member {path!r}: path collision")
                continue
            batch.append(f'dump <{ino}> "{staging / str(n)}"\n')
            todo.append((path, staging / str(n), target, size, meta))
        for i in range(0, len(batch), 2000):
            self._debugfs(art, tool, batch[i:i + 2000])
        for path, tmp, target, _size, meta in todo:
            try:
                st = tmp.lstat()
            except FileNotFoundError:
                self.result.warnings.append(f"{art.name}: {path!r} could not be read from the image")
                continue
            if not stat.S_ISREG(st.st_mode):
                tmp.unlink()
                continue
            try:
                os.rename(tmp, target)
            except OSError as exc:
                tmp.unlink(missing_ok=True)
                self.result.warnings.append(f"{art.name}: rejected member {path!r}: {exc.strerror}")
                continue
            os.chmod(target, 0o644)
            self.budget.charge_file()
            self.budget.charge_bytes(st.st_size, file_total=st.st_size)
            self._note_meta(target, **meta)
        shutil.rmtree(staging, ignore_errors=True)
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
        return proc.stdout.decode("utf-8", "surrogateescape")  # names keep their bytes (escaped later)

    def _ext_list(self, art: Artifact, tool: str) -> list[tuple[str, int, int, int, int, int]]:
        """Breadth-first listing via 'ls -p <inode>': no names in commands, so a name may hold any byte but '/'
        and NUL (quotes, backslashes, newlines, bytes that are not UTF-8 used to be skipped, together with
        everything below such a directory). Returns regular files as (path, mode, uid, gid, size, inode)."""
        files: list[tuple[str, int, int, int, int, int]] = []
        paths: dict[int, str] = {2: ""}  # directory inode -> display path (2: the root directory)
        level = [2]
        depth = 0
        while level and depth <= MAX_PATH_DEPTH:
            nxt: list[int] = []
            for i in range(0, len(level), 20_000):  # directories per debugfs run (all of them are listed)
                self._ext_ls(art, tool, level[i:i + 20_000], paths, nxt, files)
                if len(files) + len(paths) > self.limits.max_files:
                    self.result.limits_hit.append("max_files")
                    return files
            level = nxt
            depth += 1
        if level:
            self.result.warnings.append(f"{art.name}: directories nested deeper than {MAX_PATH_DEPTH} levels not listed")
        return files

    def _ext_ls(self, art: Artifact, tool: str, inodes: list[int], paths: dict[int, str], nxt: list[int],
                files: list[tuple[str, int, int, int, int, int]]) -> None:
        out = self._debugfs(art, tool, [f"ls -p <{ino}>\n" for ino in inodes])
        current: str | None = None
        record = ""
        for line in out.split("\n"):
            if line.startswith("debugfs: "):
                m = re.match(r"debugfs: ls -p <(\d+)>$", line)
                current, record = (paths.get(int(m.group(1))) if m else None), ""
                continue
            if current is None:
                continue
            record = f"{record}\n{line}" if record else line
            if not record.startswith("/") or record.count("\n") > 8:
                record = ""
                continue
            if record.count("/") < 7:
                continue  # a name with a newline: the record goes on in the next line
            parts, record = record.split("/"), ""
            if len(parts) != 8:
                continue
            try:
                ino, mode, uid, gid = int(parts[1]), int(parts[2], 8), int(parts[3]), int(parts[4])
                size = int(parts[6]) if parts[6] else 0
            except ValueError:
                continue
            name = parts[5]  # raw bytes as surrogates: safe_member_path escapes them after its separator check
            if name in (".", "..", "") or ino < 1:
                continue
            path = f"{current}/{name}"
            if len(files) + len(paths) > self.limits.max_files:
                return  # the caller records the limit
            if stat.S_ISDIR(mode):
                if ino not in paths:
                    paths[ino] = path
                    nxt.append(ino)
            elif stat.S_ISREG(mode):
                files.append((path, mode, uid, gid, size, ino))
            elif stat.S_ISLNK(mode):
                self._record_link(art, path, "symlink", None)
            else:
                kind = "device" if (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)) else "fifo"
                self._record_link(art, path, kind, None)

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
                    end = self.fp.tell() - len(self.d.unused_data) - len(self.pending)
                    if end < os.fstat(self.fp.fileno()).st_size:
                        self.trailing_offset = end
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

    def end_offset(self) -> int:
        """File offset just after the stream (valid once read() returned b"")."""
        return self.fp.tell() - len(self.d.unused_data)


class _Bz2StreamReader(_XzStreamReader):
    """Exactly one bzip2 stream starting at the current position (same decompressor API as lzma)."""

    def __init__(self, fp: BinaryIO) -> None:  # noqa: D107 - see the class docstring
        self.fp = fp
        self.d = bz2.BZ2Decompressor()  # type: ignore[assignment]


class _ConcatenatedStreams:
    """Consecutive gzip members or xz streams in a file (both formats allow several), decoded one by one.

    gzip.open and lzma failed on anything after the last stream that is not another one, such as the 0xFF
    padding of an erased flash block, and the whole content went unanalysed. Here zero padding is skipped
    and other data ends the output; ``trailing_offset`` says where it starts so the caller can look at it.
    Damage inside the first stream, or inside a later one after it produced output, still raises."""

    def __init__(self, path: Path, magic: bytes, member: Callable[[BinaryIO], _GzipMemberReader | _XzStreamReader]):
        self.fp = path.open("rb")
        self.magic, self.member = magic, member
        self.cur: _GzipMemberReader | _XzStreamReader | None = member(self.fp)
        self.start, self.first, self.started = 0, True, False
        self.trailing_offset: int | None = None

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, *exc) -> None:
        self.fp.close()

    def read(self, size: int = -1) -> bytes:
        while self.cur is not None:
            try:
                out = self.cur.read(size)
            except (zlib.error, lzma.LZMAError, EOFError, OSError):  # bz2 raises OSError("Invalid data stream")
                if self.first or self.started:
                    raise
                self.trailing_offset, self.cur = self.start, None  # began like a stream, but is not one
                break
            if out:
                self.started = True
                return out
            pos = end = self.cur.end_offset()
            self.fp.seek(pos)
            while (chunk := self.fp.read(64 * 1024)) and not chunk.strip(b"\x00"):
                pos += len(chunk)  # zero padding (xz stream padding, dd'ed images)
            pos += len(chunk) - len(chunk.lstrip(b"\x00"))
            self.fp.seek(pos)
            if not chunk:
                self.cur = None
            elif self.fp.read(len(self.magic)) == self.magic:
                self.fp.seek(pos)
                self.start, self.first, self.started = pos, False, False
                self.cur = self.member(self.fp)
            else:  # from the stream's end: the zeros may belong to what follows (an ext image's boot block)
                self.trailing_offset, self.cur = end, None
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

    def end_offset(self) -> int:
        """File offset just after the member (valid once read() returned b"")."""
        return self.fp.tell() - len(self.d.unused_data) - len(self.tail)


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


def demangle(names: list[str], timeout: int = 60) -> dict[str, str]:
    """Readable names for C++ (Itanium ABI) symbols via binutils' c++filt, without parameter lists
    ('_ZN12MissionBlock30get_absolute_altitude_for_itemERK14mission_item_s' ->
    'MissionBlock::get_absolute_altitude_for_item'). The names come from the untrusted ELF, so this runs on the
    sandbox side, CPU/memory-limited. Empty if c++filt is unavailable or fails."""
    exe = shutil.which("c++filt")
    todo = sorted({n for n in names if n.startswith("_Z") and n.isascii() and n.isprintable() and " " not in n})
    if not exe or not todo:
        return {}

    def preexec() -> None:  # pragma: no cover - runs in child
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 5))
        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))

    try:
        p = subprocess.run([exe, "--no-params"], input=("\n".join(todo) + "\n").encode(), capture_output=True,
                           timeout=timeout, preexec_fn=preexec, env={"PATH": os.environ.get("PATH", "")})
    except (OSError, subprocess.SubprocessError):
        return {}
    out = p.stdout.decode("utf-8", "replace").split("\n")
    if p.returncode != 0 or len(out) < len(todo):
        return {}
    return {m: d[:300] for m, d in zip(todo, out[:len(todo)], strict=True) if d and d != m}


DECLARED_SIZE_FORMATS = {"ext", "fat", "romfs", "cromfs", "cramfs"}


def _declared_image_size(fmt: str, head: bytes) -> int | None:
    """Size a filesystem image declares for itself (anything after it is not part of the image)."""
    try:
        if fmt == "ext":
            blocks, log = struct.unpack_from("<I", head, 1028)[0], struct.unpack_from("<I", head, 1048)[0]
            if struct.unpack_from("<I", head, 1024 + 0x60)[0] & 0x80:  # 64bit feature: high half of the count
                blocks |= struct.unpack_from("<I", head, 1024 + 0x150)[0] << 32
            return blocks * (1024 << log) if log <= 6 else None
        if fmt == "fat":
            bps, ts16 = struct.unpack_from("<HH", head, 11)[0], struct.unpack_from("<H", head, 19)[0]
            return bps * (ts16 or struct.unpack_from("<I", head, 32)[0]) if bps in (512, 1024, 2048, 4096) else None
        if fmt == "romfs":
            return romfs_size(head)
        if fmt == "cromfs":
            hdr = cromfs_header(head[:20], 1 << 40)
            return hdr["fsize"] if hdr else None
        if fmt == "cramfs":
            off = more.cramfs_offset(head)
            return struct.unpack_from("<I", head, off + 4)[0] if off is not None else None  # includes the pad
    except struct.error:
        return None
    return None


MODULE_SIG_MARKER = b"~Module signature appended~\n"
SHT_NOBITS = 8


def _elf_data_end(fp: BinaryIO, size: int) -> int | None:
    """Offset just past an ELF file's own data: header, program and section header tables, segments and
    sections (without .bss-like ones). None if the header is not usable. Reads only the tables."""
    fp.seek(0)
    hdr = fp.read(64)
    if len(hdr) < 52 or hdr[:4] != b"\x7fELF" or hdr[4] not in (1, 2) or hdr[5] not in (1, 2):
        return None
    e = "<" if hdr[5] == 1 else ">"
    if hdr[4] == 1:
        phoff, shoff = struct.unpack_from(e + "II", hdr, 28)
        ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHHH", hdr, 40)
        ph = (e + "I", 4, e + "I", 16)  # (offset fmt, at, filesz fmt, at)
        sh = (e + "I", 4, e + "I", 16, e + "I", 20)  # (type, at, offset, at, size, at)
    else:
        if len(hdr) < 64:
            return None
        phoff, shoff = struct.unpack_from(e + "QQ", hdr, 32)
        ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHHH", hdr, 52)
        ph = (e + "Q", 8, e + "Q", 32)
        sh = (e + "I", 4, e + "Q", 24, e + "Q", 32)
    ends = [ehsize]
    if shoff and shnum == 0 and shentsize >= 40 and shoff + shentsize <= size:  # more sections than fit e_shnum
        fp.seek(shoff)
        shnum = min(struct.unpack_from(sh[4], fp.read(shentsize), sh[5])[0], 1_000_000)
    for off, count, entsize, kind in ((phoff, phnum, phentsize, "ph"), (shoff, shnum, shentsize, "sh")):
        if not off or not count or entsize < 32 or off + count * entsize > size:
            continue
        ends.append(off + count * entsize)
        fp.seek(off)
        table = fp.read(count * entsize)
        for i in range(0, len(table) - entsize + 1, entsize):
            entry = table[i:i + entsize]
            if kind == "ph":
                start, length = struct.unpack_from(ph[0], entry, ph[1])[0], struct.unpack_from(ph[2], entry, ph[3])[0]
            else:
                if struct.unpack_from(sh[0], entry, sh[1])[0] == SHT_NOBITS:
                    continue
                start, length = struct.unpack_from(sh[2], entry, sh[3])[0], struct.unpack_from(sh[4], entry, sh[5])[0]
            if start + length <= size:
                ends.append(start + length)
    return max(ends)


def _is_mcu_elf(path: Path) -> bool:
    """Statically linked ARM executable built for a Cortex-M profile (EABI attribute 'M' / cortex-m*)."""
    try:
        from elftools.elf.elffile import ELFFile
        with path.open("rb") as fp:
            elf = ELFFile(fp)
            if elf["e_machine"] != "EM_ARM" or elf["e_type"] != "ET_EXEC":
                return False
            if any(s["p_type"] in ("PT_INTERP", "PT_DYNAMIC") for s in elf.iter_segments()):
                return False
            attrs = elf.get_section_by_name(".ARM.attributes")
            data = attrs.data()[:4096] if attrs is not None else b""
            return b"\x07M" in data or b"cortex-m" in data.lower()
    except Exception:  # noqa: BLE001 - malformed ELF: not ours to convert
        return False


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


# 'unsquashfs -lln' lines: mode, uid/gid, size (or "major, minor"), date, time, path ("squashfs-root/...")
_LS_LINE = re.compile(rb"^([-dlcbps][-rwxsStT]{9}) +(\d+)/(\d+) +(?:\d+|\d+, *\d+) +\d{4}-\d\d-\d\d \d\d:\d\d (.+)$")
_LS_TYPES = {"-": stat.S_IFREG, "d": stat.S_IFDIR, "l": stat.S_IFLNK, "c": stat.S_IFCHR, "b": stat.S_IFBLK,
             "p": stat.S_IFIFO, "s": stat.S_IFSOCK}


def _ls_mode(text: str) -> int | None:
    """'-rwsr-xr-x' -> 0o104755 ('s'/'S' setuid/setgid with/without x, 't'/'T' sticky)."""
    if len(text) != 10 or text[0] not in _LS_TYPES:
        return None
    mode = _LS_TYPES[text[0]]
    for i, c in enumerate(text[1:]):
        bit = 0o400 >> i
        special = {2: 0o4000, 5: 0o2000, 8: 0o1000}.get(i)
        if c == "rwx"[i % 3]:
            mode |= bit
        elif special and c in ("sS" if i < 8 else "tT"):
            mode |= special | (bit if c.islower() else 0)
        elif c != "-":
            return None
    return mode


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


def _not_unpacked(self: Extractor, art: Artifact) -> list[Artifact]:
    """Archive formats that are recognised but not unpacked: say so (an info finding names the gap) rather than
    treating them as raw data. Their unpackers create links while extracting, which would need the same
    by-name care as debugfs; until then the content is reported as not analysed."""
    raise UnsupportedFormat(f"{art.format_description.split(' (')[0]} detected; this format is not unpacked, so "
                            "its contents were not analysed")


HANDLERS: dict[str, Callable[[Extractor, Artifact], list[Artifact]]] = {
    "7z": _not_unpacked,
    "rar": _not_unpacked,
    "cab": _not_unpacked,
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
    "elf": Extractor.h_mcu_elf,
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
