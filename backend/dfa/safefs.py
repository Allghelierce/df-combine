"""Worker/API access to scan directories without trusting their contents.

Everything below a scan directory may have been written by the analysis sandbox or a tool container
while it processed untrusted firmware. If one of them were compromised it could leave a symlink named
``findings.json`` pointing at the database, ``manifest.json`` pointing at another user's scan, or a
FIFO that blocks the worker forever. So:

* paths are walked component by component through directory fds with ``O_NOFOLLOW`` - no symlink is
  followed, not even an intermediate one;
* only regular files are read (a FIFO is rejected instead of blocking; a link to ``/dev/zero`` cannot
  exhaust memory), and reads are size limited;
* files are written to a fresh temporary name (``O_EXCL``) and renamed over the target, which replaces
  whatever entry was there - a planted link is replaced, never written through.

The scan directory itself (``base``) is trusted: it is created by the worker or the sandbox broker
inside a work root the containers cannot modify, and it is the containers' bind-mount point, which
they cannot rename or replace.
"""
from __future__ import annotations

import errno
import os
import secrets
import stat
from pathlib import Path

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class UnsafeEntry(OSError):
    """A path component is a link or special file, or the file is larger than allowed."""


def _parts(rel: str | os.PathLike) -> list[str]:
    s = os.fspath(rel)
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if not parts or s.startswith("/") or ".." in parts:
        raise UnsafeEntry(errno.EINVAL, f"unsafe relative path {s!r}")
    return parts


def _open_dirs(base: Path, parts: list[str], create: bool) -> int:
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in parts:
            try:
                nfd = os.open(name, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(name, 0o755, dir_fd=fd)
                nfd = os.open(name, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise UnsafeEntry(exc.errno, f"{name!r} is a link or not a directory") from None
                raise
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_bytes(base: Path, rel: str | os.PathLike, limit: int) -> bytes:
    """Contents of the regular file ``base/rel``; FileNotFoundError if it does not exist."""
    parts = _parts(rel)
    dfd = _open_dirs(base, parts[:-1], create=False)
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeEntry(exc.errno, f"{os.fspath(rel)!r} is a symbolic link") from None
        raise
    finally:
        os.close(dfd)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise UnsafeEntry(errno.EINVAL, f"{os.fspath(rel)!r} is not a regular file")
        if st.st_size > limit:
            raise UnsafeEntry(errno.EFBIG, f"{os.fspath(rel)!r} is larger than {limit} bytes")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise UnsafeEntry(errno.EFBIG, f"{os.fspath(rel)!r} is larger than {limit} bytes")
    return data


def read_text(base: Path, rel: str | os.PathLike, limit: int) -> str:
    return read_bytes(base, rel, limit).decode("utf-8", errors="replace")


def ensure_dir(base: Path, rel: str | os.PathLike) -> Path:
    """Create ``base/rel`` (and parents) as real directories; UnsafeEntry if a component is a link."""
    parts = _parts(rel)
    os.close(_open_dirs(base, parts, create=True))
    return base.joinpath(*parts)


def write_bytes(base: Path, rel: str | os.PathLike, data: bytes) -> Path:
    """Atomically replace ``base/rel`` with a new regular file (mode 0644)."""
    parts = _parts(rel)
    dfd = _open_dirs(base, parts[:-1], create=True)
    try:
        tmp = f".{parts[-1][:100]}.{secrets.token_hex(6)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dfd)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, parts[-1], src_dir_fd=dfd, dst_dir_fd=dfd)  # replaces a link, never follows it
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
    finally:
        os.close(dfd)
    return base.joinpath(*parts)


def write_text(base: Path, rel: str | os.PathLike, text: str) -> Path:
    return write_bytes(base, rel, text.encode("utf-8", errors="replace"))
