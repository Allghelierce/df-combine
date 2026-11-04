"""Resource limits applied while unpacking untrusted firmware.

Every extraction routine receives an :class:`ExtractionBudget` and must charge
each byte it writes and each file it creates against it.  The budget is the
primary defence against decompression bombs, archive floods and deeply
nested archives.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class LimitExceeded(Exception):
    """Raised when an extraction exceeds one of the configured limits."""


@dataclass
class Limits:
    max_total_bytes: int = 2 * 1024**3  # total bytes written during extraction
    max_file_bytes: int = 512 * 1024**2  # largest single extracted file
    max_files: int = 20_000  # files created across all nested archives
    max_depth: int = 5  # nesting depth of archives within archives
    max_ratio: float = 250.0  # decompressed/compressed ratio per member
    ratio_min_bytes: int = 10 * 1024**2  # ratio check applies above this size
    max_carves_per_file: int = 32  # embedded blobs carved from one raw image
    tool_timeout_s: int = 300  # timeout for external unpackers (unsquashfs...)
    max_scan_bytes_per_file: int = 64 * 1024**2  # bytes read by content scanners per file

    @classmethod
    def from_dict(cls, data: dict | None) -> "Limits":
        lim = cls()
        for key, value in (data or {}).items():
            if hasattr(lim, key):
                setattr(lim, key, type(getattr(lim, key))(value))
        return lim


@dataclass
class ExtractionBudget:
    limits: Limits
    bytes_written: int = 0
    files_created: int = 0
    warnings: list[str] = field(default_factory=list)

    def charge_bytes(self, n: int, *, file_total: int | None = None) -> None:
        self.bytes_written += n
        if self.bytes_written > self.limits.max_total_bytes:
            raise LimitExceeded(
                f"total extracted size exceeds limit ({self.limits.max_total_bytes} bytes)"
            )
        if file_total is not None and file_total > self.limits.max_file_bytes:
            raise LimitExceeded(
                f"single extracted file exceeds limit ({self.limits.max_file_bytes} bytes)"
            )

    def charge_file(self) -> None:
        self.files_created += 1
        if self.files_created > self.limits.max_files:
            raise LimitExceeded(f"extracted file count exceeds limit ({self.limits.max_files})")

    def check_ratio(self, compressed: int, decompressed: int, name: str) -> None:
        if decompressed < self.limits.ratio_min_bytes:
            return
        ratio = decompressed / max(compressed, 1)
        if ratio > self.limits.max_ratio:
            raise LimitExceeded(
                f"compression ratio {ratio:.0f}:1 for '{name}' exceeds limit "
                f"({self.limits.max_ratio:.0f}:1) - possible decompression bomb"
            )

    @property
    def remaining_bytes(self) -> int:
        return max(self.limits.max_total_bytes - self.bytes_written, 0)
