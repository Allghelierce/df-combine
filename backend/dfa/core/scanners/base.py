"""Shared context passed to all built-in content scanners."""
from __future__ import annotations

import bisect
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..extract import Artifact
from ..identify import iter_strings
from ..limits import Limits

# Formats whose content is covered by their extracted children once unpacked.
UNPACKED_CONTAINERS = {"zip", "tar", "gzip", "bzip2", "xz", "lzma", "zstd", "lz4", "lz4_legacy", "lzop", "cramfs",
                       "erofs", "android_sparse", "parrot_plf", "dji_imah", "esp_image", "esp_flash",
                       "squashfs", "ext", "fat", "cpio",
                       "romfs", "cromfs", "disk_image", "ubi", "ubifs", "jffs2", "dfu", "uimage", "px4", "apj", "fw_json", "ihex"}

TEXT_SUFFIXES = (".conf", ".cfg", ".ini", ".txt", ".sh", ".param", ".params", ".parm", ".json",
                 ".yaml", ".yml", ".xml", ".py", ".lua", ".service", ".rules", ".env", ".properties")


@dataclass
class ScanContext:
    artifacts: list[Artifact]
    paths: dict[int, Path]
    display: dict[int, str]
    limits: Limits
    elf: dict[int, dict] = field(default_factory=dict)  # artifact id -> ElfInfo dict
    category: dict[int, str] = field(default_factory=dict)
    copied: dict[int, list[tuple[int, int]]] = field(default_factory=dict)  # byte ranges carved verbatim into children
    _strings: dict[int, list[tuple[int, str]]] = field(default_factory=dict)
    _text: dict[int, str | None] = field(default_factory=dict)
    _merged: dict[int, tuple[list[int], list[int]]] = field(default_factory=dict)

    def content_artifacts(self) -> Iterator[Artifact]:
        """Artifacts whose bytes should be scanned (skip fully unpacked containers)."""
        for a in self.artifacts:
            if a.format in UNPACKED_CONTAINERS and a.extraction == "ok":
                continue
            if a.format == "empty":
                continue
            yield a

    def text(self, art: Artifact, max_bytes: int = 2 * 1024**2) -> str | None:
        if art.id in self._text:
            return self._text[art.id]
        val = None
        if art.format == "text" or (art.size <= max_bytes and art.name.lower().endswith(TEXT_SUFFIXES)):
            try:
                raw = self.paths[art.id].read_bytes()[:max_bytes]
                if b"\x00" not in raw[:4096]:
                    val = raw.decode("utf-8", "replace")
            except OSError:
                val = None
        self._text[art.id] = val
        return val

    def strings(self, art: Artifact) -> list[tuple[int, str]]:
        if art.id not in self._strings:
            out: list[tuple[int, str]] = []
            for item in iter_strings(self.paths[art.id], min_len=6,
                                     max_bytes=self.limits.max_scan_bytes_per_file):
                out.append(item)
                if len(out) >= 400_000:
                    break
            self._strings[art.id] = out
        return self._strings[art.id]

    def outside_children(self, art: Artifact, offset: int) -> bool:
        """Whether a byte of ``art`` lies outside the regions carved verbatim into child artifacts (whose own
        analysis covers them)."""
        if art.id not in self._merged:
            merged: list[list[int]] = []
            for start, end in sorted(self.copied.get(art.id, ())):  # regions may nest (inside a 7z's claim)
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            self._merged[art.id] = ([m[0] for m in merged], [m[1] for m in merged])
        starts, ends = self._merged[art.id]
        i = bisect.bisect_right(starts, offset) - 1
        return i < 0 or offset >= ends[i]

    def fs_path(self, art: Artifact) -> str:
        """Path of the artifact inside its filesystem/archive ('/etc/shadow')."""
        return art.name if art.name.startswith("/") else "/" + art.name

    def where(self, art: Artifact) -> str:
        return self.display.get(art.id, art.name)


def build_display_paths(artifacts: list[Artifact]) -> dict[int, str]:
    by_id = {a.id: a for a in artifacts}
    cache: dict[int, str] = {}

    def disp(aid: int) -> str:
        if aid in cache:
            return cache[aid]
        a = by_id[aid]
        if a.parent_id is None:
            cache[aid] = a.name
        else:
            cache[aid] = f"{disp(a.parent_id)} > {a.name}"
        return cache[aid]

    for a in artifacts:
        disp(a.id)
    return cache
