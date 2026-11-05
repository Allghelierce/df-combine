"""Sandbox entry point: identify, extract, inventory and scan one firmware file.

Usage (inside the isolated container or a resource-limited subprocess)::

    python -m dfa.core.analyze --input /in/firmware --name orig.bin --work /work [--limits '{...}']

Writes ``<work>/manifest.json``.  This module only *reads* the firmware and
never executes any of its content.  It has no network or database access and
depends only on the standard library and pyelftools.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import traceback
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from .extract import Artifact, Extractor
from .findings import Finding, dedupe
from .formats.elfinfo import inspect_elf
from .identify import PlatformAccumulator, file_entropy, parse_ardupilot_descriptor, scan_file_for_platform
from .limits import Limits
from .scanners import binaries, components, configs, drone, packages, secrets
from .scanners.base import ScanContext, build_display_paths

MANIFEST_VERSION = 1
PLATFORM_SCAN_BUDGET = 512 * 1024**2

# Known PX4/ArduPilot board ids (from the .px4/.apj "board_id" field). Only
# well-established values are listed; unknown ids are reported raw.
BOARD_IDS = {9: "PX4 FMUv2/FMUv3 (Pixhawk 1 class)", 11: "PX4 FMUv4 (Pixracer class)",
             50: "PX4 FMUv5 (Pixhawk 4 class)"}

SCANNERS: list[tuple[str, Callable[[ScanContext], list[Finding]]]] = [
    ("builtin:secrets", secrets.scan),
    ("builtin:config", configs.scan),
    ("builtin:drone", drone.scan),
    ("builtin:binary", binaries.scan),
]


def categorize(art: Artifact, elf: dict | None, ctx: ScanContext) -> str:
    if art.format == "elf" and elf:
        if elf.get("is_kernel_module"):
            return "kernel_module"
        if elf.get("os_hint") == "bare-metal":
            return "firmware_image"
        if elf.get("interpreter"):
            return "executable"
        if elf.get("elf_type") == "ET_DYN" or ".so" in art.name:
            return "shared_library"
        return "executable"
    if art.format in ("cortexm_raw",):
        return "firmware_image"
    if art.format in ("squashfs", "ext", "fat", "romfs", "cromfs", "cramfs", "erofs", "android_sparse", "disk_image",
                      "ubi", "ubifs", "jffs2"):
        return "filesystem_image"
    if art.format in ("zip", "tar", "gzip", "bzip2", "xz", "lzma", "zstd", "lz4", "lz4_legacy", "lzop", "cpio"):
        return "archive"
    if art.format in ("px4", "apj", "fw_json", "ihex", "dfu", "uimage", "parrot_plf", "dji_imah", "esp_image", "esp_flash"):
        return "firmware_container"
    if art.format == "text":
        text = ctx.text(art) or ""
        name = ctx.fs_path(art)
        if "PRIVATE KEY-----" in text:
            return "key_material"
        if "BEGIN CERTIFICATE" in text:
            return "certificate"
        if text.startswith("#!") or name.endswith((".sh", ".py", ".lua")):
            return "script"
        if "/etc/" in name or name.endswith((".conf", ".cfg", ".ini", ".parm", ".param", ".params", ".json",
                                              ".yaml", ".yml", ".service")):
            return "config"
        return "text"
    if art.format == "raw" and art.parent_id is None:
        return "firmware_image"
    return "data"


def find_rootfs(extractor: Extractor, work: Path) -> list[str]:
    """Directories that look like a Linux root filesystem."""
    roots = []
    for d in sorted(work.joinpath("files").rglob("etc")):
        if not d.is_dir():
            continue
        parent = d.parent
        if any((parent / x).is_dir() for x in ("bin", "sbin", "usr", "lib")):
            roots.append(str(parent.relative_to(work)))
        if len(roots) > 20:
            break
    return roots


def run(input_path: Path, original_name: str, work: Path, limits: Limits,
        progress: Callable[[str], None] | None = None) -> dict:
    progress = progress or (lambda m: None)
    t0 = time.monotonic()
    manifest: dict = {"manifest_version": MANIFEST_VERSION, "scanner_runs": []}

    progress("identify+extract")
    ex = Extractor(work, limits, progress=progress)
    result = ex.run(input_path, original_name)
    arts = result.artifacts
    display = build_display_paths(arts)
    ctx = ScanContext(artifacts=arts, paths={a.id: ex.path_of(a.id) for a in arts}, display=display, limits=limits,
                      copied=result.copied)

    progress("inventory")
    for a in arts:
        if a.format == "elf":
            try:
                with ex.path_of(a.id).open("rb") as fp:
                    ctx.elf[a.id] = inspect_elf(fp).to_dict()
            except Exception as exc:  # noqa: BLE001 - malformed ELF is data, not a crash
                a.details["elf_error"] = str(exc)[:200]
        ctx.category[a.id] = categorize(a, ctx.elf.get(a.id), ctx)

    from .formats.arch import guess_architecture
    for a in arts:  # instruction set of headerless code blobs
        if a.format == "raw" and a.size >= 4096 and a.extraction in (None, "ok"):
            with ex.path_of(a.id).open("rb") as fp:
                g = guess_architecture(fp.read(8 * 1024**2))
            if g:
                a.details["arch_guess"] = g.to_dict()
    for a in arts:  # load address of raw MCU images (needed for disassembly / bare-metal analysis)
        if a.format == "cortexm_raw":
            from .formats.cortexm import analyze_vector_table, estimate_flash_base
            with ex.path_of(a.id).open("rb") as fp:
                data = fp.read(16 * 1024**2)
            vt = analyze_vector_table(data)
            if vt:
                a.details["initial_sp"] = hex(vt.initial_sp)
                a.details["reset_handler"] = hex(vt.reset_handler)
            if "load_address" in a.details:
                a.details["flash_base"] = a.details["load_address"]
                a.details["flash_base_source"] = ("ELF load address" if a.details.get("derived_from_elf")
                                                  else "container metadata")
            else:
                est = estimate_flash_base(data)
                if est:
                    a.details["flash_base"] = hex(est[0])
                    a.details["flash_base_source"] = est[1]["method"]
                    a.details["flash_base_scores"] = est[1]["candidates"]
    _link_images_to_elf_symbols(arts, ctx)

    progress("platform detection")
    acc = PlatformAccumulator()
    budget = PLATFORM_SCAN_BUDGET
    for a in ctx.content_artifacts():
        if budget <= 0:
            break
        if a.format in ("text", "elf", "raw", "cortexm_raw") or ctx.category[a.id] in ("config", "script"):
            n = min(a.size, limits.max_scan_bytes_per_file, budget)
            scan_file_for_platform(ex.path_of(a.id), acc, n)
            budget -= n
            for _, s in (ctx.strings(a) if a.format != "text" else
                         enumerate((ctx.text(a) or "").splitlines()[:20000])):
                acc.feed_string(s)
    ap_desc = None
    for a in arts:
        if a.format == "cortexm_raw" and ap_desc is None:
            with ex.path_of(a.id).open("rb") as fp:
                ap_desc = parse_ardupilot_descriptor(fp.read(4 * 1024**2), a.size)
            if ap_desc and "board_id" in ap_desc:  # only a populated descriptor is evidence
                acc.hint("ArduPilot", f"populated ArduPilot app descriptor at {ap_desc['offset']}")
            elif ap_desc:
                ap_desc = None
    for a in arts:
        if a.format == "px4":
            acc.hint("PX4", "PX4 firmware container magic 'PX4FWv1'")
        elif a.format == "apj":
            acc.hint("ArduPilot", "ArduPilot firmware container magic 'APJFWv1'")
        elif a.format == "dji_imah":
            acc.hint("DJI", "DJI 'IM*H' module header")
        elif a.format == "parrot_plf":
            acc.hint("Parrot", "Parrot 'PLF!' container header")
        elif a.format == "esp_image" and a.details.get("checksum_valid"):
            app = a.details.get("esp_app")
            acc.hint("Espressif", f"{a.details.get('esp_chip')} application image with a valid checksum"
                     + (f" (ESP-IDF project '{app.get('project_name')}')" if app else ""))
    platforms = acc.results()

    progress("components")
    comps = components.fingerprint(ctx)
    # Platform versions become components as well.
    container_meta = next(iter(result.container_metadata.values()), {})
    for p in platforms[:2]:
        if p.version and p.confidence in ("high", "medium"):
            comps.append(components.Component(name=p.name.lower(), version=p.version, sources=["platform signature"],
                                              method="platform-signature", variant=p.vehicle))
    for a in arts:  # ESP-IDF application descriptors name the SDK version and the application itself
        app = a.details.get("esp_app") or {}
        if app.get("idf_version"):
            components.merge(comps, components.Component(
                name="esp-idf", version=app["idf_version"].removeprefix("v"), sources=[ctx.where(a)],
                method="esp_app_desc"))
        if app.get("project_name") and app.get("version"):
            components.merge(comps, components.Component(
                name=app["project_name"], version=app["version"], sources=[ctx.where(a)], method="esp_app_desc"))

    st = time.monotonic()
    try:
        pkg_inv = packages.inventory(ctx)
        manifest["scanner_runs"].append({"name": "builtin:packages", "status": "completed",
                                         "findings": 0, "duration_s": round(time.monotonic() - st, 3),
                                         "packages": len(pkg_inv["packages"])})
    except Exception as exc:  # noqa: BLE001
        pkg_inv = {"distro": None, "managers": [], "packages": []}
        manifest["scanner_runs"].append({"name": "builtin:packages", "status": "failed", "findings": 0,
                                         "error": f"{type(exc).__name__}: {exc}"})
    manifest["packages"] = pkg_inv

    findings: list[Finding] = []
    for name, fn in SCANNERS:
        st = time.monotonic()
        try:
            res = fn(ctx)
            findings += res
            manifest["scanner_runs"].append({"name": name, "status": "completed", "findings": len(res),
                                             "duration_s": round(time.monotonic() - st, 3)})
        except Exception as exc:  # noqa: BLE001 - one scanner must not kill the scan
            manifest["scanner_runs"].append({"name": name, "status": "failed", "findings": 0,
                                             "error": f"{type(exc).__name__}: {exc}",
                                             "trace": traceback.format_exc()[-2000:],
                                             "duration_s": round(time.monotonic() - st, 3)})
    st = time.monotonic()
    try:
        res = components.assess(comps)
        findings += res
        manifest["scanner_runs"].append({"name": "builtin:components", "status": "completed",
                                         "findings": len(res), "duration_s": round(time.monotonic() - st, 3)})
    except Exception as exc:  # noqa: BLE001
        manifest["scanner_runs"].append({"name": "builtin:components", "status": "failed", "findings": 0,
                                         "error": f"{type(exc).__name__}: {exc}"})
    findings += _identification_findings(ctx, arts, platforms)
    findings += _appended_data_findings(ctx, arts)
    findings += _archive_anomaly_findings(ctx, result)

    # ---- identification summary --------------------------------------------
    root = arts[0]
    arch, bits, endian, os_hint = _primary_arch(arts, ctx)
    primary = platforms[0] if platforms else None
    board_id = container_meta.get("board_id")
    if board_id is None and ap_desc and "board_id" in ap_desc:
        board_id = ap_desc["board_id"]
    ident = {
        "format": root.format,
        "format_description": root.format_description,
        "size": root.size,
        "sha256": root.sha256,
        "entropy": file_entropy(input_path),
        "architecture": arch,
        "bits": bits,
        "endianness": endian,
        "os_hint": os_hint,
        "platform": primary.name if primary else "Unknown",
        "platform_family": primary.family if primary else None,
        "platform_confidence": primary.confidence if primary else None,
        "platform_version": _plain_version((primary.version if primary else None) or container_meta.get("git_identity")),
        "vehicle_type": primary.vehicle if primary else None,
        "platform_candidates": [p.to_dict() for p in platforms],
        "board_id": board_id,
        "board_hint": BOARD_IDS.get(board_id) if isinstance(board_id, int) else None,
        "board_name": (primary.board if primary else None) or _container_board(container_meta),
        "build": (primary.build if primary else None) or _container_build(container_meta),
        "container_metadata": container_meta,
        "ardupilot_descriptor": ap_desc,
        "details": root.details,
    }
    cats = Counter(ctx.category.values())
    manifest.update({
        "input": {"name": original_name, "size": root.size, "sha256": root.sha256},
        "identification": ident,
        "extraction": {
            "artifacts": [_art_dict(a, ctx) for a in arts],
            "links": [vars(link) for link in result.links[:5000]],
            "link_count": len(result.links),
            "warnings": result.warnings[:500],
            "filesystems": result.filesystems,
            "limits_hit": sorted(set(result.limits_hit)),
            "stats": result.stats,
            "rootfs": find_rootfs(ex, work),
        },
        "inventory": {"categories": dict(cats)},
        "components": [c.to_dict() for c in comps],
        "findings": [f.to_dict() for f in dedupe(findings)],
        "duration_s": round(time.monotonic() - t0, 3),
    })
    return manifest


def _container_board(meta: dict) -> str | None:
    """Board named by a .px4/.apj container ('summary', e.g. 'CubeOrange', 'PX4FMUv6C')."""
    s = meta.get("summary")
    return s[:64] if isinstance(s, str) and s.strip() and s.isprintable() else None


def _container_build(meta: dict) -> dict | None:
    """Build facts recorded by a .px4/.apj container: git commit and build time (UTC)."""
    out: dict[str, str] = {}
    h = meta.get("git_hash")
    if isinstance(h, str) and re.fullmatch(r"[0-9a-f]{7,40}", h):
        out["revision"] = h[:12]
    t = meta.get("build_time")
    if isinstance(t, int) and 946684800 <= t < 4102444800:  # 2000..2100
        from datetime import UTC, datetime
        dt = datetime.fromtimestamp(t, UTC)
        out["date"], out["time"] = dt.strftime("%b %d %Y"), dt.strftime("%H:%M:%S UTC")
    return out or None


def _link_images_to_elf_symbols(arts: list[Artifact], ctx: ScanContext) -> None:
    """A stripped image (e.g. from a .px4) that is byte-identical to the flash image derived from an ELF in the
    same upload - same SHA-256 and same load address, as for a PX4 build's .px4 and .elf - is the same program,
    so the ELF's function symbols apply to it."""
    derived = {(a.sha256, a.details.get("flash_base")): a for a in arts
               if a.format == "cortexm_raw" and a.details.get("derived_from_elf") and a.details.get("symbol_map")}
    if not derived:
        return
    for a in arts:
        src = derived.get((a.sha256, a.details.get("flash_base")))
        if a.format != "cortexm_raw" or src is None or src.id == a.id or a.details.get("symbol_map"):
            continue
        a.details.update({"symbol_map": src.details["symbol_map"], "symbol_count": src.details.get("symbol_count"),
                          "symbols_from": ctx.display.get(src.parent_id, ""), "identical_to": src.id})


def _art_dict(a: Artifact, ctx: ScanContext) -> dict:
    d = a.to_dict()
    d["category"] = ctx.category.get(a.id)
    d["display_path"] = ctx.display.get(a.id)
    if a.id in ctx.elf:
        e = dict(ctx.elf[a.id])
        e.pop("imports", None)
        d["elf"] = e
    return d


def _plain_version(v: str | None) -> str | None:
    """'v1.17.0' (git tag style, e.g. PX4's git_identity) -> '1.17.0'."""
    return v[1:] if v and len(v) > 1 and v[0] in "vV" and v[1].isdigit() else v


def _primary_arch(arts: list[Artifact], ctx: ScanContext) -> tuple[str | None, int | None, str | None, str | None]:
    root_elf = ctx.elf.get(arts[0].id)
    if root_elf:
        return root_elf["arch"], root_elf["bits"], root_elf["endianness"], root_elf["os_hint"]
    for a in arts:
        if a.format == "cortexm_raw":
            return "ARM Cortex-M (Thumb-2)", 32, "little", "bare-metal"
    archs = Counter((e["arch"], e["bits"], e["endianness"]) for e in ctx.elf.values() if e.get("os_hint") == "linux")
    if archs:
        (arch, bits, end), _ = archs.most_common(1)[0]
        return arch, bits, end, "linux"
    for a in arts:
        if a.format == "uimage" and a.details.get("arch"):
            return a.details["arch"], None, None, "linux"
    any_elf = Counter((e["arch"], e["bits"], e["endianness"], e["os_hint"]) for e in ctx.elf.values())
    if any_elf:
        return any_elf.most_common(1)[0][0]
    for a in arts:
        if a.details.get("esp_architecture"):
            return f"{a.details['esp_architecture']} ({a.details['esp_chip']})", 32, "little", "bare-metal"
    guesses = sorted((a for a in arts if a.details.get("arch_guess")), key=lambda a: -a.size)
    if guesses:
        g = guesses[0].details["arch_guess"]
        return f"{g['architecture']} (opcode heuristic)", g["bits"], g["endianness"], None
    return None, None, None, None


def _identification_findings(ctx: ScanContext, arts: list[Artifact], platforms) -> list[Finding]:
    from .findings import Classification as C
    from .findings import Confidence as K
    from .findings import Evidence
    from .findings import Severity as S
    out = []
    root = arts[0]
    if root.format in ("raw",) and len(arts) == 1:
        ent = file_entropy(ctx.paths[root.id])
        if ent > 7.6:
            out.append(Finding(
                title="Firmware appears encrypted or compressed with an unknown scheme",
                description=f"Entropy is {ent:.2f} bits/byte and no known format or embedded object was found. "
                            "Static analysis coverage is very limited for this file.",
                severity=S.info, classification=C.info, confidence=K.medium, source_tool="builtin:identify",
                rule_id="high-entropy-unknown", affected_component=root.name,
                remediation="Obtain the decrypted/unpacked image (e.g. from the vendor or a device dump) for analysis.",
                evidence=[Evidence("string", f"entropy={ent:.3f}")]))
    for a in arts:
        if a.extraction in ("failed", "unsupported", "partial", "skipped"):
            out.append(Finding(
                title=f"Content not fully analysed: {a.format_description}",
                description=f"Extraction of '{a.name}' was {a.extraction}: {a.extraction_note}. Findings for "
                            "its contents may be missing.",
                severity=S.info, classification=C.info, confidence=K.high, source_tool="builtin:extract",
                rule_id=f"extraction-{a.extraction}", affected_component=ctx.where(a),
                remediation="Review the artifact manually or install the missing unpacker.",
                evidence=[Evidence("string", a.extraction_note or "")]))
    return out


def _appended_data_findings(ctx: ScanContext, arts: list[Artifact]) -> list[Finding]:
    """Data found after an executable's or an image's own data (analysed as an artifact of its own) is worth a
    look in itself: appended to an executable it is a pattern of packed and self-extracting programs and of
    droppers (suspicious); after an image or archive it may be a normal layout, such as an overlay (info)."""
    from .findings import Classification as C
    from .findings import Confidence as K
    from .findings import Evidence
    from .findings import Severity as S
    by_id = {a.id: a for a in arts}
    out = []
    for a in arts:
        parent = by_id.get(a.parent_id) if a.parent_id is not None else None
        if parent is None or a.origin != "carved" or not a.name.startswith("trailing_"):
            continue
        ev = Evidence("offset", f"{a.details.get('carved_offset', '?')}: {a.size:,} bytes ({a.format_description})",
                      ctx.where(a))
        if parent.format == "elf":
            out.append(Finding(
                title="Executable carries appended data (overlay)",
                description=f"'{parent.name}' has {a.size:,} bytes after its own segments and sections. Self-extracting "
                            "and packed programs keep their payload there, and so can a dropper; the appended data was "
                            "analysed separately. This is a pattern, not a confirmed problem.",
                severity=S.low, classification=C.suspicious, confidence=K.medium, source_tool="builtin:extract",
                rule_id="appended-to-executable", affected_component=ctx.where(parent),
                remediation="Check what the appended data is and whether the vendor ships the program packed.",
                evidence=[ev], tags=["extraction"]))
        else:
            out.append(Finding(
                title=f"Data after the end of a {parent.format_description}",
                description=f"{a.size:,} bytes follow the end of '{parent.name}' and were analysed separately (an "
                            "overlay or another image may sit there, or something added later).",
                severity=S.info, classification=C.info, confidence=K.high, source_tool="builtin:extract",
                rule_id="data-after-image", affected_component=ctx.where(parent),
                remediation="Check that the data after the image belongs to the firmware layout.",
                evidence=[ev], tags=["extraction"]))
    return out


def _archive_anomaly_findings(ctx: ScanContext, result) -> list[Finding]:
    """Archive constructs that only make sense as an attack (zip-slip style) - flagged, never followed."""
    import posixpath

    from .findings import Classification as C
    from .findings import Confidence as K
    from .findings import Evidence
    from .findings import Severity as S
    out: list[Finding] = []
    traversal = [w for w in result.warnings if "path traversal" in w or "absolute (drive) path" in w]
    escaping = []
    for link in result.links:
        if link.kind == "symlink" and link.target and not link.target.startswith("/"):
            base = posixpath.dirname(link.path.lstrip("/"))
            if posixpath.normpath(posixpath.join(base, link.target)).startswith(".."):
                escaping.append(link)
    if traversal:
        out.append(Finding(
            title=f"Archive contains path-traversal entries ({len(traversal)})",
            description="One or more archive members use '..' or drive-letter paths that would be written outside "
                        "the extraction directory by a naive unpacker (zip-slip). They were rejected. In a firmware "
                        "update package this indicates tampering or an attempt to exploit the device's updater.",
            severity=S.high, classification=C.detected, confidence=K.high, source_tool="builtin:extract",
            rule_id="archive-path-traversal", affected_component=ctx.where(ctx.artifacts[0]),
            remediation="Do not install this package. Ensure the on-device updater validates member paths.",
            evidence=[Evidence("path", w[:200]) for w in traversal[:20]], cwe="CWE-22",
            references=["https://cwe.mitre.org/data/definitions/22.html"], tags=["archive", "tampering"]))
    if escaping:
        out.append(Finding(
            title=f"Symlinks pointing outside their archive ({len(escaping)})",
            description="Relative symlinks resolve outside the archive root. Combined with later members written "
                        "through the link, this is a classic arbitrary-file-write technique against updaters. "
                        "The links were recorded but not created.",
            severity=S.medium, classification=C.suspicious, confidence=K.medium, source_tool="builtin:extract",
            rule_id="archive-escaping-symlink", affected_component=ctx.where(ctx.artifacts[0]),
            remediation="Inspect the package origin; reject archives containing escaping links.",
            evidence=[Evidence("path", f"{link.path} -> {link.target}") for link in escaping[:20]], cwe="CWE-59",
            tags=["archive", "tampering"]))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--name", required=True)
    ap.add_argument("--work", required=True, type=Path)
    ap.add_argument("--limits", default="{}")
    args = ap.parse_args(argv)
    args.work.mkdir(parents=True, exist_ok=True)
    progress_file = args.work / "progress.log"

    def progress(msg: str) -> None:
        with progress_file.open("a") as fp:
            fp.write(f"{time.time():.3f} {msg}\n")

    try:
        manifest = run(args.input, args.name, args.work, Limits.from_dict(json.loads(args.limits)), progress)
    except Exception as exc:  # noqa: BLE001
        manifest = {"manifest_version": MANIFEST_VERSION, "fatal_error": f"{type(exc).__name__}: {exc}",
                    "trace": traceback.format_exc()[-4000:]}
        (args.work / "manifest.json").write_text(json.dumps(manifest, indent=1, default=str))
        return 2
    (args.work / "manifest.json").write_text(json.dumps(manifest, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
