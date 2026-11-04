"""ELF header/hardening inspection using pyelftools (pure Python, no execution)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import BinaryIO

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

MACHINE_NAMES = {
    "EM_ARM": "ARM (32-bit)",
    "EM_AARCH64": "AArch64",
    "EM_X86_64": "x86-64",
    "EM_386": "x86",
    "EM_MIPS": "MIPS",
    "EM_PPC": "PowerPC",
    "EM_PPC64": "PowerPC64",
    "EM_RISCV": "RISC-V",
    "EM_XTENSA": "Xtensa",
    "EM_AVR": "AVR",
    "EM_SPARC": "SPARC",
    "EM_SH": "SuperH",
}

DANGEROUS_IMPORTS = {
    "gets": "high",
    "strcpy": "low",
    "strcat": "low",
    "sprintf": "low",
    "vsprintf": "low",
    "system": "low",
    "popen": "low",
    "execl": "info",
    "execlp": "info",
    "execve": "info",
    "mktemp": "low",
    "tmpnam": "low",
}


@dataclass
class ElfInfo:
    machine: str
    arch: str
    bits: int
    endianness: str
    elf_type: str
    entry: int
    interpreter: str | None = None
    is_dynamic: bool = False
    soname: str | None = None
    needed: list[str] = field(default_factory=list)
    stripped: bool = True
    has_debug_info: bool = False
    nx: bool | None = None
    pie: bool | None = None
    relro: str | None = None  # "full" | "partial" | "none"
    canary: bool = False
    fortify: bool = False
    imports: list[str] = field(default_factory=list)
    dangerous_imports: list[str] = field(default_factory=list)
    is_kernel_module: bool = False
    os_hint: str | None = None  # "linux" | "bare-metal" | None
    sections: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["imports"] = self.imports[:200]
        return d


def inspect_elf(fp: BinaryIO) -> ElfInfo:
    """Parse an ELF file.  Raises ELFError/ValueError on malformed input."""
    try:
        elf = ELFFile(fp)
    except (ELFError, ValueError, OSError, IndexError, KeyError) as exc:  # pragma: no cover
        raise ValueError(f"malformed ELF: {exc}") from None
    machine = elf["e_machine"]
    info = ElfInfo(
        machine=str(machine),
        arch=MACHINE_NAMES.get(str(machine), str(machine)),
        bits=elf.elfclass,
        endianness="little" if elf.little_endian else "big",
        elf_type=str(elf["e_type"]),
        entry=int(elf["e_entry"]),
    )
    try:
        info.sections = elf.num_sections()
    except Exception:  # noqa: BLE001 - malformed headers are common in firmware
        info.sections = 0

    gnu_stack = None
    has_relro = False
    for seg in _safe_iter(elf.iter_segments):
        ptype = seg["p_type"]
        if ptype == "PT_INTERP":
            try:
                info.interpreter = seg.get_interp_name()
            except Exception:  # noqa: BLE001
                info.interpreter = "<unreadable>"
        elif ptype == "PT_GNU_STACK":
            gnu_stack = seg
        elif ptype == "PT_GNU_RELRO":
            has_relro = True
        elif ptype == "PT_DYNAMIC":
            info.is_dynamic = True

    bind_now = False
    symbols: set[str] = set()
    has_symtab = False
    for sec in _safe_iter(elf.iter_sections):
        name = sec.name or ""
        if name.startswith(".debug_"):
            info.has_debug_info = True
        if name == ".modinfo" or name == ".gnu.linkonce.this_module":
            info.is_kernel_module = True
        if isinstance(sec, DynamicSection):
            for tag in _safe_iter(sec.iter_tags):
                t = tag.entry.d_tag
                if t == "DT_NEEDED":
                    info.needed.append(tag.needed)
                elif t == "DT_SONAME":
                    info.soname = tag.soname
                elif t == "DT_BIND_NOW":
                    bind_now = True
                elif t == "DT_FLAGS" and tag.entry.d_val & 0x8:
                    bind_now = True
                elif t == "DT_FLAGS_1" and tag.entry.d_val & 0x1:
                    bind_now = True
        if isinstance(sec, SymbolTableSection):
            if sec.name == ".symtab":
                has_symtab = True
            for sym in _safe_iter(sec.iter_symbols):
                if sym.name:
                    if sec.name == ".dynsym" and sym["st_shndx"] == "SHN_UNDEF":
                        info.imports.append(sym.name)
                    symbols.add(sym.name)
                if len(symbols) > 200_000:
                    break
    info.stripped = not has_symtab
    info.canary = "__stack_chk_fail" in symbols or "__stack_chk_guard" in symbols
    info.fortify = any(s.endswith("_chk") and s.startswith("__") and s != "__stack_chk_fail" for s in symbols)
    imported = set(info.imports)
    info.dangerous_imports = sorted(f for f in DANGEROUS_IMPORTS if f in imported)

    is_linux_userland = bool(info.interpreter) or info.is_dynamic or info.is_kernel_module
    info.os_hint = "linux" if is_linux_userland else ("bare-metal" if info.elf_type == "ET_EXEC" else None)
    if is_linux_userland and not info.is_kernel_module:
        info.nx = gnu_stack is not None and not (gnu_stack["p_flags"] & 0x1)
        info.pie = info.elf_type == "ET_DYN" and info.interpreter is not None
        info.relro = "full" if (has_relro and bind_now) else ("partial" if has_relro else "none")
    return info


def _safe_iter(fn):
    try:
        yield from fn()
    except Exception:  # noqa: BLE001 - tolerate truncated/malformed tables
        return
