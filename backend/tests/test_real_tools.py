"""Real tool integration tests: the actual FwAnalyzer, cwe_checker, Ghidra (Docker) and FACT (REST API) on real,
publicly distributed binaries - no mocks. These complement the mock-based unit tests in test_adapters.py.

Opt-in because they need Docker images / a FACT instance and take minutes:

    python scripts/fetch_real_firmware.py               # pinned public samples -> fixtures/real
    DFA_REAL_TOOLS=1 [DFA_FACT_URL=http://localhost:5000] pytest backend/tests/test_real_tools.py

Assertions are about the tools having run and produced parseable output on the given input. Expected findings
are only asserted where the input demonstrably contains the pattern (e.g. an imported strcpy).
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
import urllib.request
import uuid
from pathlib import Path

import pytest

from dfa.adapters.base import AdapterContext
from dfa.adapters.cwe_checker import CweCheckerAdapter
from dfa.adapters.fact import FactAdapter
from dfa.adapters.fwanalyzer import FwAnalyzerAdapter
from dfa.adapters.ghidra import GhidraAdapter
from dfa.config import Settings
from dfa.sandbox import run_analysis

REAL = Path(__file__).resolve().parents[2] / "fixtures" / "real"
SANDBOX_IMAGE = os.environ.get("DFA_SANDBOX_IMAGE", "dfa-sandbox:latest")
CWE_IMAGE = os.environ.get("DFA_CWE_CHECKER_IMAGE", "fkiecad/cwe_checker:latest")
FACT_URL = os.environ.get("DFA_FACT_URL")

pytestmark = pytest.mark.skipif(os.environ.get("DFA_REAL_TOOLS") != "1",
                                reason="real tool integration tests are opt-in: DFA_REAL_TOOLS=1")


def _image(name: str) -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "image", "inspect", name], capture_output=True).returncode == 0


def _sample(name: str) -> Path:
    p = REAL / name
    if not p.exists():
        pytest.skip(f"{name} not fetched (python scripts/fetch_real_firmware.py)")
    return p


def _tar_member(tar_name: str, member: str) -> bytes:
    with tarfile.open(_sample(tar_name)) as t:
        f = t.extractfile(member)
        assert f is not None
        return f.read()


@pytest.fixture
def real_settings(tmp_path) -> Settings:
    if not _image(SANDBOX_IMAGE):
        pytest.skip(f"sandbox image {SANDBOX_IMAGE} not built (make sandbox-image)")
    return Settings(data_dir=tmp_path / "data", sandbox_mode="docker", sandbox_image=SANDBOX_IMAGE,
                    broker_socket=None, cwe_checker_image=CWE_IMAGE, ghidra_image=CWE_IMAGE,
                    fact_url=FACT_URL, fact_poll_s=5, worker_mode="external")


def _scan(settings: Settings, data: bytes, name: str) -> AdapterContext:
    """Stage an upload, run the real sandbox analysis container and return the adapters' context."""
    settings.ensure_dirs()
    sid = str(uuid.uuid4())
    upload = settings.uploads_dir / f"{sid}.bin"
    upload.write_bytes(data)
    work = settings.work_root / sid
    work.mkdir(parents=True)
    res = run_analysis(upload, name, work, settings)
    assert res.isolation.startswith("docker"), res.isolation
    return AdapterContext(scan_id=sid, input_path=upload, original_name=name, work_dir=work,
                          manifest=res.manifest, settings=settings)


# ----------------------------------------------------------------------------- FwAnalyzer
def test_fwanalyzer_on_real_alpine_rootfs(real_settings):
    ctx = _scan(real_settings, _sample("alpine3.15.0-arm64-rootfs.tar.gz").read_bytes(), "alpine-rootfs.tar.gz")
    r = FwAnalyzerAdapter(real_settings).execute(ctx)
    assert r.status == "completed", r.message
    assert "analysed 1/1 filesystem" in r.message
    reports = list((ctx.work_dir / "tools" / "fwanalyzer").glob("report_*.json"))
    assert reports, "FwAnalyzer wrote no report"
    report = json.loads(reports[0].read_text())
    # FwAnalyzer's report always names the analysed image; offenders/informational/data are omitted when empty.
    # The image is the cpio written by the sandbox with the archive's original modes (permission checks on).
    assert report.get("fs_type") == "cpiofs" and report.get("image_name")
    assert set(report) <= {"fs_type", "image_name", "image_digest", "offenders", "informational", "data"}
    assert all(f.source_tool == "fwanalyzer" for f in r.findings)


def test_fwanalyzer_permission_checks_on_real_debian_rootfs(real_settings):
    """Debian 11 really ships setuid-root binaries (su, mount, passwd, ...); FwAnalyzer must see them."""
    ctx = _scan(real_settings, _sample("debian11-armhf-rootfs-20210816.tar.gz").read_bytes(), "debian-rootfs.tar.gz")
    r = FwAnalyzerAdapter(real_settings).execute(ctx)
    assert r.status == "completed", r.message
    assert r.details["runs"][0]["mode"] == "cpiofs"
    suid = [f for f in r.findings if f.rule_id == "fwa-suid"]
    assert suid and suid[0].classification.value == "detected"
    paths = " ".join(e.location or "" for e in suid[0].evidence)
    assert "/bin/su" in paths and "/bin/mount" in paths


def test_fwanalyzer_on_real_px4_cromfs(real_settings):
    ctx = _scan(real_settings, _sample("px4_fmu-v2_default.px4").read_bytes(), "px4_fmu-v2_default.px4")
    fs = [a for a in ctx.manifest["extraction"]["artifacts"] if a["format"] == "cromfs"]
    assert fs, "PX4 CROMFS (ROMFS of /etc) was not extracted"
    r = FwAnalyzerAdapter(real_settings).execute(ctx)
    assert r.status == "completed", r.message
    assert r.details["runs"], r.details


# ----------------------------------------------------------------------------- cwe_checker
@pytest.fixture
def cwe_image():
    if not _image(CWE_IMAGE):
        pytest.skip(f"{CWE_IMAGE} not pulled")


def test_cwe_checker_on_real_arm_elf(real_settings, cwe_image):
    """Debian 11 armhf /sbin/killall5 (18 KB, imports strcpy/sscanf): a dynamically linked 32-bit ARM ELF."""
    elf = _tar_member("debian11-armhf-rootfs-20210816.tar.gz", "sbin/killall5")
    ctx = _scan(real_settings, elf, "killall5")
    r = CweCheckerAdapter(real_settings).execute(ctx)
    assert r.status == "completed", r.message
    raw = list((ctx.work_dir / "tools" / "cwe_checker").glob("result_*.json"))
    assert raw and isinstance(json.loads(raw[0].read_text()), list)  # cwe_checker's JSON warning list
    assert all(f.source_tool == "cwe_checker" and f.classification.value != "detected" for f in r.findings)
    # killall5 really imports strcpy; cwe_checker's CWE-676 check reports such call sites
    assert any(f.cwe == "CWE-676" for f in r.findings), [f.title for f in r.findings]


def test_cwe_checker_and_ghidra_bare_metal_px4_bootloader(real_settings, cwe_image):
    """Official PX4 CAN bootloader (.px4): decoded Cortex-M image analysed with a bare-metal configuration."""
    ctx = _scan(real_settings, _sample("ark_can-flow_canbootloader.px4").read_bytes(), "canbootloader.px4")
    raw = [a for a in ctx.manifest["extraction"]["artifacts"] if a["format"] == "cortexm_raw"]
    assert raw and raw[0]["details"].get("flash_base"), "no Cortex-M image with a flash base"
    r = CweCheckerAdapter(real_settings).execute(ctx)
    assert r.status == "completed", r.message
    assert any(t.get("mode") == "bare-metal" for t in r.details["targets"]), r.details
    g = GhidraAdapter(real_settings).execute(ctx)
    assert g.status == "completed", g.message
    summary = g.details["binaries"][0]
    assert summary["function_count"] > 20 and summary["instruction_count"] > 1000


# ----------------------------------------------------------------------------- FACT
def test_fact_on_real_px4_bootloader(real_settings):
    if not FACT_URL:
        pytest.skip("DFA_FACT_URL not set")
    try:
        urllib.request.urlopen(f"{FACT_URL.rstrip('/')}/rest/status", timeout=10).read()  # noqa: S310
    except OSError as exc:
        pytest.skip(f"FACT not reachable: {exc}")
    ctx = _scan(real_settings, _sample("ark_can-flow_canbootloader.px4").read_bytes(), "canbootloader.px4")
    r = FactAdapter(real_settings).execute(ctx)
    assert r.status == "completed", r.message
    subs = r.details["submissions"]
    assert subs and all(s["status"] == "completed" and s["uid"] for s in subs)
    stored = list((ctx.work_dir / "tools" / "fact").glob("firmware_*.json"))
    assert stored and "analysis" in json.loads(stored[0].read_text())


def test_fact_analyses_files_extracted_from_px4_cromfs(real_settings):
    """FACT has no CROMFS unpacker: the PX4 /etc files are submitted as a tar, and FACT really unpacks them."""
    if not FACT_URL:
        pytest.skip("DFA_FACT_URL not set")
    try:
        urllib.request.urlopen(f"{FACT_URL.rstrip('/')}/rest/status", timeout=10).read()  # noqa: S310
    except OSError as exc:
        pytest.skip(f"FACT not reachable: {exc}")
    ctx = _scan(real_settings, _sample("px4_fmu-v2_default.px4").read_bytes(), "px4_fmu-v2_default.px4")
    r = FactAdapter(real_settings).execute(ctx)
    assert r.status == "completed", r.message
    tree = next(s for s in r.details["submissions"] if s["target"].startswith("files extracted from cromfs"))
    assert tree["status"] == "completed" and tree["files_analysed"] > 20, tree
    assert "application/x-tar" in tree["file_types"]


def test_inputs_are_what_they_claim():
    """Guard against silently testing the wrong file: pinned hashes are checked by the fetch script, and the
    ELF used above must really import strcpy."""
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(_tar_member("debian11-armhf-rootfs-20210816.tar.gz", "sbin/killall5")))
    assert elf.header.e_machine == "EM_ARM"
    names = {s.name.split("@")[0] for s in elf.get_section_by_name(".dynsym").iter_symbols()}
    assert "strcpy" in names
