"""Sandbox runner tests. Docker-mode tests run only when Docker and the dfa-sandbox image exist."""
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from dfa.containers import DockerJobExecutor, JobRejected, _image_has, build_argv
from dfa.sandbox import SandboxError, docker_available, docker_image_present, resolve_mode, run_analysis

DOCKER_OK = docker_available() and docker_image_present("dfa-sandbox:latest")


def stage(settings, fixture: Path) -> tuple[str, Path, Path]:
    """Place a fixture in the standard scan layout (<data>/uploads/<id>.bin, <data>/work/<id>)."""
    sid = str(uuid.uuid4())
    settings.ensure_dirs()
    inp = settings.uploads_dir / f"{sid}.bin"
    shutil.copy(fixture, inp)
    work = settings.work_root / sid
    work.mkdir(parents=True)
    return sid, inp, work


def test_local_mode(settings, fixtures, tmp_path):
    res = run_analysis(fixtures["px4"], "fw.px4", tmp_path / "w", settings)
    assert res.isolation.startswith("local")
    assert res.manifest["identification"]["platform"] == "PX4"


def test_local_mode_memory_limit_enforced(settings, fixtures, tmp_path):
    settings.sandbox_memory = "20m"  # far too small for the interpreter
    with pytest.raises(SandboxError):
        run_analysis(fixtures["px4"], "fw.px4", tmp_path / "w", settings)


def test_docker_required_but_missing(settings):
    settings.sandbox_mode = "docker"
    settings.sandbox_image = "dfa-test/does-not-exist:0"
    with pytest.raises(SandboxError):
        resolve_mode(settings)


def test_unsandboxed_fallback_can_be_disabled(settings):
    settings.sandbox_mode = "auto"
    settings.sandbox_image = "dfa-test/does-not-exist:0"
    settings.allow_unsandboxed = False
    with pytest.raises(SandboxError):
        resolve_mode(settings)


def test_docker_mode_requires_scan_layout(settings, fixtures, tmp_path):
    if not DOCKER_OK:
        pytest.skip("Docker or dfa-sandbox image not available")
    settings.sandbox_mode = "docker"
    with pytest.raises(SandboxError, match="uploads"):
        run_analysis(fixtures["px4"], "fw.px4", tmp_path / "w", settings)


# --------------------------------------------------------------- profile contract (no Docker needed)
@pytest.mark.parametrize("profile,params", [
    ("fwanalyzer", {"config": "/etc/passwd", "target": "/in/firmware", "out": "/work/tools/fwanalyzer/o.json"}),
    ("fwanalyzer", {"config": "/work/tools/fwanalyzer/../../x.toml", "target": "/in/firmware",
                    "out": "/work/tools/fwanalyzer/o.json"}),
    ("fwanalyzer", {"config": "/work/tools/fwanalyzer/c.toml", "target": "/work/-rf", "out": "/work/tools/fwanalyzer/o"}),
    ("cwe_checker", {"target": "/host/secret"}),
    ("cwe_checker", {"target": "/in/firmware", "bare_metal_config": "/work/files/evil.json"}),
    ("ghidra", {"target": "/in/firmware", "out": "/work/tools/ghidra/o.json", "raw": {"processor": "EVIL", "base": "0x0"}}),
    ("ghidra", {"target": "/in/firmware", "out": "/work/tools/ghidra/o.json",
                "raw": {"processor": "ARM:LE:32:Cortex", "base": "0x08000000; rm -rf /"}}),
    ("ghidra", {"target": "/in/firmware", "out": "/tmp/x.json"}),
    ("analyze", {"limits": {"max_files": "lots"}}),
    ("privileged", {}),
])
def test_profile_contract_rejects_bad_requests(profile, params):
    with pytest.raises(JobRejected):
        build_argv(profile, params)


def test_profile_command_is_hardened(settings):
    sid = str(uuid.uuid4())
    settings.ensure_dirs()
    (settings.uploads_dir / f"{sid}.bin").write_bytes(b"x")
    (settings.work_root / sid).mkdir()
    ex = DockerJobExecutor(settings)
    cmd, _name, _t = ex.command("cwe_checker", sid, {"target": "/in/firmware"})
    joined = " ".join(cmd)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--pids-limit",
                 "--memory", "--ulimit core=0", ":/in/firmware:ro"):
        assert flag in joined, flag
    assert "--privileged" not in joined and "/var/run/docker.sock" not in joined
    with pytest.raises(JobRejected):
        ex.command("analyze", "../../etc", {})
    with pytest.raises(JobRejected):
        ex.command("analyze", str(uuid.uuid4()), {})  # unknown scan


# --------------------------------------------------------------- real Docker runs
@pytest.mark.skipif(not DOCKER_OK, reason="Docker or dfa-sandbox image not available")
def test_docker_mode(settings, fixtures):
    settings.sandbox_mode = "docker"
    settings.sandbox_image = "dfa-sandbox:latest"
    sid, inp, work = stage(settings, fixtures["squashfs"])
    res = run_analysis(inp, "rootfs.squashfs", work, settings)
    assert res.isolation.startswith("docker")
    names = {a["name"] for a in res.manifest["extraction"]["artifacts"]}
    assert "/etc/shadow" in names
    assert (work / "manifest.json").exists()


@pytest.mark.skipif(not DOCKER_OK, reason="Docker or dfa-sandbox image not available")
def test_docker_mode_has_no_network():
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "dfa-sandbox:latest", "python", "-c",
                        "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)"],
                       capture_output=True, timeout=60)
    assert r.returncode != 0


def test_host_path_translation(settings, tmp_path):
    settings.sandbox_host_data_dir = Path("/srv/dfa/var")
    ex = DockerJobExecutor(settings)
    inside = settings.work_root / "abc" / "files"
    inside.mkdir(parents=True)
    assert ex._host(inside) == "/srv/dfa/var/work/abc/files"
    with pytest.raises(JobRejected):
        ex._host(tmp_path / "elsewhere")


@pytest.mark.skipif(not DOCKER_OK, reason="Docker or dfa-sandbox image not available")
def test_fwanalyzer_runs_inside_sandbox(settings, fixtures):
    from dfa.adapters.base import AdapterContext
    from dfa.adapters.fwanalyzer import FwAnalyzerAdapter
    if not _image_has("dfa-sandbox:latest", "fwanalyzer"):
        pytest.skip("sandbox image built without FwAnalyzer")
    settings.sandbox_mode = "docker"
    settings.sandbox_image = "dfa-sandbox:latest"
    sid, inp, work = stage(settings, fixtures["squashfs"])
    res = run_analysis(inp, "rootfs.squashfs", work, settings)
    ad = FwAnalyzerAdapter(settings)
    assert ad.status().mode == "sandbox"
    ctx = AdapterContext(scan_id=sid, input_path=inp, original_name="rootfs.squashfs",
                         work_dir=work, manifest=res.manifest, settings=settings)
    r = ad.execute(ctx)
    assert r.status == "completed", r.message
    assert r.details["execution"] == "sandbox"
    rules = {f.rule_id for f in r.findings}
    assert {"fwa-suid", "fwa-empty-password", "fwa-bad-file"} <= rules


@pytest.mark.skipif(not DOCKER_OK, reason="Docker or dfa-sandbox image not available")
@pytest.mark.parametrize("key", ["ubi", "jffs2", "ext4"])
def test_docker_mode_filesystems(settings, fixtures, key):
    if key not in fixtures:
        pytest.skip("fixture unavailable")
    if key != "ext4" and not _image_has("dfa-sandbox:latest", "jefferson"):
        pytest.skip("sandbox image built without UBI/JFFS2 tools")
    settings.sandbox_mode = "docker"
    settings.sandbox_image = "dfa-sandbox:latest"
    sid, inp, work = stage(settings, fixtures[key])
    res = run_analysis(inp, fixtures[key].name, work, settings)
    arts = {a["name"]: a for a in res.manifest["extraction"]["artifacts"]}
    assert "/etc/shadow" in arts
    if key == "ext4":
        assert arts["/bin/busybox"]["mode"] == 0o4755
    assert any(f["rule_id"] == "empty-password" for f in res.manifest["findings"])
