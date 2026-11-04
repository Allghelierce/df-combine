"""Sandbox runner tests (Docker mode runs only when the sandbox image is built)."""

import pytest

from dfa.sandbox import SandboxError, docker_available, docker_image_present, resolve_mode, run_analysis

DOCKER_OK = docker_available() and docker_image_present("dfa-sandbox:latest")


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


@pytest.mark.skipif(not DOCKER_OK, reason="Docker or dfa-sandbox image not available")
def test_docker_mode(settings, fixtures, tmp_path):
    settings.sandbox_mode = "docker"
    settings.sandbox_image = "dfa-sandbox:latest"
    res = run_analysis(fixtures["squashfs"], "rootfs.squashfs", tmp_path / "w", settings)
    assert res.isolation.startswith("docker")
    names = {a["name"] for a in res.manifest["extraction"]["artifacts"]}
    assert "/etc/shadow" in names
    assert (tmp_path / "w" / "manifest.json").exists()


@pytest.mark.skipif(not DOCKER_OK, reason="Docker or dfa-sandbox image not available")
def test_docker_mode_has_no_network(settings, tmp_path):
    import subprocess
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "dfa-sandbox:latest", "python", "-c",
                        "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)"],
                       capture_output=True, timeout=60)
    assert r.returncode != 0


@pytest.mark.skipif(not DOCKER_OK, reason="Docker or dfa-sandbox image not available")
def test_fwanalyzer_runs_inside_sandbox(settings, fixtures, tmp_path):
    from dfa.adapters.base import AdapterContext
    from dfa.adapters.fwanalyzer import FwAnalyzerAdapter
    from dfa.toolexec import image_has_binary
    if not image_has_binary("dfa-sandbox:latest", "fwanalyzer"):
        pytest.skip("sandbox image built without FwAnalyzer")
    settings.sandbox_mode = "docker"
    settings.sandbox_image = "dfa-sandbox:latest"
    work = tmp_path / "w"
    res = run_analysis(fixtures["squashfs"], "rootfs.squashfs", work, settings)
    ad = FwAnalyzerAdapter(settings)
    assert ad.status().mode == "sandbox"
    ctx = AdapterContext(scan_id="t", input_path=fixtures["squashfs"], original_name="rootfs.squashfs",
                         work_dir=work, manifest=res.manifest, settings=settings)
    r = ad.execute(ctx)
    assert r.status == "completed", r.message
    assert r.details["execution"] == "sandbox"
    rules = {f.rule_id for f in r.findings}
    assert {"fwa-suid", "fwa-empty-password", "fwa-bad-file"} <= rules


def test_host_path_translation(settings, tmp_path):
    from pathlib import Path

    from dfa.sandbox import _host_path
    settings.sandbox_host_data_dir = Path("/srv/dfa/var")
    inside = settings.work_root / "abc" / "files"
    inside.mkdir(parents=True)
    assert _host_path(inside, settings) == "/srv/dfa/var/work/abc/files"
    assert _host_path(tmp_path, settings) == str(tmp_path.resolve())
