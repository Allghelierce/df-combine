"""Sandbox runner tests. Docker-mode tests run only when Docker and the dfa-sandbox image exist."""
import os
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


@pytest.mark.skipif(os.getuid() != 0, reason="ownership hand-over needs root (as the broker runs)")
def test_job_output_is_handed_back_to_the_worker(settings, monkeypatch):
    """The broker chowns the writable tree to the tool UID for the job and back to the worker afterwards."""
    settings.ensure_dirs()
    os.chown(settings.data_dir, 12345, 12346)  # the (unprivileged) worker owns the data directory
    sid = str(uuid.uuid4())
    (settings.uploads_dir / f"{sid}.bin").write_bytes(b"x")
    work = settings.work_root / sid
    (work / "tools" / "fwanalyzer").mkdir(parents=True)
    (work / "tools" / "fwanalyzer" / "cfg.toml").write_text("x")
    for dirpath, _d, files in os.walk(work):  # as if the worker had created them
        os.chown(dirpath, 12345, 12346)
        for f in files:
            os.chown(os.path.join(dirpath, f), 12345, 12346)
    seen = {}

    class FakeProc:
        returncode = 0
        stdout = stderr = None

        def __init__(self, cmd, **kw):
            seen["during_analyze_work"] = work.stat().st_uid
            seen["during_tools"] = (work / "tools").stat().st_uid
            (work / "files").mkdir(exist_ok=True)
            (work / "files" / "out.bin").write_bytes(b"y")
            os.chown(work / "files" / "out.bin", 10001, 10001)  # written by the sandbox user
            (work / "evil").symlink_to("/etc/passwd")

        def poll(self):
            return 0

    import io
    FakeProc.stdout = io.BytesIO()
    FakeProc.stderr = io.BytesIO()
    monkeypatch.setattr("dfa.containers.subprocess.Popen", lambda cmd, **kw: _with_streams(FakeProc(cmd, **kw)))
    before = os.stat("/etc/passwd")
    DockerJobExecutor(settings).run("analyze", sid, {"name": "x", "limits": {}})
    assert seen["during_analyze_work"] == 10001 and seen["during_tools"] == 12345
    for p in (work, work / "files", work / "files" / "out.bin", work / "tools" / "fwanalyzer" / "cfg.toml"):
        assert (p.stat().st_uid, p.stat().st_gid) == (12345, 12346), p
    assert os.lstat(work / "evil").st_uid == 12345  # the link itself, never its target
    after = os.stat("/etc/passwd")
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)


@pytest.mark.skipif(os.getuid() != 0, reason="ownership hand-over needs root (as the broker runs)")
def test_broker_never_chowns_through_symlinks(settings, tmp_path):
    """A compromised worker owns work/ and tools/ and can swap them for symlinks to host paths
    (e.g. the Docker socket's directory). The root broker must refuse instead of chowning the target."""
    settings.ensure_dirs()
    os.chown(settings.work_root, 12345, 12346)
    victim = tmp_path / "host-secrets"
    victim.mkdir()
    (victim / "docker.sock").write_text("x")
    before = {p.name: (p.stat().st_uid, p.stat().st_gid) for p in (victim, victim / "docker.sock")}

    sid = str(uuid.uuid4())
    (settings.uploads_dir / f"{sid}.bin").write_bytes(b"x")
    work = settings.work_root / sid
    (work / "tools").mkdir(parents=True)
    (work / "tools" / "cwe_checker").symlink_to(victim)  # swapped tool directory
    ex = DockerJobExecutor(settings)
    with pytest.raises(JobRejected):
        ex.command("cwe_checker", sid, {"target": "/in/firmware"})

    sid2 = str(uuid.uuid4())
    (settings.uploads_dir / f"{sid2}.bin").write_bytes(b"x")
    (settings.work_root / sid2).symlink_to(victim)  # swapped scan directory
    with pytest.raises(JobRejected):
        ex.command("analyze", sid2, {"name": "x", "limits": {}})

    sid3 = str(uuid.uuid4())
    (settings.uploads_dir / f"{sid3}.bin").symlink_to(victim / "docker.sock")  # swapped upload
    (settings.work_root / sid3).mkdir()
    with pytest.raises(JobRejected):
        ex.command("analyze", sid3, {"name": "x", "limits": {}})

    after = {p.name: (p.stat().st_uid, p.stat().st_gid) for p in (victim, victim / "docker.sock")}
    assert after == before


@pytest.mark.skipif(os.getuid() != 0, reason="broker-managed directories need root (as the broker runs)")
def test_broker_owns_work_root_and_manages_scan_dirs(settings, tmp_path):
    """The worker cannot replace work/<id> (a bind-mount source) because only the broker can write the
    work root; the broker resets and removes scan directories without following links."""
    settings.ensure_dirs()
    os.chown(settings.data_dir, 12345, 12346)
    os.chown(settings.work_root, 12345, 12346)  # as left by an older version
    victim = tmp_path / "outside"
    victim.mkdir()
    (victim / "keep.txt").write_text("x")
    ex = DockerJobExecutor(settings)
    sid = str(uuid.uuid4())
    work = settings.work_root / sid
    work.mkdir()
    (work / "files").mkdir()
    (work / "files" / "a.bin").write_bytes(b"1")
    (work / "files" / "link").symlink_to(victim)  # attacker-chosen link inside the tree
    ex.workdir(sid, "reset")
    st = os.stat(settings.work_root)
    assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (0, 0, 0o755)
    assert list(work.iterdir()) == [] and (os.stat(work).st_uid, os.stat(work).st_gid) == (12345, 12346)
    assert (victim / "keep.txt").exists()  # the link was removed, not followed
    os.rmdir(work)
    work.symlink_to(victim)  # a link where the scan directory should be
    ex.workdir(sid, "reset")
    assert work.is_dir() and not work.is_symlink() and (victim / "keep.txt").exists()
    ex.workdir(sid, "remove")
    assert not work.exists() and (victim / "keep.txt").exists()
    with pytest.raises(JobRejected):
        ex.workdir("../etc", "reset")


def _with_streams(proc):
    import io
    proc.stdout, proc.stderr = io.BytesIO(), io.BytesIO()
    return proc


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


def test_broker_protocol_over_unix_socket(settings, tmp_path):
    """The real broker server and client: work directory management, rejected requests, token check."""
    import threading

    from dfa.broker import serve
    from dfa.containers import BrokerRunner, JobError
    settings.ensure_dirs()
    sock = tmp_path / "b.sock"
    server = serve(sock, settings, token="s3cret-token")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = BrokerRunner(settings.model_copy(update={"broker_socket": sock, "broker_token": "s3cret-token"}))
        sid = str(uuid.uuid4())
        (settings.uploads_dir / f"{sid}.bin").write_bytes(b"x")
        client.workdir(sid, "reset")
        assert (settings.work_root / sid).is_dir()
        client.workdir(sid, "remove")
        assert not (settings.work_root / sid).exists()
        with pytest.raises(JobRejected):
            client.workdir("../../etc", "reset")
        with pytest.raises(JobRejected):
            client.run("shell", sid, {"cmd": "id"})  # only the fixed profiles exist
        intruder = BrokerRunner(settings.model_copy(update={"broker_socket": sock, "broker_token": "guess"}))
        with pytest.raises(JobError):
            intruder.workdir(sid, "reset")
        assert not (settings.work_root / sid).exists()
    finally:
        server.shutdown()
        server.server_close()
