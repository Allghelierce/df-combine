import json
import shutil
import subprocess

import pytest

from dfa.adapters import cwe_checker, fwanalyzer
from dfa.adapters.base import AdapterContext
from dfa.adapters.registry import all_statuses

CWE_SAMPLE = json.dumps([
    {"name": "CWE676", "version": "0.1", "addresses": ["00101170"], "tids": ["instr_00101170_2"],
     "symbols": ["main"], "other": [["dangerous_function", "strcpy"]],
     "description": "(Use of Potentially Dangerous Function) main (00101170) -> strcpy"},
    {"name": "CWE676", "version": "0.1", "addresses": ["00101180"], "tids": [], "symbols": ["main"], "other": [],
     "description": "(Use of Potentially Dangerous Function) main (00101180) -> gets"},
    {"name": "CWE787", "version": "0.3", "addresses": ["00101190"], "tids": [], "symbols": [], "other": [],
     "description": "(Buffer Overflow) Potential overflow at 00101190"},
])


def ctx_for(settings, manifest, tmp_path, input_path=None):
    return AdapterContext(scan_id="t", input_path=input_path or tmp_path / "in.bin", original_name="in.bin",
                          work_dir=tmp_path, manifest=manifest, settings=settings)


def test_statuses_report_unavailable_tools(settings):
    st = {s["name"]: s for s in all_statuses(settings)}
    assert st["builtin"]["available"]
    if not shutil.which("cwe_checker"):
        assert st["cwe_checker"]["available"] is False


def test_cwe_checker_parse_and_normalize():
    ws = cwe_checker.parse_output("some log line\n" + CWE_SAMPLE)
    fs = cwe_checker.normalize(ws, "fw > /usr/bin/flightd")
    by = {f.rule_id: f for f in fs}
    assert by["CWE676"].title.endswith("(2 warnings)")
    assert all(f.classification.value == "unverified" for f in fs)
    assert by["CWE787"].cwe == "CWE-787"
    assert cwe_checker.parse_output("") == []
    with pytest.raises(ValueError):
        cwe_checker.parse_output("garbage")


def test_cwe_checker_plan(settings, tmp_path):
    ad = cwe_checker.CweCheckerAdapter(settings)
    elf = {"machine": "EM_ARM", "is_kernel_module": False}
    man = {"extraction": {"artifacts": [
        {"id": 1, "name": "/bin/busybox", "format": "elf", "elf": elf, "category": "executable", "size": 900000},
        {"id": 2, "name": "/usr/bin/mavlink-routerd", "format": "elf", "elf": elf, "category": "executable", "size": 1000},
        {"id": 3, "name": "/lib/x.ko", "format": "elf", "elf": {**elf, "is_kernel_module": True}, "size": 1},
        {"id": 4, "name": "/lib/libc.so", "format": "elf", "elf": {**elf, "machine": "EM_XTENSA"}, "size": 1},
    ]}}
    targets, _ = ad.plan(ctx_for(settings, man, tmp_path))
    assert [t["artifact"]["id"] for t in targets] == [2]  # BusyBox is skipped: slow (~9 min) and noisy
    raw = {"extraction": {"artifacts": [{"id": 0, "name": "image.bin", "format": "cortexm_raw", "size": 10}]}}
    targets, reason = ad.plan(ctx_for(settings, raw, tmp_path))
    assert targets == [] and "bare-metal" in reason


def test_cwe_checker_names_unchecked_return_value():
    ws = [{"name": "CWE252", "version": "0.1", "addresses": ["00101170"], "tids": [], "symbols": [], "other": [],
           "description": "(Unchecked Return Value) ..."}]
    (f,) = cwe_checker.normalize(ws, "fw > /usr/bin/flightd")
    assert f.title == "[cwe_checker] CWE252: Unchecked return value (1 warning)"
    assert f.cwe == "CWE-252"


def test_cwe_checker_removes_container_after_timeout(settings, tmp_path, monkeypatch):
    calls = []

    def fake_run_cmd(cmd, timeout, cwd=None):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, timeout)
        return 0, "", "", 0.0

    monkeypatch.setattr(cwe_checker, "run_cmd", fake_run_cmd)
    ad = cwe_checker.CweCheckerAdapter(settings)
    monkeypatch.setattr(ad, "status", lambda: ad._status(True, "test", mode="docker"))
    (tmp_path / "flightd").write_bytes(b"\x7fELF")
    art = {"id": 1, "name": "/usr/bin/flightd", "path": "flightd", "display_path": "fw > /usr/bin/flightd"}

    res = ad.run(ctx_for(settings, {}, tmp_path), [{"artifact": art, "bare_metal": None}])

    run_cmd_args = calls[0]
    name = run_cmd_args[run_cmd_args.index("--name") + 1]
    assert calls[1] == ["docker", "rm", "-f", name]
    assert res.details["targets"][0]["status"] == "failed"


def test_cwe_checker_unavailable_execute(settings, tmp_path):
    if shutil.which("cwe_checker"):
        pytest.skip("cwe_checker installed")
    r = cwe_checker.CweCheckerAdapter(settings).execute(ctx_for(settings, {}, tmp_path))
    assert r.status == "unavailable"


FWA_REPORT = {"fs_type": "squashfs", "offenders": {
    "/bin/busybox": ["File is SUID, not allowed"],
    "/etc/app/cloud.conf": ["File is WorldWriteable, not allowed"],
    "/etc/shadow": ["RegEx check failed, for: shadow_empty_password : account with empty password : line: root::19000:0:99999:7:::"],
    "/etc/ssh/ssh_host_rsa_key": ["File not allowed for pattern: /etc/ssh/ssh_host_*_key"],
}, "informational": {"/bin": ["CheckFileTree: new file"]}}


def test_fwanalyzer_normalize():
    fs = fwanalyzer.normalize(FWA_REPORT, "fw.squashfs", perms=True)
    by = {f.rule_id: f for f in fs}
    assert by["fwa-empty-password"].severity.value == "critical"
    assert by["fwa-bad-file"].severity.value == "high"
    assert by["fwa-suid"] and by["fwa-world-writable"]
    assert by["fwa-informational"].classification.value == "info"


def test_fwanalyzer_config_escaping(tmp_path):
    (tmp_path / "etc/ssh").mkdir(parents=True)
    (tmp_path / "etc/ssh/sshd_config").write_text("x")
    cfg = fwanalyzer.build_config("dirfs", tmp_path, perms=False)
    assert 'FsType = "dirfs"' in cfg and "Suid = false" in cfg
    assert '"^\\\\s*PermitEmptyPasswords\\\\s+yes"' in cfg


def test_fwanalyzer_not_applicable_to_mcu(settings, tmp_path):
    ad = fwanalyzer.FwAnalyzerAdapter(settings)
    targets, reason = ad.plan(ctx_for(settings, {"extraction": {"artifacts": [], "filesystems": []}}, tmp_path))
    assert not targets and "PX4" in reason


@pytest.mark.skipif(not shutil.which("fwanalyzer"), reason="fwanalyzer binary not installed")
@pytest.mark.parametrize("key", ["squashfs", "ext4", "tar_gz"])
def test_fwanalyzer_real_run(settings, fixtures, tmp_path, key):
    """Runs the real FwAnalyzer binary on extracted synthetic filesystems."""
    if key not in fixtures:
        pytest.skip("fixture unavailable")
    from dfa.core.analyze import run
    from dfa.core.limits import Limits
    work = tmp_path / "work"
    man = run(fixtures[key], fixtures[key].name, work, Limits())
    ad = fwanalyzer.FwAnalyzerAdapter(settings)
    res = ad.execute(ctx_for(settings, man, work, input_path=fixtures[key]))
    assert res.status == "completed", res.message
    rules = {f.rule_id for f in res.findings}
    assert "fwa-empty-password" in rules and "fwa-bad-file" in rules
    if key == "squashfs":
        assert "fwa-suid" in rules  # image mode keeps permission bits
    if key == "ext4":
        # Stock e2tools makes FwAnalyzer's extfs backend fail; we fall back to dirfs and say so.
        assert any(r.get("mode") for r in res.details["runs"])


def test_correlation_merges_fwanalyzer_duplicates():
    from dfa.core.findings import Classification, Confidence, Evidence, Finding, Severity, correlate
    b = Finding("Account 'root' has an empty password", "d", Severity.critical, Classification.detected,
                Confidence.high, "builtin:secrets", "empty-password", "fw.img > p1.img > /etc/shadow", "r",
                [Evidence("config", "root::1", "/etc/shadow")])
    other = Finding("Static Wi-Fi passphrase", "d", Severity.high, Classification.detected, Confidence.medium,
                    "builtin:secrets", "hostapd-static-psk", "fw.img > p1.img > /etc/hostapd.conf", "r")
    fwa = fwanalyzer.normalize(FWA_REPORT, "fw.img > p1.img", perms=True)
    merged = correlate([b, other] + fwa)
    assert not any(f.rule_id == "fwa-empty-password" for f in merged)
    assert "corroborated-by:fwanalyzer" in b.tags
    assert any(e.value.startswith("[fwanalyzer]") for e in b.evidence)
    # Unrelated FwAnalyzer results stay.
    assert any(f.rule_id == "fwa-bad-file" for f in merged)
