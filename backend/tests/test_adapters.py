import json
import shutil

import httpx
import pytest

from dfa.adapters import cwe_checker, fact, fwanalyzer
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
    assert st["fact"]["available"] is False and "DFA_FACT_URL" in st["fact"]["detail"]
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
    assert [t["artifact"]["id"] for t in targets] == [2, 1]
    raw = {"extraction": {"artifacts": [{"id": 0, "name": "image.bin", "format": "cortexm_raw", "size": 10}]}}
    targets, reason = ad.plan(ctx_for(settings, raw, tmp_path))
    assert targets == [] and "load address" in reason
    raw["extraction"]["artifacts"][0]["details"] = {"flash_base": "0x8008000", "initial_sp": "0x2002b962"}
    targets, _ = ad.plan(ctx_for(settings, raw, tmp_path))
    assert targets[0]["bare_metal"] == {"processor_id": "ARM:LE:32:Cortex", "flash_base_address": "0x8008000",
                                        "ram_base_address": "0x20000000", "ram_size": "0x30000"}
    settings.cwe_checker_bare_metal = False
    targets, reason = ad.plan(ctx_for(settings, raw, tmp_path))
    assert targets == [] and "bare-metal mode is disabled" in reason


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
    assert not targets and "NuttX" in reason


def test_fwanalyzer_nuttx_profile(settings, tmp_path):
    etc = tmp_path / "files" / "00002_x.cromfs.d"
    (etc / "init.d" / "airframes").mkdir(parents=True)
    (etc / "init.d" / "rcS").write_text("param set-default CBRK_SUPPLY_CHK 894281\n")
    (etc / "init.d" / "airframes" / "1000_x").write_text("param set MAV_BROADCAST 1\n")
    man = {"extraction": {"artifacts": [{"id": 2, "name": "carved.cromfs", "display_path": "fw > carved.cromfs",
                                         "format": "cromfs", "path": "files/x"}],
                          "filesystems": [{"artifact_id": 2, "type": "cromfs", "root": "files/00002_x.cromfs.d"}]}}
    targets, _ = fwanalyzer.FwAnalyzerAdapter(settings).plan(ctx_for(settings, man, tmp_path))
    assert targets and targets[0]["profile"] == "nuttx"
    cfg = fwanalyzer.build_config("dirfs", etc, False, "nuttx")
    assert 'File = "/init.d/rcS"' in cfg and "CBRK_" in cfg and "Suid = false" in cfg
    rule, sev, title, _ = fwanalyzer._classify(
        "RegEx check failed, for: cbrk_1 : PX4 safety circuit breaker set to its disable value : line: x", "/x", False)
    assert rule == "fwa-px4-cbrk"


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


class FakeFact:
    def __init__(self):
        self.uploaded = None
        self.status_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/status":
            self.status_calls += 1
            running = {"abc_123": {}} if self.status_calls < 3 else {}
            return httpx.Response(200, json={"system_status": {"backend": {"analysis": {"current_analyses": running}}}})
        if request.method == "PUT" and request.url.path == "/rest/firmware":
            self.uploaded = json.loads(request.content)
            return httpx.Response(200, json={"uid": "abc_123"})
        if request.url.path == "/rest/firmware/abc_123":
            # shape verified against a real FACT 4.x instance (summary = {label: [uids]}, unpacker always present)
            return httpx.Response(200, json={"firmware": {"meta_data": {"number_of_included_files": 7}, "analysis": {
                "unpacker": {"summary": {"unpacked": ["abc_123"]}},
                "software_components": {"summary": {"BusyBox 1.31.1": ["uid9"], "OpenSSL 1.0.2k": ["uid8"]}},
                "crypto_material": {"summary": {"SshRsaPrivateKeyBlock": ["uid1", "uid2"]}},
                "users_and_passwords": {"summary": {"root:unix": ["uid3"]}},
                "cve_lookup": {"summary": {"OpenSSL 1.0.1e (CRITICAL)": ["uid4"]}},
                "exploit_mitigations": {"summary": {"NX enabled": ["u"], "Canary disabled": ["u5"]}},
                "file_type": {"summary": {"application/x-executable": ["u"]}},
            }}})
        return httpx.Response(404)


def test_fact_adapter_with_mock(settings, tmp_path, monkeypatch):
    settings.fact_url = "http://fact.test"
    settings.fact_poll_s = 0
    settings.fact_timeout_s = 20
    fake = FakeFact()
    ad = fact.FactAdapter(settings)
    monkeypatch.setattr(ad, "_client", lambda: httpx.Client(base_url="http://fact.test",
                                                            transport=httpx.MockTransport(fake.handler)))
    inp = tmp_path / "fw.bin"
    inp.write_bytes(b"firmware")
    res = ad.execute(ctx_for(settings, {"identification": {"platform": "PX4"}}, tmp_path, input_path=inp))
    assert res.status == "completed", res.message
    assert fake.uploaded["vendor"] == "PX4" and fake.uploaded["binary"] == "ZmlybXdhcmU="
    # FACT's own cwe_checker plug-in would analyse every ELF of a rootfs (hours); it is opt-in only
    assert "cwe_checker" not in fake.uploaded["requested_analysis_systems"]
    assert "crypto_material" in fake.uploaded["requested_analysis_systems"]
    titles = [f.title for f in res.findings]
    assert any("SshRsaPrivateKeyBlock" in t for t in titles)
    assert any("Canary disabled" in t for t in titles) and not any("NX enabled" in t for t in titles)
    assert {"name": "busybox", "version": "1.31.1"}.items() <= res.details["components"][0].items()
    assert "8 file(s)" in res.message or "file(s)" in res.message
    cve = next(f for f in res.findings if f.rule_id == "fact-cve_lookup")
    assert cve.severity.value == "high" and cve.classification.value == "unverified"


def test_fact_unreachable(settings, tmp_path):
    settings.fact_url = "http://127.0.0.1:9"
    r = fact.FactAdapter(settings).execute(ctx_for(settings, {}, tmp_path))
    assert r.status == "unavailable" and "unreachable" in r.message


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


class SlowFact(FakeFact):
    """FACT that never finishes (or cancels) the analysis but already has partial plug-in results."""

    def __init__(self, cancel: bool = False):
        super().__init__()
        self.cancel = cancel

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/status":
            analysis = {"current_analyses": {} if self.cancel else {"abc_123": {}},
                        "recently_canceled_analyses": {"abc_123": {}} if self.cancel else {}}
            return httpx.Response(200, json={"system_status": {"backend": {"analysis": analysis}}})
        if request.url.path == "/rest/firmware/abc_123":
            return httpx.Response(200, json={"firmware": {"meta_data": {"number_of_included_files": 3311}, "analysis": {
                "unpacker": {"summary": {"unpacked": ["abc_123"]}},
                "crypto_material": {"summary": {"SshRsaPrivateKeyBlock": ["uid1"]}}}}})
        return super().handler(request)


@pytest.mark.parametrize("cancel", [False, True])
def test_fact_timeout_or_cancel_keeps_partial_results(settings, tmp_path, monkeypatch, cancel):
    settings.fact_url, settings.fact_poll_s, settings.fact_timeout_s = "http://fact.test", 0, 0.2
    fake = SlowFact(cancel=cancel)
    ad = fact.FactAdapter(settings)
    monkeypatch.setattr(ad, "_client", lambda: httpx.Client(base_url="http://fact.test",
                                                            transport=httpx.MockTransport(fake.handler)))
    inp = tmp_path / "fw.bin"
    inp.write_bytes(b"firmware")
    res = ad.execute(ctx_for(settings, {"identification": {}}, tmp_path, input_path=inp))
    sub = res.details["submissions"][0]
    if cancel:
        assert res.status == "failed" and sub["status"] == "cancelled"
        assert "cancelled in FACT" in res.message
    else:
        assert res.status == "timeout" and sub["status"] == "timeout"
        assert "did not finish within" in res.message
    assert sub["partial"] and "partial results so far" in res.message and "3312 file(s)" in res.message
    assert any("SshRsaPrivateKeyBlock" in f.title for f in res.findings)  # what FACT had already found is kept
