import base64
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
                "crypto_material": {"summary": {"SshRsaPrivateKeyBlock": ["uid1", "uid2"], "SSLCertificate": ["uid6"]}},
                "users_and_passwords": {"summary": {"root:unix": ["uid3"], "bin:unix": ["uid3"], "daemon:unix": ["uid3"]}},
                "cve_lookup": {"summary": {"OpenSSL 1.0.1e (CRITICAL)": ["uid4"]}},
                # label vocabulary of FACT's exploit_mitigations plug-in (checksec)
                "exploit_mitigations": {"summary": {"NX enabled": ["u"], "CANARY disabled": ["u5"],
                                                    "PIE/DSO present": ["u5"], "RPATH disabled": ["u5"],
                                                    "STRIPPED SYMBOLS disabled": ["u5"]}},
                "file_type": {"summary": {"application/x-executable": ["u"]}},
            }}})
        if request.url.path == "/rest/file_object/uid3":
            # shape of FACT's full users_and_passwords result (captured from a real instance)
            entries = [{"username": "root", "type": "unix", "password_hash": "$6$saltsalt$abcdefghijkl", "password": "admin",
                        "full_entry": "root:$6$...", "error": None},
                       {"username": "bin", "type": "unix", "password_hash": "x", "password": None, "error": None},
                       {"username": "daemon", "type": "unix", "password_hash": "*", "password": None, "error": None}]
            return httpx.Response(200, json={"file_object": {"meta_data": {"hid": "/etc/shadow"}, "analysis": {
                "users_and_passwords": {"result": {"unix": entries, "http": [], "mosquitto": []}}}}})
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
    mitigations = sorted(t for t in titles if "Exploit mitigation" in t)
    assert mitigations == ["[FACT] Exploit mitigation: CANARY disabled"]  # good/neutral states are not weaknesses
    cert = next(f for f in res.findings if "SSLCertificate" in f.title)
    assert (cert.severity.value, cert.classification.value) == ("info", "info")
    creds = [f for f in res.findings if f.rule_id == "fact-users_and_passwords"]
    assert [f.title for f in creds] == ["[FACT] Password of 'root' recovered from its hash"]  # not bin ('x'), daemon ('*')
    assert "admin" not in str(creds[0].evidence)
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
            import time as _t
            analysis = {"current_analyses": {} if self.cancel else {"abc_123": {}},
                        "recently_canceled_analyses": {"abc_123": {"time_finished": _t.time()}} if self.cancel else {}}
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


def test_fact_resubmission_ignores_previous_runs_entries(settings, tmp_path, monkeypatch):
    """FACT UIDs are content hashes: an old 'cancelled' entry for the same file must not end a new run."""
    import time as _t
    settings.fact_url, settings.fact_poll_s, settings.fact_timeout_s = "http://fact.test", 0, 20
    fake = FakeFact()
    base_handler = fake.handler

    def handler(request):
        if request.url.path == "/rest/status":
            fake.status_calls += 1
            running = {"abc_123": {}} if fake.status_calls < 3 else {}
            return httpx.Response(200, json={"system_status": {"backend": {"analysis": {
                "current_analyses": running,
                "recently_canceled_analyses": {"abc_123": {"time_finished": _t.time() - 3600}},
                "recently_finished_analyses": {"abc_123": {"time_finished": _t.time()}} if not running else {}}}}})
        return base_handler(request)
    ad = fact.FactAdapter(settings)
    monkeypatch.setattr(ad, "_client", lambda: httpx.Client(base_url="http://fact.test",
                                                            transport=httpx.MockTransport(handler)))
    inp = tmp_path / "fw.bin"
    inp.write_bytes(b"firmware")
    res = ad.execute(ctx_for(settings, {"identification": {}}, tmp_path, input_path=inp))
    assert res.status == "completed", res.message
    assert fake.status_calls >= 3  # waited while FACT listed the new run as current


def test_cwe_checker_symbolises_flash_images_derived_from_elf(settings, tmp_path):
    """Bare-metal warnings on a flash image derived from an ELF are mapped back to its function symbols."""
    syms = cwe_checker.SymbolMap([[0x8004000, 0x40, "__start"], [0x8010000, 0x100, "mavlink_main"],
                                  [0x8010200, 0, "no_size"], ["bad", 1, "x"], [1, 2, 3]])
    assert syms.lookup(0x8004000) == "__start"
    assert syms.lookup(0x8010010) == "mavlink_main+0x10"
    assert syms.lookup(0x8010150) is None          # past the end of mavlink_main
    assert syms.lookup(0x8010208) == "no_size+0x8"  # unknown size: nearest preceding symbol
    assert syms.lookup(0x8000000) is None
    # shape of cwe_checker 0.9.0 bare-metal output (decimal 'addresses', hex 'tids')
    ws = [{"name": "CWE787", "version": "0.3", "addresses": [str(0x8010010)], "tids": ["instr_0x08010010_1"],
           "symbols": [], "other": [["For the object ID fun_0x08010000 @ sp:i32 access to the offset 0 (size 4) "
                                     "may overflow the upper object bound of 1."]],
           "description": f"(Out-of-bounds Write) Memory write at {0x8010010} may be out of bounds."}]
    f = cwe_checker.normalize(ws, "fw.elf > flash.bin", bare_metal=True, symbols=syms)[0]
    assert f.evidence[0].location == "0x8010010 (mavlink_main+0x10)"
    assert "function symbols of the ELF" in f.description and f.classification.value == "unverified"
    # the symbol table written by the sandbox is read through the work-directory check
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "symbols.json").write_text(json.dumps([[0x8010000, 0x100, "mavlink_main"]]))
    ctx = ctx_for(settings, {}, tmp_path)
    art = {"details": {"symbol_map": "files/symbols.json"}}
    assert cwe_checker._load_symbols(ctx, art).lookup(0x8010004) == "mavlink_main+0x4"
    assert cwe_checker._load_symbols(ctx, {"details": {"symbol_map": "../../etc/passwd"}}) is None
    assert cwe_checker._load_symbols(ctx, {"details": {}}) is None


def test_cwe_checker_plan_uses_flash_image_instead_of_cortex_m_elf(settings, tmp_path):
    ad = cwe_checker.CweCheckerAdapter(settings)
    man = {"extraction": {"artifacts": [
        {"id": 0, "name": "fw.elf", "format": "elf", "category": "executable", "size": 2000,
         "elf": {"machine": "EM_ARM", "arch": cwe_checker.CORTEX_M, "is_kernel_module": False}},
        {"id": 1, "name": "flash.bin", "format": "cortexm_raw", "size": 1000, "parent": 0,
         "details": {"flash_base": "0x8004000", "initial_sp": "0x20005c18", "derived_from_elf": True,
                     "symbol_map": "files/symbols.json"}},
        {"id": 2, "name": "/usr/bin/x", "format": "elf", "category": "executable", "size": 1000,
         "elf": {"machine": "EM_ARM", "arch": "ARM (32-bit)", "interpreter": "/lib/ld-linux-armhf.so.3",
                 "is_kernel_module": False}},
    ]}}
    targets, _ = ad.plan(ctx_for(settings, man, tmp_path))
    assert sorted(t["artifact"]["id"] for t in targets) == [1, 2]
    assert next(t for t in targets if t["artifact"]["id"] == 1)["bare_metal"]["flash_base_address"] == "0x8004000"


def test_fact_submits_files_of_filesystems_it_cannot_unpack(settings, tmp_path, monkeypatch):
    """FACT has no NuttX CROMFS unpacker: the files extracted from one are submitted as a tar."""
    import io
    import tarfile
    settings.fact_url = "http://fact.test"
    settings.fact_poll_s = 0
    settings.fact_timeout_s = 20
    uploads = []

    class Recording(FakeFact):
        def handler(self, request):
            if request.method == "PUT" and request.url.path == "/rest/firmware":
                uploads.append(json.loads(request.content))
            return super().handler(request)
    fake = Recording()
    ad = fact.FactAdapter(settings)
    monkeypatch.setattr(ad, "_client", lambda: httpx.Client(base_url="http://fact.test",
                                                            transport=httpx.MockTransport(fake.handler)))
    root = tmp_path / "files" / "00002_etc.cromfs.d"
    (root / "init.d").mkdir(parents=True)
    (root / "init.d" / "rcS").write_text("param set CBRK_IO_SAFETY 22027\n")
    (root / "extras").mkdir()
    (root / "extras" / "io.bin").write_bytes(b"\x00\x10\x00\x20")
    inp = tmp_path / "fw.px4"
    inp.write_bytes(b"{}")
    man = {"identification": {"platform": "PX4"}, "extraction": {
        "filesystems": [{"artifact_id": 2, "type": "cromfs", "root": "files/00002_etc.cromfs.d", "name": "etc.cromfs"}],
        "artifacts": [
            {"id": 0, "path": "<input>", "name": "fw.px4", "format": "json", "size": 2},
            {"id": 2, "path": "files/00001/etc.cromfs", "name": "etc.cromfs", "format": "cromfs", "size": 10, "parent_id": 0},
            {"id": 3, "path": "files/00002_etc.cromfs.d/init.d/rcS", "name": "/init.d/rcS", "origin": "extracted",
             "parent_id": 2, "size": 31, "mode": 0o644},
            {"id": 4, "path": "files/00002_etc.cromfs.d/extras/io.bin", "name": "/extras/io.bin", "origin": "extracted",
             "parent_id": 2, "size": 4, "mode": 0o755},
        ]}}
    res = ad.execute(ctx_for(settings, man, tmp_path, input_path=inp))
    assert res.status == "completed", res.message
    assert [u["file_name"] for u in uploads] == ["in.bin", "etc.cromfs.tar"]
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(uploads[1]["binary"]))) as tar:
        assert sorted(tar.getnames()) == ["extras/io.bin", "init.d/rcS"]
        assert tar.extractfile("init.d/rcS").read().startswith(b"param set")
        assert tar.getmember("extras/io.bin").mode == 0o755
    assert "files extracted from cromfs etc.cromfs" in res.message
    # a member replaced by a link (compromised sandbox) is not read: that submission fails, nothing leaks
    (root / "init.d" / "rcS").unlink()
    (root / "init.d" / "rcS").symlink_to(settings.data_dir)
    uploads.clear()
    res = ad.execute(ctx_for(settings, man, tmp_path, input_path=inp))
    assert len(uploads) == 1 and "not submitted" in res.message


def test_fwanalyzer_suid_offenders_name_the_actual_bit():
    """FwAnalyzer labels setuid and setgid alike ('File is SUID, not allowed'); evidence states the real bit
    from the archive metadata (as seen on Debian 11: /usr/bin/wall is setgid tty, /var/mail a setgid dir)."""
    report = {"offenders": {"/bin/su": ["File is SUID, not allowed"], "/usr/bin/wall": ["File is SUID, not allowed"],
                            "/var/mail": ["File is SUID, not allowed"], "/x": ["File is SUID, not allowed"]}}
    modes = {"/bin/su": (0o4755, False), "/usr/bin/wall": (0o2755, False), "/var/mail": (0o2775, True)}
    f = fwanalyzer.normalize(report, "rootfs", perms=True, modes=modes)[0]
    assert f.title == "[FwAnalyzer] setuid/setgid file not in allow-list (4)"
    ev = {e.location: e.value for e in f.evidence}
    assert ev["/bin/su"].endswith("[setuid file, mode 4755]")
    assert ev["/usr/bin/wall"].endswith("[setgid file, mode 2755]")
    assert ev["/var/mail"].endswith("[setgid directory, mode 2775]")
    assert ev["/x"] == "File is SUID, not allowed"  # mode unknown: FwAnalyzer's text only


def test_fact_mapping_of_real_debian_results():
    """Shapes and labels from FACT's real analysis of the Debian 11 armhf rootfs (2026-11-05)."""
    lib = "243518884420af9f2dace683339c6fa32c6d1d18754ce188affb36bf5f37e20c_1498044"
    fw = {"meta_data": {"number_of_included_files": 1, "total_files_in_firmware": 3311}, "analysis": {
        "unpacker": {"summary": {"unpacked": ["x"]}},
        "crypto_material": {"summary": {"SSLPrivateKey": [lib], "SshRsaPrivateKeyBlock": [lib]}},
        # stored from an earlier analysis that requested FACT's cwe_checker plug-in (UIDs are content hashes)
        "cwe_checker": {"summary": {"CWE476": ["a", "b"], "CWE676": ["c"]}},
        "cve_lookup": {"summary": {"OpenSSL 1.1.1k (CRITICAL)": ["t"]}},
    }}
    requested = {"crypto_material", "cve_lookup", "exploit_mitigations"}
    fs = fact.normalize(fw, "debian.tar.gz", [], requested=requested,
                        paths={lib: "/usr/lib/arm-linux-gnueabihf/libgnutls.so.30.29.1"})
    by_rule = {}
    for f in fs:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert "fact-cwe_checker" not in by_rule  # not requested in this run
    keys = by_rule["fact-crypto-library-key"]
    assert len(keys) == 2 and all((f.severity.value, f.classification.value) == ("info", "info") for f in keys)
    assert "libgnutls.so.30.29.1" in keys[0].evidence[0].location
    # a private key outside crypto libraries stays a high-severity finding
    other = fact.normalize(fw, "x", [], requested=requested, paths={lib: "/etc/ssl/private/device.key"})
    assert any(f.rule_id == "fact-crypto_material" and f.severity.value == "high" for f in other)
