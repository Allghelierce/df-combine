import pytest

from dfa.core.scanners.components import Component, assess, parse_version, version_in_range


def rules(manifest):
    return {f["rule_id"]: f for f in manifest["findings"]}


@pytest.fixture(scope="module")
def companion(fixtures, tmp_path_factory):
    from dfa.core.analyze import run
    from dfa.core.limits import Limits
    return run(fixtures["tar_gz"], "companion_rootfs.tar.gz", tmp_path_factory.mktemp("w"), Limits())


def test_secret_findings(companion):
    r = rules(companion)
    assert r["empty-password"]["severity"] == "critical"
    assert r["empty-password"]["classification"] == "detected"
    assert r["static-password-hash"]["title"].endswith("(MD5-crypt)")
    assert r["ssh-host-key"]["classification"] == "detected"
    assert r["hostapd-static-psk"]["severity"] == "high"  # short passphrase
    assert r["ssh-authorized-keys"]
    cred = r["hardcoded-credential-assignment"]
    assert cred["classification"] == "suspicious"


def test_secrets_are_redacted(companion):
    blob = str(companion["findings"])
    assert "drone1234" not in blob
    assert "tok_synthetic_0123456789abcdef" not in blob
    assert "$1$abcdefgh$0123456789abcdefghijkl" not in blob


def test_config_findings(companion):
    r = rules(companion)
    assert r["telnetd-shell-no-auth"]["severity"] == "critical"
    assert r["telnetd-shell-no-auth"]["classification"] == "suspicious"
    assert "sshd-permit-root-login" in r
    assert "world-writable-files" in r and "setuid-files" in r


def test_drone_findings(companion, fixtures, run_analysis):
    r = rules(companion)
    assert {"mavlink-router-tcp-server", "mavlink-router-udp-server", "mavproxy-network-output"} <= set(r)
    px4 = rules(run_analysis(fixtures["px4"]))
    assert px4["px4-cbrk_io_safety"]["classification"] == "detected"
    assert "px4-cbrk_usb_chk" in px4 and "px4-mav-broadcast" in px4
    ap = rules(run_analysis(fixtures["apj"]))
    assert "ardupilot-arming_check" in ap and "ardupilot-brd_safetyenable" in ap


def test_binary_findings(companion):
    r = rules(companion)
    if "elf-gets" not in r:
        pytest.skip("no C compiler available to build the ELF fixture")
    for rule in ("elf-no-nx", "elf-no-pie", "elf-no-relro", "elf-no-canary", "elf-dangerous-imports"):
        assert rule in r, rule


def test_components_and_kb(companion):
    comps = {(c["name"], c["version"]) for c in companion["components"]}
    assert ("busybox", "1.31.1") in comps and ("openssl", "1.0.1e") in comps and ("linux", "4.14.98") in comps
    outdated = [f for f in companion["findings"] if f["rule_id"].startswith("outdated-")]
    assert outdated and all(f["classification"] == "unverified" for f in outdated)
    assert any("CVE-2014-0160" in f["tags"] for f in outdated)


def test_no_finding_claims_confirmed(companion):
    for f in companion["findings"]:
        assert f["classification"] in ("detected", "suspicious", "unverified", "info")
        assert "confirmed" not in f["title"].lower()


@pytest.mark.parametrize("a,b", [("1.0.1f", "1.0.1g"), ("1.0.1", "1.0.1a"), ("8.9p1", "9.8p1"), ("1.1.1w", "3.0.0"),
                                 ("2022.82", "2022.83"), ("1.36.0-rc1", "1.36.0"), ("4.14.98", "5.10")])
def test_version_order(a, b):
    assert parse_version(a) < parse_version(b)


def test_version_ranges():
    hb = {"min": "1.0.1", "max_inclusive": "1.0.1f"}
    assert version_in_range("1.0.1e", hb) and version_in_range("1.0.1", hb)
    assert not version_in_range("1.0.1g", hb) and not version_in_range("1.0.0", hb)
    regre = {"min": "8.5p1", "max_exclusive": "9.8p1"}
    assert version_in_range("9.6p1", regre) and not version_in_range("9.8p1", regre)
    assert not version_in_range("8.4p1", regre)


def test_assess_no_match_for_current_versions():
    assert assess([Component("openssl", "3.0.13"), Component("busybox", "1.36.1"), Component("linux", "6.6.30")]) == []


def test_clean_text_has_no_findings(tmp_path, run_analysis):
    p = tmp_path / "readme.txt"
    p.write_text("This is a harmless release note for a flight controller.\nNo secrets here.\n")
    m = run_analysis(p)
    assert m["findings"] == []


def _scan_tree(tmp_path, files, run_analysis):
    import tarfile
    root = tmp_path / "tree"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    out = tmp_path / "t.tar"
    with tarfile.open(out, "w") as tf:
        tf.add(root, arcname=".")
    return {f["rule_id"]: f for f in run_analysis(out)["findings"]}


def test_stopping_telnet_is_not_enabling(tmp_path, run_analysis):
    r = _scan_tree(tmp_path, {"etc/init.d/S99secure": "#!/bin/sh\nkillall telnetd\n"}, run_analysis)
    assert "telnetd-enabled" not in r
    r = _scan_tree(tmp_path / "b", {"etc/init.d/S50telnet": "#!/bin/sh\n/usr/sbin/telnetd -p 23\n"}, run_analysis)
    assert "telnetd-enabled" in r


def test_more_credentials(tmp_path, run_analysis):
    r = _scan_tree(tmp_path, {
        "etc/wpa_supplicant/wpa_supplicant.conf": 'network={\n ssid="GCS"\n psk="supersecret99"\n}\n',
        "etc/wireguard/wg0.conf": "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/24\n",
        "root/.netrc": "machine updates.example.test login ci password hunter2\n",
        "root/.aws/credentials": "[default]\naws_access_key_id = X\naws_secret_access_key = Y\n",
    }, run_analysis)
    assert {"wpa-supplicant-psk", "wireguard-private-key", "credential-file"} <= set(r)
    assert "supersecret99" not in str(r) and "yAnz5TF+lXXJte14tji3zlMNq" not in str(r)
