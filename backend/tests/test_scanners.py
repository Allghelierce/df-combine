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


# --- Additional userland fingerprints -------------------------------------------------------------

NEW_FINGERPRINTS = ["curl", "nginx", "mosquitto", "openvpn", "iptables", "samba", "avahi", "ntp", "chrony",
                    "systemd", "sudo", "bash", "python", "lua", "libxml2", "expat", "libpng", "pcre2", "gstreamer",
                    "ffmpeg", "dbus", "bluez", "gnutls", "wolfssl", "libssh", "libssh2"]

FP_POSITIVE = [
    ("curl", "curl 8.5.0 (x86_64-pc-linux-gnu) %s", "8.5.0"),
    ("curl", "curl 7.88.1 (aarch64-unknown-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.11 zlib/1.2.13", "7.88.1"),
    ("nginx", "<hr><center>nginx/1.24.0</center>", "1.24.0"),
    ("mosquitto", "1700000000: mosquitto version 2.0.18 starting", "2.0.18"),
    ("openvpn", "OpenVPN 2.6.8 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL]", "2.6.8"),
    ("openvpn", "OpenVPN 2.5.9 mipsel-openwrt-linux-gnu [SSL (mbed TLS)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]",
     "2.5.9"),
    ("iptables", "# Generated by iptables-save v1.8.9 on Tue Oct  3 10:00:00 2023", "1.8.9"),
    ("iptables", "iptables v1.8.9 (nf_tables)", "1.8.9"),
    ("samba", "Samba 4.17.12-Debian", "4.17.12"),
    ("samba", "[2024/01/01 10:00:00,  0] ../../source3/smbd/server.c:1741(main)  smbd version 4.17.12-Debian started.",
     "4.17.12"),
    ("avahi", "avahi-daemon 0.8 starting up.", "0.8"),
    ("avahi", "avahi 0.8", "0.8"),
    ("ntp", "ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1): Starting", "4.2.8p15"),
    ("chrony", "chronyd (chrony) version 4.5 (+CMDMON +NTP +REFCLOCK +RTC)", "4.5"),
    ("systemd", "%ssystemd 252%s (252.22-1~deb12u1)", "252"),
    ("systemd", "systemd 252.22-1~deb12u1 running in %ssystem mode (%s)", "252.22"),
    ("sudo", "Sudo version 1.9.13p3", "1.9.13p3"),
    ("bash", "GNU bash, version 5.2.15(1)-release (x86_64-pc-linux-gnu)", "5.2.15"),
    ("bash", "@(#)Bash version 5.2.15(1) release GNU", "5.2.15"),
    ("python", "Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0] on linux", "3.11.2"),
    ("python", "Python 2.7.18 (default, Apr 20 2020, 19:34:11)", "2.7.18"),
    ("python", "Python 3.12.0rc1", "3.12.0rc1"),
    ("lua", "$LuaVersion: Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio $", "5.3.6"),
    ("libxml2", "/usr/lib/arm-linux-gnueabihf/libxml2.so.2.9.14", "2.9.14"),
    ("expat", "expat_2.5.0", "2.5.0"),
    ("libpng", " libpng version 1.6.39 - November 20, 2022", "1.6.39"),
    ("pcre2", "PCRE2 version 10.42 2022-12-11", "10.42"),
    ("pcre2", "10.42 2022-12-11", "10.42"),
    ("gstreamer", "GStreamer 1.22.0", "1.22.0"),
    ("gstreamer", "GStreamer Core Library version 1.22.0", "1.22.0"),
    ("ffmpeg", "ffmpeg version 5.1.4-0+deb12u1 Copyright (c) 2000-2023 the FFmpeg developers", "5.1.4"),
    ("dbus", "LIBDBUS_PRIVATE_1.14.10", "1.14.10"),
    ("bluez", "Bluetooth daemon 5.66", "5.66"),
    ("gnutls", "Enabled GnuTLS 3.7.9 logging...", "3.7.9"),
    ("gnutls", "curl 7.88.1 (arm-unknown-linux-gnueabihf) libcurl/7.88.1 GnuTLS/3.7.9 zlib/1.2.13", "3.7.9"),
    ("wolfssl", "wolfSSL 5.6.4", "5.6.4"),
    ("wolfssl", "/home/build/wolfssl-5.6.4-stable/src/ssl.c", "5.6.4"),
    ("libssh", "SSH-2.0-libssh_0.10.5", "0.10.5"),
    ("libssh2", "SSH-2.0-libssh2_1.11.0", "1.11.0"),
]

FP_NEGATIVE = [
    ("curl", "libcurl/8.5.0 OpenSSL/3.0.13"),
    ("nginx", "Server: nginx"),
    ("mosquitto", "mosquitto version %s starting"),
    ("openvpn", "OpenVPN Connect 3.4.2 (build 7890)"),
    ("iptables", "iptables v%s: %s"),
    ("samba", "server string = %h server (Samba, Ubuntu)"),
    ("avahi", "Found user 'avahi' (UID 105) and group 'avahi' (GID 110)."),
    ("ntp", "ntpd ntpsec-1.2.2 2023-02-08T18:00:00Z"),
    ("chrony", "chronyd (chrony) version %s (%s)"),
    ("systemd", "Requires systemd 252 or newer"),
    ("sudo", "Sudoers file grammar version 48"),
    ("bash", "GNU bash, version %s (%s)"),
    ("python", "requires Python 3.8.10 or newer"),
    ("lua", "LuaJIT 2.1.0-beta3 -- Copyright (C) 2005-2017 Mike Pall. http://luajit.org/"),
    ("libxml2", "libxml2.so.2"),
    ("expat", "libexpat.so.1.8.10"),
    ("libpng", "libpng warning: iCCP: known incorrect sRGB profile"),
    ("pcre2", "PCRE version 8.45 2021-06-15"),
    ("gstreamer", "GStreamer 1.0 Base Plugins"),
    ("ffmpeg", "FFmpeg version N-111795-g5f4b1d2"),
    ("dbus", "LIBDBUS_1_3"),
    ("bluez", "Bluetooth: Core ver 2.22"),
    ("gnutls", "GNUTLS_3_6_3"),
    ("wolfssl", "libwolfssl.so.35.5.1"),
    ("libssh", "SSH-2.0-libssh2_1.11.0"),
    ("libssh2", "SSH-2.0-libssh_0.10.5"),
    # Prose mentioning a version is not a fingerprint.
    ("python", "# introduced in Python 3.7.0"),
    ("samba", "New keywords for Samba 2.0.6"),
    ("openvpn", "Upgrade to OpenVPN 2.6.8 or later"),
    ("avahi", "avahi 0.6.31 and earlier are affected"),
    ("gstreamer", "Fixed in GStreamer 1.22.1 and later"),
    ("bluez", "Requires BlueZ 5.50 or newer"),
    ("gnutls", "Requires GnuTLS 3.6.0 or later"),
    ("wolfssl", "wolfSSL 5.6.4 fixes several issues"),
]


def test_new_fingerprints_are_registered_and_covered():
    from dfa.core.scanners.components import FINGERPRINTS
    names = [n for n, _ in FINGERPRINTS]
    assert len(names) == len(set(names))
    assert set(NEW_FINGERPRINTS) <= set(names)
    assert {n for n, _, _ in FP_POSITIVE} == set(NEW_FINGERPRINTS)
    assert {n for n, _ in FP_NEGATIVE} == set(NEW_FINGERPRINTS)


@pytest.mark.parametrize("name,line,version", FP_POSITIVE)
def test_fingerprint_positive(name, line, version):
    from dfa.core.scanners.components import match_line
    hits = [v for n, v in match_line(line) if n == name]
    assert hits == [version]


@pytest.mark.parametrize("name,line", FP_NEGATIVE)
def test_fingerprint_near_miss(name, line):
    from dfa.core.scanners.components import match_line
    assert [v for n, v in match_line(line) if n == name] == []


def test_curl_banner_also_yields_libcurl():
    from dfa.core.scanners.components import match_line
    hits = set(match_line("curl 7.88.1 (aarch64-unknown-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.11"))
    assert {("curl", "7.88.1"), ("libcurl", "7.88.1")} <= hits


# --- Package databases (dpkg / opkg) --------------------------------------------------------------

DPKG_STATUS = """\
Package: openssl
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 1393
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Architecture: armhf
Version: 1.1.1n-0+deb11u5
Depends: libc6 (>= 2.34), libssl1.1 (>= 1.1.1)
Conffiles:
 /etc/ssl/openssl.cnf 5d6b2d3e2a2b1c0f8f6e5d4c3b2a1908
Description: Secure Sockets Layer toolkit - cryptographic utility
 This package is part of the OpenSSL project's implementation of the SSL
 and TLS cryptographic protocols. GNU bash, version 9.9.9(1)-release
 .
 Samba 9.9.9 nginx/9.9.9

Package: openssh-server
Status: install ok installed
Architecture: armhf
Source: openssh
Version: 1:9.2p1-2+deb12u3

Package: libxml2
Status: install ok installed
Architecture: armhf
Version: 2.9.14+dfsg-1.3

Package: busybox
Status: install ok installed
Version: 1:1.36.1-1

Package: libc6
Status: hold ok installed
Version: 2.36-9+deb12u4

Package: zlib1g
Status: install ok installed
Version: 1:1.2.13.dfsg-1

Package: sudo
Status: deinstall ok config-files
Version: 1.9.5p2-3

Package: bash
Status: install reinstreq half-installed
Version: 5.2.15-2+b2

Package: vim-tiny
Status: install ok installed
Version: 2:9.0.1378-2
"""

OPKG_STATUS = """\
Package: dropbear
Version: 2022.82-6
Depends: libc
Conffiles:
 /etc/config/dropbear 3ea4ad7d3f7a0f1b2c3d4e5f60718293
Status: install user installed
Architecture: mipsel_24kc
Installed-Time: 1700000000

Package: libopenssl3
Version: 3.0.12-1
Depends: libc, libatomic1
Status: install ok installed
Architecture: mipsel_24kc

Package: libwolfssl5.6.4.e624513f
Version: 5.6.4-stable-1
Status: install user installed
Architecture: mipsel_24kc

Package: hostapd-common
Version: 2023-09-08-e5ccbfc6-6
Status: install user installed
Architecture: mipsel_24kc

Package: kmod-usb-core
Version: 5.15.137-1
Status: install user installed
Architecture: mipsel_24kc

Package: mosquitto-ssl
Version: 2.0.18-1
Status: install user not-installed
Architecture: mipsel_24kc
"""


@pytest.mark.parametrize("raw,upstream", [
    ("1.1.1n-0+deb11u5", "1.1.1n"), ("1:9.2p1-2+deb12u3", "9.2p1"), ("2.9.14+dfsg-1.3", "2.9.14"),
    ("1.36.1-1", "1.36.1"), ("1:1.2.13.dfsg-1", "1.2.13"), ("252.22-1~deb12u1", "252.22"),
    ("1:4.2.8p15+dfsg-2~1.2.2+dfsg1-1+deb12u1", "4.2.8p15"), ("2022.82-6", "2022.82"), ("5.6.4-stable-1", "5.6.4"),
    ("2.10", "2.10"), ("2023-09-08-e5ccbfc6-6", None), ("", None),
])
def test_upstream_version(raw, upstream):
    from dfa.core.scanners.components import upstream_version
    assert upstream_version(raw) == upstream


def test_package_component_mapping():
    from dfa.core.scanners.components import PACKAGE_COMPONENTS, package_component
    assert PACKAGE_COMPONENTS["libc6"] == "glibc"
    for pkg, comp in [("libssl1.1", "openssl"), ("libssl3t64", "openssl"), ("libopenssl3", "openssl"),
                      ("openssh-sftp-server", "openssh"), ("hostapd-basic-openssl", "hostapd"),
                      ("wpasupplicant", "wpa_supplicant"), ("wpa-supplicant-mini", "wpa_supplicant"),
                      ("openvpn-mbedtls", "openvpn"), ("python3.11-minimal", "python"), ("libpython3.11", "python"),
                      ("lua5.3", "lua"), ("liblua5.3-0", "lua"), ("libavcodec59", "ffmpeg"),
                      ("libwolfssl5.6.4.e624513f", "wolfssl"), ("libmbedtls14", "mbedtls"), ("libc6:armhf", "glibc")]:
        assert package_component(pkg) == comp, pkg
    for pkg in ("vim-tiny", "libssl-dev", "openvpn-easy-rsa", "lua-cjson", "lua5.1-policy", "python3-requests"):
        assert package_component(pkg) is None, pkg


def test_parse_dpkg_status():
    from dfa.core.scanners.components import parse_package_status
    got = parse_package_status(DPKG_STATUS)
    assert sorted(got) == sorted([("openssl", "1.1.1n"), ("openssh", "9.2p1"), ("libxml2", "2.9.14"),
                                  ("busybox", "1.36.1"), ("glibc", "2.36"), ("zlib", "1.2.13")])
    names = {n for n, _ in got}
    assert "sudo" not in names  # deinstall ok config-files
    assert "bash" not in names  # half-installed
    assert "vim-tiny" not in names and "vim" not in names  # unmapped


def test_parse_dpkg_status_crlf_and_no_trailing_newline():
    from dfa.core.scanners.components import parse_package_status
    text = "Package: curl\r\nStatus: install ok installed\r\nVersion: 7.88.1-10+deb12u5"
    assert parse_package_status(text) == [("curl", "7.88.1")]


def test_parse_opkg_status():
    from dfa.core.scanners.components import parse_package_status
    got = sorted(parse_package_status(OPKG_STATUS))
    assert got == [("dropbear", "2022.82"), ("openssl", "3.0.12"), ("wolfssl", "5.6.4")]


def _fingerprint_tree(tmp_path, files):
    import tarfile

    from dfa.core.extract import Extractor
    from dfa.core.limits import Limits
    from dfa.core.scanners.base import ScanContext, build_display_paths
    from dfa.core.scanners.components import fingerprint
    root = tmp_path / "tree"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    out = tmp_path / "rootfs.tar"
    with tarfile.open(out, "w") as tf:
        tf.add(root, arcname=".")
    ex = Extractor(tmp_path / "work", Limits())
    arts = ex.run(out, "rootfs.tar").artifacts
    ctx = ScanContext(artifacts=arts, paths={a.id: ex.path_of(a.id) for a in arts},
                      display=build_display_paths(arts), limits=Limits())
    return fingerprint(ctx)


def test_fingerprint_reads_dpkg_status(tmp_path):
    comps = _fingerprint_tree(tmp_path, {
        "var/lib/dpkg/status": DPKG_STATUS,
        "etc/motd": "Welcome. BusyBox v1.36.1 (2023-11-07 18:53:16 UTC) multi-call binary.\n",
    })
    by_key = {(c.name, c.version): c for c in comps}
    assert len(by_key) == len(comps)  # one entry per (name, version)
    ssl = by_key[("openssl", "1.1.1n")]
    assert ssl.method == "package-db"
    assert len(ssl.sources) == 1 and ssl.sources[0].endswith("/var/lib/dpkg/status")
    assert by_key[("openssh", "9.2p1")].method == "package-db"
    # Found both in the package DB and by string match: merged into one component with both sources.
    bb = by_key[("busybox", "1.36.1")]
    assert len(bb.sources) == 2
    assert any(s.endswith("/var/lib/dpkg/status") for s in bb.sources)
    assert any(s.endswith("/etc/motd") for s in bb.sources)
    # Free-text descriptions inside the DB are not string-scanned.
    assert not any(c.version == "9.9.9" for c in comps)


def test_fingerprint_reads_opkg_status(tmp_path):
    comps = _fingerprint_tree(tmp_path, {"usr/lib/opkg/status": OPKG_STATUS})
    got = {(c.name, c.version, c.method) for c in comps}
    assert ("dropbear", "2022.82", "package-db") in got and ("wolfssl", "5.6.4", "package-db") in got


def test_prefix_reads_do_not_load_whole_file(tmp_path, monkeypatch):
    """Scanners only need a bounded prefix: a multi-GB artifact must never be read whole into memory."""
    from pathlib import Path

    from dfa.core.extract import Artifact
    from dfa.core.limits import Limits
    from dfa.core.scanners.base import ScanContext
    from dfa.core.scanners.secrets import _rebuild_pem_text

    big = tmp_path / "big.log"
    big.write_bytes(b"-----BEGIN PRIVATE KEY-----\n" + b"A" * (3 * 1024**2))
    art = Artifact(id=1, path="files/big.log", name="/var/log/big.log", size=big.stat().st_size, sha256="0",
                   format="text", format_description="text", parent_id=None, depth=0, origin="extracted")
    ctx = ScanContext(artifacts=[art], paths={1: big}, display={1: "big.log"},
                      limits=Limits(max_scan_bytes_per_file=1024**2))

    def whole_read(self):
        raise AssertionError(f"whole-file read of {self}")

    monkeypatch.setattr(Path, "read_bytes", whole_read)
    text = ctx.text(art)
    assert text is not None and len(text) == 2 * 1024**2  # ScanContext.text default cap
    pem = _rebuild_pem_text(ctx, art)
    assert pem.startswith("-----BEGIN PRIVATE KEY-----") and len(pem) == 1024**2
