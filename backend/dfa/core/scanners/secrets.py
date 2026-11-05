"""Hardcoded credentials, private keys and tokens."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

from ..findings import Classification as C
from ..findings import Confidence as K
from ..findings import Evidence, Finding, redact
from ..findings import Severity as S
from .base import ScanContext

TOOL = "builtin:secrets"

PEM_RE = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----"
    r"([\s\S]{0,8192}?)-----END \1-----")
PEM_HEADER_RE = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----")

TOKEN_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS access key ID", S.high),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), "Google API key", S.medium),
    ("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), "GitHub token", S.high),
    ("slack-token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "Slack token", S.medium),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"), "JSON Web Token", S.medium),
]

# key = value assignments that look like credentials in configs/scripts.
ASSIGN_RE = re.compile(
    r"""(?ix)^\s*(?:export\s+)?
    (?P<key>[\w.\-]*(?:passwd|password|passphrase|pwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)[\w.\-]*)
    \s*[:=]\s*
    (?P<q>["']?)(?P<val>[^"'\s#;]{4,128})(?P=q)""")
PLACEHOLDERS = {"none", "null", "nil", "true", "false", "yes", "no", "xxxx", "xxxxxx", "******", "<password>",
                "changeme_please", "required", "optional", "string", "example", "your_password", "password_here",
                # configuration keywords seen in real root filesystems (nsswitch sources, Perl build flags,
                # PAM profile fields), not credentials
                "define", "undef", "files", "compat", "systemd", "primary", "additional", "sufficient",
                "requisite", "include", "nis", "nisplus", "ldap", "winbind", "cache", "myhostname", "resolve"}
# Files whose credential-looking keys are configuration vocabulary, not secrets
NOT_CREDENTIAL_FILES = re.compile(r"(^|/)(nsswitch\.conf|Config(_heavy)?\.p[lm]|Config_git\.pl)$|/pam-configs/|"
                                  r"/usr/share/(doc|man|info|locale)/")
WEAK_VALUES = {"admin", "password", "root", "1234", "12345", "123456", "12345678", "toor", "default", "changeme",
               "dji12345", "drone", "pass", "letmein", "ardupilot", "px4"}

SHADOW_HASH = {
    "$1$": "MD5-crypt", "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt", "$5$": "SHA-256-crypt",
    "$6$": "SHA-512-crypt", "$y$": "yescrypt", "$7$": "scrypt", "$gy$": "gost-yescrypt",
}
WEAK_HASHES = {"MD5-crypt", "DES-crypt"}


def _hash_kind(h: str) -> str:
    for prefix, name in SHADOW_HASH.items():
        if h.startswith(prefix):
            return name
    if len(h) == 13 and re.fullmatch(r"[./0-9A-Za-z]{13}", h):
        return "DES-crypt"
    return "unknown"


def scan(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    for art in ctx.content_artifacts():
        path = ctx.fs_path(art)
        text = ctx.text(art)
        base = path.rsplit("/", 1)[-1]
        if text is not None:
            out += _pem_findings(ctx, art, text, in_binary=False)
            if base in ("shadow", "shadow-", "passwd", "passwd-") and "/etc/" in path:
                out += _account_findings(ctx, art, text, base.rstrip("-"))
            if base == "authorized_keys" or base == "authorized_keys2":
                keys = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
                if keys:
                    out.append(Finding(
                        title="Pre-installed SSH authorized_keys",
                        description=(f"{len(keys)} public key(s) are authorised for SSH login out of the box. "
                                     "Whoever holds the matching private key can log in to every device "
                                     "running this image."),
                        severity=S.medium, classification=C.detected, confidence=K.high, source_tool=TOOL,
                        rule_id="ssh-authorized-keys", affected_component=ctx.where(art),
                        remediation="Remove vendor keys from the image; provision per-device keys at deployment.",
                        evidence=[Evidence("config", k[:60] + ("..." if len(k) > 60 else ""), path) for k in keys[:5]],
                        cwe="CWE-798"))
            if base == "hostapd.conf" or base.endswith("hostapd.conf"):
                out += _hostapd_findings(ctx, art, text)
            if base.startswith("wpa_supplicant") and base.endswith(".conf"):
                out += _wpa_supplicant_findings(ctx, art, text)
            if base.endswith(".conf") and "[Interface]" in text and "PrivateKey" in text:
                out += _wireguard_findings(ctx, art, text)
            if base in CREDENTIAL_FILES or path.endswith("/.aws/credentials"):
                out += _credential_file(ctx, art, text, base)
            out += _assignment_findings(ctx, art, text)
            out += _token_findings(ctx, art, ((0, ln) for ln in text.splitlines()), in_binary=False)
        else:
            # Binary content: only high-signal patterns (PEM blocks, tokens). Regions carved verbatim into child
            # artifacts are left to those (a key in a stored zip member is reported once, for the member).
            strings = [(o, s) for o, s in ctx.strings(art) if ctx.outside_children(art, o)]
            joined = "\n".join(s for _, s in strings if "PRIVATE KEY" in s or "-----" in s or len(s) > 60)
            if "PRIVATE KEY" in joined:
                out += _pem_findings(ctx, art, _rebuild_pem_text(ctx, art), in_binary=True)
            out += _token_findings(ctx, art, strings, in_binary=True)
    return out


def _rebuild_pem_text(ctx: ScanContext, art) -> str:
    raw = ctx.paths[art.id].read_bytes()[: ctx.limits.max_scan_bytes_per_file]
    if copied := ctx.copied.get(art.id):
        raw = bytearray(raw)
        for start, end in copied:
            raw[start:end] = bytes(len(raw[start:end]))  # carved into a child: analysed there
    return raw.decode("latin-1")


# Cryptographic toolkits embed public known-answer/self-test keys (e.g. GnuTLS's FIPS self-tests in
# crypto-selftests-pk.c). Such keys are present but are not device secrets.
CRYPTO_LIBRARY = re.compile(r"(^|/)lib(gnutls|crypto|ssl|mbedcrypto|mbedtls|mbedx509|nettle|hogweed|wolfssl|gcrypt|"
                            r"tomcrypt|sodium|nss3|softokn3|freebl3)[\w.+-]*\.so(\.[\d.]+)?$")
_B64_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_ARMOR_HEADER = re.compile(r"^(Proc-Type|DEK-Info|Comment|Version|Hash|Charset)\s*:", re.I)


def pem_body(raw: str) -> str | None:
    """The base64 payload of a PEM/armored block, or None if the content between the markers is not one
    (e.g. other string constants that sit between a library's BEGIN/END literals)."""
    lines = [ln.strip() for ln in raw.replace("\r", "").split("\n")]
    lines = [ln for ln in lines if ln and not _ARMOR_HEADER.match(ln)]
    if lines and lines[-1].startswith("=") and len(lines[-1]) == 5:  # OpenPGP armor checksum
        lines = lines[:-1]
    if not lines or not all(_B64_LINE.fullmatch(ln) for ln in lines):
        return None
    body = "".join(lines)
    try:
        base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (ValueError, binascii.Error):
        return None
    return body


def _pem_findings(ctx: ScanContext, art, text: str, in_binary: bool) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    base = path.rsplit("/", 1)[-1]
    for m in PEM_RE.finditer(text):
        kind = m.group(1)
        body = pem_body(m.group(2))
        encrypted = "ENCRYPTED" in kind or "Proc-Type: 4,ENCRYPTED" in m.group(2) or "Proc-Type:4,ENCRYPTED" in m.group(2)
        valid = body is not None and len(body) >= 64
        if not valid and in_binary:
            continue  # PEM marker strings of a parser/library (header and footer constants), not a key
        fp = hashlib.sha256((body or "").encode()).hexdigest()[:16]
        host_key = bool(re.search(r"(ssh_host_.*_key|dropbear_.*host_key)$", base))
        if host_key:
            title = "SSH host private key embedded in image"
            desc = ("An SSH host key is shipped inside the firmware. Every device built from this image "
                    "shares the same host identity, enabling impersonation/MITM of any unit.")
            rem = "Generate SSH host keys on first boot instead of shipping them in the image."
        else:
            title = "Private key embedded in firmware" + (" (encrypted)" if encrypted else "")
            desc = (f"A PEM '{kind}' block was found. Anyone with access to the firmware can extract it; "
                    "if it is used for TLS, code signing, telemetry or authentication it must be treated "
                    "as compromised.")
            rem = ("Remove private keys from the firmware image. Provision unique per-device keys "
                   "(ideally in a secure element) and rotate any key that has shipped.")
        sev = S.high if not encrypted else S.medium
        if not valid:
            out.append(Finding(title="Private key marker without a plausible key body",
                               description="A PEM private key header was found but the body is too short "
                                           "or malformed; it may be a test vector or a format string.",
                               severity=S.low, classification=C.suspicious, confidence=K.low, source_tool=TOOL,
                               rule_id="pem-private-key-malformed", affected_component=ctx.where(art),
                               remediation="Review the referenced file manually.",
                               evidence=[Evidence("string", f"-----BEGIN {kind}-----", path)], cwe="CWE-321"))
            continue
        if in_binary and CRYPTO_LIBRARY.search(path):
            out.append(Finding(
                title="Self-test key material in a cryptographic library",
                description=(f"'{base}' embeds a complete PEM '{kind}' block. Cryptographic libraries ship public "
                             "known-answer/self-test keys (GnuTLS, for example, for its FIPS self-tests); such a key "
                             "is not a device secret. Confirm the key is not used for device identity, signing or TLS."),
                severity=S.info, classification=C.info, confidence=K.medium, source_tool=TOOL,
                rule_id="crypto-library-test-key", affected_component=ctx.where(art),
                remediation="No action if this is the library's built-in self-test key.",
                evidence=[Evidence("string", f"-----BEGIN {kind}----- (body sha256 prefix {fp}, {len(body)} b64 chars)",
                                   path + f" @ offset {m.start():#x}")],
                cwe="CWE-321", tags=["crypto", "self-test"]))
            continue
        out.append(Finding(
            title=title, description=desc, severity=sev, classification=C.detected,
            confidence=K.high if not in_binary else K.medium, source_tool=TOOL,
            rule_id="ssh-host-key" if host_key else "pem-private-key", affected_component=ctx.where(art),
            remediation=rem,
            evidence=[Evidence("string", f"-----BEGIN {kind}----- (body sha256 prefix {fp}, {len(body or '')} b64 chars)",
                               path + (f" @ offset {m.start():#x}" if in_binary else ""))],
            cwe="CWE-321", references=["https://cwe.mitre.org/data/definitions/321.html"],
            tags=["credentials", "crypto"]))
    if in_binary or out:
        return out
    hdr = PEM_HEADER_RE.search(text)
    if hdr:  # header without matching footer (truncated)
        out.append(Finding(title="Truncated private key block", description="A PEM private key header was found "
                           "without a matching footer.", severity=S.low, classification=C.suspicious,
                           confidence=K.low, source_tool=TOOL, rule_id="pem-private-key-truncated",
                           affected_component=ctx.where(art), remediation="Review the file manually.",
                           evidence=[Evidence("string", hdr.group(0), path)], cwe="CWE-321"))
    return out


def _account_findings(ctx: ScanContext, art, text: str, kind: str) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 2 or not parts[0] or line.startswith("#"):
            continue
        user, pw = parts[0], parts[1]
        shell = parts[6] if kind == "passwd" and len(parts) > 6 else ""
        if kind == "passwd" and pw in ("x", "*", "!", "!!"):
            continue
        if kind == "passwd" and shell.endswith(("nologin", "false")):
            continue
        if pw == "":
            out.append(Finding(
                title=f"Account '{user}' has an empty password",
                description=(f"/etc/{kind} contains an entry for '{user}' with an empty password field. "
                             "Depending on PAM/BusyBox login configuration, this allows login without a password "
                             "on any console or network service that authenticates against it."),
                severity=S.critical if user == "root" else S.high, classification=C.detected, confidence=K.high,
                source_tool=TOOL, rule_id="empty-password", affected_component=ctx.where(art),
                remediation="Lock the account ('!' or '*') or set a unique per-device password at provisioning.",
                evidence=[Evidence("config", f"{user}::{':'.join(parts[2:4])}...", path)], cwe="CWE-258",
                tags=["credentials"]))
            continue
        if pw.startswith(("!", "*")) or pw in ("x",):
            continue
        hk = _hash_kind(pw)
        weak = hk in WEAK_HASHES
        loc = "/etc/passwd (world-readable)" if kind == "passwd" else "/etc/shadow"
        out.append(Finding(
            title=f"Static password hash for '{user}' shipped in image" + (f" ({hk})" if weak else ""),
            description=(f"A {hk} password hash for '{user}' is stored in {loc}. Every device running this "
                         "image shares the same credential; offline cracking of the hash yields access to all "
                         "of them." + (" The hash algorithm is weak and fast to brute-force." if weak else "")),
            severity=S.high if (weak or kind == "passwd") else S.medium,
            classification=C.detected, confidence=K.high, source_tool=TOOL,
            rule_id="static-password-hash", affected_component=ctx.where(art),
            remediation=("Do not ship shared credentials. Lock interactive accounts and provision unique "
                         "per-device credentials; use yescrypt/SHA-512-crypt if passwords are required."),
            evidence=[Evidence("config", f"{user}:{redact(pw, 4)}", path)], cwe="CWE-798",
            references=["https://cwe.mitre.org/data/definitions/798.html"], tags=["credentials"]))
    return out


def _hostapd_findings(ctx: ScanContext, art, text: str) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    lines = {ln.split("=", 1)[0].strip(): ln.split("=", 1)[1].strip()
             for ln in text.splitlines() if "=" in ln and not ln.strip().startswith("#")}
    if "wpa_passphrase" in lines:
        val = lines["wpa_passphrase"]
        weak = val.lower() in WEAK_VALUES or len(val) < 10
        out.append(Finding(
            title="Static Wi-Fi passphrase in access point configuration",
            description=("hostapd.conf contains a fixed WPA passphrase. All drones/companion computers built from "
                         "this image expose an access point with the same key, so anyone who extracts the "
                         "firmware can join the control/telemetry network."
                         + (" The passphrase is short or a common default." if weak else "")),
            severity=S.high if weak else S.medium, classification=C.detected, confidence=K.high, source_tool=TOOL,
            rule_id="hostapd-static-psk", affected_component=ctx.where(art),
            remediation="Generate a unique Wi-Fi passphrase per device at provisioning time.",
            evidence=[Evidence("config", f"wpa_passphrase={redact(val)}", path)], cwe="CWE-798",
            tags=["credentials", "wireless"]))
    if lines.get("ssid") and not any(k in lines for k in ("wpa", "wpa_passphrase", "wpa_psk", "wep_key0", "auth_algs_sae")):
        out.append(Finding(
            title="Open (unencrypted) Wi-Fi access point", description="hostapd.conf defines an SSID without WPA "
            "settings; the wireless link (often carrying MAVLink/video) would be unauthenticated and unencrypted.",
            severity=S.high, classification=C.detected, confidence=K.medium, source_tool=TOOL,
            rule_id="hostapd-open-network", affected_component=ctx.where(art),
            remediation="Enable WPA2/WPA3 (wpa=2, rsn_pairwise=CCMP or SAE).",
            evidence=[Evidence("config", f"ssid={lines['ssid']}", path)], cwe="CWE-319", tags=["wireless"]))
    elif lines.get("wpa") == "0" or any(k.startswith("wep_key") for k in lines):
        out.append(Finding(
            title="Weak Wi-Fi security (WEP or WPA disabled)", description="hostapd.conf uses WEP or disables WPA.",
            severity=S.high, classification=C.detected, confidence=K.high, source_tool=TOOL,
            rule_id="hostapd-weak-security", affected_component=ctx.where(art),
            remediation="Use WPA2-CCMP or WPA3-SAE.", evidence=[Evidence("config", "wpa=0 / wep_key*", path)],
            cwe="CWE-326", tags=["wireless"]))
    return out


CREDENTIAL_FILES = {".netrc": "netrc machine credentials", ".git-credentials": "Git credentials",
                    "credentials": "cloud credentials", ".pgpass": "PostgreSQL passwords",
                    ".my.cnf": "MySQL client credentials"}


def _wpa_supplicant_findings(ctx: ScanContext, art, text: str) -> list[Finding]:
    path = ctx.fs_path(art)
    hits = re.findall(r'^\s*psk\s*=\s*"?([^"\n]{8,63})"?\s*$', text, re.M)
    if not hits:
        return []
    return [Finding(
        title="Static Wi-Fi client passphrase in wpa_supplicant configuration",
        description=(f"{len(hits)} network PSK(s) are stored in the image. Anyone with the firmware learns the "
                     "credentials of the network the drone/companion joins (often the operator's GCS network)."),
        severity=S.medium, classification=C.detected, confidence=K.high, source_tool=TOOL,
        rule_id="wpa-supplicant-psk", affected_component=ctx.where(art),
        remediation="Provision Wi-Fi credentials per deployment instead of baking them into the image.",
        evidence=[Evidence("config", f"psk={redact(h)}", path) for h in hits[:5]], cwe="CWE-798",
        tags=["credentials", "wireless"])]


def _wireguard_findings(ctx: ScanContext, art, text: str) -> list[Finding]:
    path = ctx.fs_path(art)
    m = re.search(r"^\s*PrivateKey\s*=\s*([A-Za-z0-9+/]{42,44}=?)\s*$", text, re.M)
    if not m:
        return []
    return [Finding(
        title="WireGuard private key embedded in image",
        description="A WireGuard interface private key is shipped in the firmware. Every unit shares the VPN "
                    "identity; anyone holding the image can impersonate devices on the VPN (often the telemetry "
                    "or remote-control backhaul).",
        severity=S.high, classification=C.detected, confidence=K.high, source_tool=TOOL,
        rule_id="wireguard-private-key", affected_component=ctx.where(art),
        remediation="Generate per-device WireGuard keys at provisioning; rotate the shipped key.",
        evidence=[Evidence("config", f"PrivateKey = {redact(m.group(1), 4)}", path)], cwe="CWE-321",
        tags=["credentials", "crypto", "network"])]


def _credential_file(ctx: ScanContext, art, text: str, base: str) -> list[Finding]:
    path = ctx.fs_path(art)
    if not text.strip():
        return []
    label = CREDENTIAL_FILES.get(base, "cloud credentials")
    if base == "credentials" and "aws_secret_access_key" not in text and "/.aws/" not in path:
        return []
    return [Finding(
        title=f"Credential file left in image ({label})", description=f"'{path}' stores {label} in clear text.",
        severity=S.high, classification=C.detected, confidence=K.medium, source_tool=TOOL,
        rule_id="credential-file", affected_component=ctx.where(art),
        remediation="Remove developer/build credentials from the image and rotate them.",
        evidence=[Evidence("path", path)], cwe="CWE-798", tags=["credentials"])]


def _assignment_findings(ctx: ScanContext, art, text: str) -> list[Finding]:
    out = []
    path = ctx.fs_path(art)
    if path.rsplit("/", 1)[-1] in ("hostapd.conf", "shadow", "passwd") or NOT_CREDENTIAL_FILES.search(path):
        return out
    hits = []
    for n, line in enumerate(text.splitlines()[:50_000], 1):
        if line.lstrip().startswith(("#", "//", ";")):
            continue
        m = ASSIGN_RE.search(line)
        if not m:
            continue
        val = m.group("val")
        if val.lower() in PLACEHOLDERS or val.startswith(("$", "%", "{", "<")) or val.isupper() and "_" in val:
            continue
        hits.append((n, m.group("key"), val))
    for n, key, val in hits[:10]:
        weak = val.lower() in WEAK_VALUES
        out.append(Finding(
            title=f"Possible hardcoded credential '{key}'" + (" (common default value)" if weak else ""),
            description=("A credential-like key is assigned a literal value. This is a pattern match: confirm "
                         "whether the value is a real secret that is used at runtime."),
            severity=S.high if weak else S.medium, classification=C.suspicious,
            confidence=K.medium if weak else K.low, source_tool=TOOL, rule_id="hardcoded-credential-assignment",
            affected_component=ctx.where(art),
            remediation="Move secrets out of the firmware image; load per-device secrets from secure storage.",
            evidence=[Evidence("config", f"{key}={redact(val)}", f"{path}:{n}")], cwe="CWE-798",
            tags=["credentials"]))
    return out


def _token_findings(ctx: ScanContext, art, lines, in_binary: bool) -> list[Finding]:
    out = []
    seen = set()
    path = ctx.fs_path(art)
    for off, s in lines:
        for rule, pat, label, sev in TOKEN_PATTERNS:
            for m in pat.finditer(s):
                tok = m.group(1)
                if tok in seen or len(seen) > 50:
                    continue
                seen.add(tok)
                out.append(Finding(
                    title=f"{label} pattern found",
                    description=(f"A string matching the {label} format was found. Format match only - whether "
                                 "the credential is valid/active was not checked."),
                    severity=sev, classification=C.suspicious, confidence=K.medium, source_tool=TOOL,
                    rule_id=f"token-{rule}", affected_component=ctx.where(art),
                    remediation="Revoke the credential if it is real and remove it from the firmware.",
                    evidence=[Evidence("string", redact(tok, 6), path + (f" @ {off:#x}" if in_binary else ""))],
                    cwe="CWE-798", tags=["credentials"]))
    return out
