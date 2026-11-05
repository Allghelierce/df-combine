"""Package-manager inventories found in extracted root filesystems.

Exact package names and versions (including distribution revisions such as
``3.0.11-1~deb12u2``) are far more reliable than version strings found in
binaries, and they allow backport-aware vulnerability matching against the
distribution's own security data.

Supported databases:
* dpkg   - ``var/lib/dpkg/status`` and ``var/lib/dpkg/status.d/*`` (Debian, Ubuntu, Raspberry Pi OS)
* apk    - ``lib/apk/db/installed`` (Alpine)
* opkg   - ``usr/lib/opkg/status`` (OpenWrt, Yocto)
* python - ``*.dist-info/METADATA`` / ``*.egg-info/PKG-INFO``
plus ``etc/os-release`` / ``usr/lib/os-release`` and ``etc/openwrt_release``.
"""
from __future__ import annotations

import re
from urllib.parse import quote

from .base import ScanContext

MAX_PACKAGES = 20000
MAX_OWNED_FILES = 200_000


def _stanzas(text: str):
    cur: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if not line.strip():
            if cur:
                yield cur
            cur, key = {}, None
            continue
        if line[0] in " \t" and key:
            continue  # continuation lines (descriptions) are not needed
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            cur[key] = val.strip()
    if cur:
        yield cur


def parse_os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = re.match(r'^([A-Z_]+)=(?:"([^"]*)"|\'([^\']*)\'|(\S*))', line.strip())
        if m:
            out[m.group(1)] = m.group(2) if m.group(2) is not None else (m.group(3) or m.group(4) or "")
    return out


def parse_dpkg(text: str) -> list[dict]:
    pkgs = []
    for st in _stanzas(text):
        if "Package" not in st or "Version" not in st:
            continue
        status = st.get("Status", "install ok installed")
        if "installed" not in status.split() or "not-installed" in status:
            continue
        src = st.get("Source", "")
        src_name, src_ver = src, None
        m = re.match(r"^(\S+)\s+\((\S+)\)$", src)
        if m:
            src_name, src_ver = m.group(1), m.group(2)
        pkgs.append({"name": st["Package"], "version": st["Version"], "arch": st.get("Architecture"),
                     "source": src_name or st["Package"], "source_version": src_ver or st["Version"],
                     "manager": "dpkg"})
    return pkgs


def parse_apk(text: str) -> list[dict]:
    pkgs = []
    for st in _stanzas(text):
        if "P" in st and "V" in st:
            pkgs.append({"name": st["P"], "version": st["V"], "arch": st.get("A"), "source": st.get("o") or st["P"],
                         "source_version": st["V"], "manager": "apk"})
    return pkgs


def apk_files(text: str) -> dict[str, str]:
    """File ownership from Alpine's installed database: P: package, F: directory, R: file in that directory."""
    owners: dict[str, str] = {}
    pkg = directory = None
    for line in text.splitlines():
        if line.startswith("P:"):
            pkg, directory = line[2:].strip(), None
        elif line.startswith("F:"):
            directory = line[2:].strip()
        elif line.startswith("R:") and pkg and directory is not None:
            owners[f"/{directory}/{line[2:].strip()}".replace("//", "/")] = pkg
        elif not line.strip():
            pkg = directory = None
    return owners


def list_files(text: str) -> list[str]:
    """dpkg/opkg '<package>.list': one owned path per line (opkg may append a tab and a mode)."""
    return [ln.split("\t", 1)[0].strip() for ln in text.splitlines() if ln.startswith("/")]


_LIST_FILE = re.compile(r"/(?:var/lib/dpkg/info|usr/lib/opkg/info|var/lib/opkg/info)/([^/]+?)(?::[a-z0-9_-]+)?\.list$")


def parse_opkg(text: str) -> list[dict]:
    pkgs = []
    for st in _stanzas(text):
        if "Package" in st and "Version" in st and "installed" in st.get("Status", "installed"):
            pkgs.append({"name": st["Package"], "version": st["Version"], "arch": st.get("Architecture"),
                         "source": st["Package"], "source_version": st["Version"], "manager": "opkg"})
    return pkgs


def parse_python_metadata(text: str) -> dict | None:
    name = re.search(r"^Name:\s*(\S+)", text, re.M)
    ver = re.search(r"^Version:\s*(\S+)", text, re.M)
    if name and ver:
        return {"name": name.group(1), "version": ver.group(1), "manager": "python", "source": name.group(1),
                "source_version": ver.group(1)}
    return None


def purl(pkg: dict, distro: dict | None) -> str:
    name = quote(pkg["name"], safe="")
    ver = quote(pkg["version"], safe="")
    did = (distro or {}).get("id", "")
    if pkg["manager"] == "dpkg":
        ns = did if did in ("debian", "ubuntu", "raspbian") else "debian"
        q = []
        if pkg.get("arch"):
            q.append(f"arch={pkg['arch']}")
        if did and distro.get("version_id"):
            q.append(f"distro={did}-{distro['version_id']}")
        return f"pkg:deb/{ns}/{name}@{ver}" + ("?" + "&".join(q) if q else "")
    if pkg["manager"] == "apk":
        q = f"?arch={pkg['arch']}" if pkg.get("arch") else ""
        return f"pkg:apk/alpine/{name}@{ver}{q}"
    if pkg["manager"] == "opkg":
        return f"pkg:generic/openwrt/{name}@{ver}"
    if pkg["manager"] == "python":
        return f"pkg:pypi/{name.lower()}@{ver}"
    return f"pkg:generic/{name}@{ver}"


def inventory(ctx: ScanContext) -> dict:
    distro: dict | None = None
    managers = []
    packages: list[dict] = []
    seen = set()
    owned: dict[tuple[int | None, str], str] = {}  # (filesystem artifact, path) -> package name
    for art in ctx.artifacts:
        path = ctx.fs_path(art)
        if art.format != "text" and not path.endswith(("/status", "/installed", "METADATA", "PKG-INFO", ".list")):
            continue
        def load(aid: int = art.id) -> str:
            try:
                return ctx.paths[aid].read_bytes()[:64 * 1024**2].decode("utf-8", "replace")
            except OSError:
                return ""

        found: list[dict] = []
        m = _LIST_FILE.search(path)
        if m:
            if len(owned) < MAX_OWNED_FILES:
                for f in list_files(load()):
                    owned[(art.parent_id, f)] = m.group(1)
            continue
        if path.endswith(("/etc/os-release", "/usr/lib/os-release")) and distro is None:
            osr = parse_os_release(load())
            if osr.get("ID"):
                distro = {"id": osr.get("ID", "").lower(), "version_id": osr.get("VERSION_ID", ""),
                          "codename": osr.get("VERSION_CODENAME", ""), "name": osr.get("PRETTY_NAME", ""),
                          "source": ctx.where(art)}
            continue
        if path.endswith("/etc/openwrt_release") and distro is None:
            osr = parse_os_release(load())
            distro = {"id": "openwrt", "version_id": osr.get("DISTRIB_RELEASE", ""), "codename": "",
                      "name": osr.get("DISTRIB_DESCRIPTION", "OpenWrt"), "source": ctx.where(art)}
            continue
        if path.endswith("/var/lib/dpkg/status") or "/var/lib/dpkg/status.d/" in path:
            found = parse_dpkg(load())
        elif path.endswith("/lib/apk/db/installed"):
            text = load()
            found = parse_apk(text)
            for f, name in list(apk_files(text).items())[:MAX_OWNED_FILES]:
                owned[(art.parent_id, f)] = name
        elif path.endswith(("/usr/lib/opkg/status", "/var/lib/opkg/status")):
            found = parse_opkg(load())
        elif re.search(r"\.(dist-info/METADATA|egg-info/PKG-INFO)$", path):
            p = parse_python_metadata(load())
            found = [p] if p else []
        if not found:
            continue
        managers.append({"type": found[0]["manager"], "database": ctx.where(art), "count": len(found)})
        for p in found:
            key = (p["manager"], p["name"], p["version"])
            if key in seen or len(packages) >= MAX_PACKAGES:
                continue
            seen.add(key)
            p["database"] = ctx.where(art)
            packages.append(p)
    for p in packages:
        p["purl"] = purl(p, distro)
    names = {p["name"] for p in packages}
    owners = {}  # display path of each extracted file -> owning package (only files that were extracted)
    if owned:
        for art in ctx.artifacts:
            name = owned.get((art.parent_id, ctx.fs_path(art)))
            if name in names:
                owners[ctx.where(art)] = name
    return {"distro": distro, "managers": managers, "packages": packages, "owners": owners}
