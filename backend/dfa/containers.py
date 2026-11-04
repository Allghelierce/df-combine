"""Container job profiles and runners.

Every container that touches firmware is described by a *profile*. A caller
only supplies a scan id and a small set of typed parameters; image, entry
point, mounts and hardening flags are fixed here and cannot be influenced by
the caller. The same code is used

* in-process by the worker (``DirectDockerRunner``, development / single-user
  setups where the worker may use Docker itself), and
* by the sandbox broker (``dfa.broker``) - the only process that holds the
  Docker socket in a hardened deployment. The worker then talks to the
  broker through ``BrokerRunner`` and never sees the Docker socket.

Mounts are derived from the scan id only:
    <data>/uploads/<scan_id>.bin  -> /in/firmware   (read-only)
    <data>/work/<scan_id>/         -> /work          (read-write)
"""
from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from .config import BACKEND_DIR, Settings

GHIDRA_SCRIPTS = BACKEND_DIR / "dfa" / "ghidra_scripts"
SANDBOX_UID = 10001  # 'analyzer' in docker/sandbox.Dockerfile
TOOL_UID = 1000  # 'cwe' in the fkiecad/cwe_checker image (also used for Ghidra)
GHIDRA_PROCESSORS = {"ARM:LE:32:Cortex", "ARM:LE:32:v7", "ARM:LE:32:v8", "ARM:BE:32:v7", "AARCH64:LE:64:v8A",
                     "MIPS:BE:32:default", "MIPS:LE:32:default", "x86:LE:32:default", "x86:LE:64:default",
                     "PowerPC:BE:32:default", "RISCV:LE:32:RV32IMC", "Xtensa:LE:32:default"}
_NAME_OK = re.compile(r"^[\w .,+()@=-]{1,255}$")
_HEX = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
_SCAN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class JobError(RuntimeError):
    pass


class JobRejected(JobError):
    """The job request violates the profile contract (never executed)."""


@dataclass
class JobResult:
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    killed_reason: str | None = None
    runner: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Profile:
    name: str
    image_setting: str  # attribute of Settings holding the image name
    user: int
    memory_setting: str
    timeout_setting: str
    writable_subdir: str | None  # sub-directory of /work the container must be able to write
    tmpfs: list[str] = field(default_factory=list)
    pids: int = 256


PROFILES: dict[str, Profile] = {
    "analyze": Profile("analyze", "sandbox_image", SANDBOX_UID, "sandbox_memory", "sandbox_timeout_s", "",
                       ["/tmp:rw,noexec,nosuid,size=64m"]),
    "fwanalyzer": Profile("fwanalyzer", "sandbox_image", SANDBOX_UID, "sandbox_memory", "fwanalyzer_timeout_s",
                          "tools/fwanalyzer", ["/tmp:rw,noexec,nosuid,size=256m"]),
    "cwe_checker": Profile("cwe_checker", "cwe_checker_image", TOOL_UID, "cwe_checker_memory",
                           "cwe_checker_timeout_s", "tools/cwe_checker",
                           ["/tmp:rw,exec,size=2g,uid=1000,gid=1000",
                            "/home/cwe/.config/ghidra:rw,size=64m,uid=1000,gid=1000",
                            "/home/cwe/.ghidra:rw,exec,size=256m,uid=1000,gid=1000",
                            "/home/cwe/.cache:rw,size=64m,uid=1000,gid=1000"], pids=1024),
    "ghidra": Profile("ghidra", "ghidra_image", TOOL_UID, "ghidra_memory", "ghidra_timeout_s", "tools/ghidra",
                      ["/tmp:rw,exec,size=3g,uid=1000,gid=1000",
                       "/home/cwe/.config/ghidra:rw,size=64m,uid=1000,gid=1000",
                       "/home/cwe/.ghidra:rw,exec,size=256m,uid=1000,gid=1000",
                       "/home/cwe/.cache:rw,size=64m,uid=1000,gid=1000"], pids=1024),
}


# ----------------------------------------------------------------------------- validation
def _container_path(value: object, *, allow_input: bool = True) -> str:
    if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
        raise JobRejected("path parameter must be a string")
    if allow_input and value == "/in/firmware":
        return value
    p = PurePosixPath(value)
    if not value.startswith("/work/") or ".." in p.parts:
        raise JobRejected(f"path must be inside /work: {value!r}")
    if any(part.startswith("-") for part in p.parts):
        raise JobRejected("path components may not start with '-'")
    return str(p)


def build_argv(profile: str, params: dict) -> list[str]:
    """Container command for a profile, built only from validated parameters."""
    if profile == "analyze":
        name = str(params.get("name", "firmware"))
        name = "".join(c for c in name if c.isprintable())[:255] or "firmware"
        limits = params.get("limits", {})
        if not isinstance(limits, dict) or not all(isinstance(k, str) and isinstance(v, (int, float))
                                                    for k, v in limits.items()):
            raise JobRejected("limits must be a flat object of numbers")
        return ["python", "-m", "dfa.core.analyze", "--input", "/in/firmware", f"--name={name}", "--work", "/work",
                f"--limits={json.dumps(limits)}"]
    if profile == "fwanalyzer":
        cfg = _container_path(params.get("config"), allow_input=False)
        out = _container_path(params.get("out"), allow_input=False)
        target = _container_path(params.get("target"))
        if not cfg.startswith("/work/tools/fwanalyzer/") or not out.startswith("/work/tools/fwanalyzer/"):
            raise JobRejected("FwAnalyzer config/output must live in /work/tools/fwanalyzer")
        return ["fwanalyzer", "-cfg", cfg, "-in", target, "-out", out]
    if profile == "cwe_checker":
        target = _container_path(params.get("target"))
        argv = ["/home/cwe/cwe_checker", target, "--json", "--quiet"]
        bm = params.get("bare_metal_config")
        if bm is not None:
            bm = _container_path(bm, allow_input=False)
            if not bm.startswith("/work/tools/cwe_checker/"):
                raise JobRejected("bare-metal config must live in /work/tools/cwe_checker")
            argv += ["--bare-metal-config", bm]
        return argv
    if profile == "ghidra":
        target = _container_path(params.get("target"))
        out = _container_path(params.get("out"), allow_input=False)
        if not out.startswith("/work/tools/ghidra/"):
            raise JobRejected("Ghidra output must live in /work/tools/ghidra")
        argv = ["/opt/ghidra/support/analyzeHeadless", "/tmp", "dfa", "-import", target]
        raw = params.get("raw")
        if raw is not None:
            if not isinstance(raw, dict) or raw.get("processor") not in GHIDRA_PROCESSORS \
                    or not _HEX.match(str(raw.get("base", ""))):
                raise JobRejected("raw import needs an allow-listed processor and a hex base address")
            argv += ["-loader", "BinaryLoader", "-loader-baseAddr", raw["base"], "-processor", raw["processor"]]
        argv += ["-scriptPath", "/dfa_scripts"]
        if raw is not None and str(raw.get("processor", "")).startswith("ARM:LE:32:Cortex"):
            argv += ["-preScript", "DfaCortexMVectors.java"]
        timeout = int(params.get("analysis_timeout", 900))
        argv += ["-postScript", "DfaExport.java", out, "-deleteProject",
                 "-analysisTimeoutPerFile", str(max(60, min(timeout, 7200)))]
        return argv
    raise JobRejected(f"unknown profile {profile!r}")


def _mem_bytes(spec: str) -> int:
    spec = spec.strip().lower()
    mult = {"k": 1024, "m": 1024**2, "g": 1024**3}.get(spec[-1:], 1)
    return int(float(spec.rstrip("kmg")) * mult)


# ----------------------------------------------------------------------------- docker execution
class DockerJobExecutor:
    """Builds and runs the hardened ``docker run`` for a profile (used by direct mode and the broker)."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._sem = threading.BoundedSemaphore(max(1, settings.sandbox_max_jobs))

    # paths on the docker host
    def _host(self, p: Path) -> str:
        s = self.settings
        if s.sandbox_host_data_dir:
            try:
                rel = p.resolve().relative_to(s.data_dir.resolve())
            except ValueError:
                raise JobRejected("path outside the data directory") from None
            return str(s.sandbox_host_data_dir / rel)
        return str(p.resolve())

    def _scan_paths(self, scan_id: str) -> tuple[Path, Path]:
        if not _SCAN_ID.match(scan_id or ""):
            raise JobRejected("invalid scan id")
        work = (self.settings.work_root / scan_id).resolve()
        upload = (self.settings.uploads_dir / f"{scan_id}.bin").resolve()
        if not work.is_relative_to(self.settings.work_root.resolve()) or not work.is_dir():
            raise JobRejected("unknown scan work directory")
        if not upload.is_file():
            raise JobRejected("unknown scan upload")
        return work, upload

    def _prepare_writable(self, work: Path, prof: Profile) -> None:
        target = work if prof.writable_subdir == "" else (work / prof.writable_subdir if prof.writable_subdir else None)
        if target is None:
            return
        target.mkdir(parents=True, exist_ok=True)
        if os.getuid() == 0:
            for dirpath, _dirs, files in os.walk(target):
                os.chown(dirpath, prof.user, prof.user)
                for f in files:
                    os.chown(os.path.join(dirpath, f), prof.user, prof.user, follow_symlinks=False)
            if prof.writable_subdir:  # tool profiles: parent dirs must be traversable
                os.chmod(work, 0o755)
        else:
            os.chmod(target, 0o777)  # data dir itself is 0700, so this is not exposed to other users

    def command(self, profile: str, scan_id: str, params: dict) -> tuple[list[str], str, int]:
        if profile not in PROFILES:
            raise JobRejected(f"unknown profile {profile!r}")
        prof = PROFILES[profile]
        s = self.settings
        argv = build_argv(profile, params)
        work, upload = self._scan_paths(scan_id)
        self._prepare_writable(work, prof)
        mem = getattr(s, prof.memory_setting)
        name = f"dfa-{profile}-{scan_id[:8]}-{secrets.token_hex(3)}"
        user = prof.user if os.getuid() == 0 or prof.user == TOOL_UID else os.getuid()
        cmd = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--hostname", "localhost",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--memory", mem, "--memory-swap", mem, "--cpus", s.sandbox_cpus, "--pids-limit", str(prof.pids),
               "--ulimit", "core=0", "--ulimit", "nofile=4096:4096",
               "--ulimit", f"fsize={s.max_extract_file_mb * 1024 * 1024 + 1}",
               "--user", f"{user}:{user}"]
        if s.sandbox_runtime:
            cmd += ["--runtime", s.sandbox_runtime]
        for t in prof.tmpfs:
            cmd += ["--tmpfs", t]
        cmd += ["-v", f"{self._host(upload)}:/in/firmware:ro", "-v", f"{self._host(work)}:/work:rw"]
        if profile == "ghidra":
            cmd += ["-v", f"{GHIDRA_SCRIPTS}:/dfa_scripts:ro", "--entrypoint", argv[0]]
            argv = argv[1:]
        elif profile == "cwe_checker":
            cmd += ["--entrypoint", argv[0]]
            argv = argv[1:]
        image = getattr(s, prof.image_setting)
        timeout = int(params.get("timeout_s") or getattr(s, prof.timeout_setting))
        timeout = max(10, min(timeout, getattr(s, prof.timeout_setting)))
        return cmd + [image] + argv, name, timeout

    def run(self, profile: str, scan_id: str, params: dict) -> JobResult:
        cmd, name, timeout = self.command(profile, scan_id, params)
        work, _ = self._scan_paths(scan_id)
        disk_limit = self.settings.max_work_dir_mb * 1024 * 1024
        with self._sem:
            t0 = time.monotonic()
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            out_buf: list[bytes] = []
            err_buf: list[bytes] = []

            def pump(stream, buf, cap=32 * 1024 * 1024):
                size = 0
                for chunk in iter(lambda: stream.read(65536), b""):
                    if size < cap:
                        buf.append(chunk[: cap - size])
                        size += len(chunk)

            threads = [threading.Thread(target=pump, args=(proc.stdout, out_buf), daemon=True),
                       threading.Thread(target=pump, args=(proc.stderr, err_buf, 256 * 1024), daemon=True)]
            for th in threads:
                th.start()
            reason = None
            last_disk = 0.0
            while proc.poll() is None:
                time.sleep(0.5)
                now = time.monotonic()
                if now - t0 > timeout:
                    reason = f"timeout after {timeout}s"
                elif now - last_disk > 5:
                    last_disk = now
                    if _dir_size(work) > disk_limit:
                        reason = f"work directory exceeded {self.settings.max_work_dir_mb} MiB"
                if reason:
                    subprocess.run(["docker", "kill", name], capture_output=True, timeout=30)
                    try:
                        proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    break
            for th in threads:
                th.join(timeout=10)
            return JobResult(exit_code=proc.returncode, stdout=b"".join(out_buf).decode("utf-8", "replace"),
                             stderr=b"".join(err_buf).decode("utf-8", "replace")[-20000:],
                             duration_s=round(time.monotonic() - t0, 2), timed_out=bool(reason and "timeout" in reason),
                             killed_reason=reason)

    def capabilities(self) -> dict:
        images = {}
        for prof in PROFILES.values():
            img = getattr(self.settings, prof.image_setting)
            if img not in images:
                images[img] = _image_present(img)
        tools = {}
        if images.get(self.settings.sandbox_image):
            for binary in ("fwanalyzer", "ubireader_extract_files", "jefferson", "unsquashfs", "debugfs"):
                tools[binary] = _image_has(self.settings.sandbox_image, binary)
        return {"docker": _docker_ok(), "images": images, "runtime": self.settings.sandbox_runtime or "runc",
                "profiles": sorted(PROFILES), "sandbox_tools": tools}


def _dir_size(path: Path) -> int:
    total = 0
    for dirpath, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return total


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True,
                              timeout=10).returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


_IMAGE_CACHE: dict[str, tuple[float, bool]] = {}


def _image_present(image: str) -> bool:
    hit = _IMAGE_CACHE.get(image)
    if hit and time.monotonic() - hit[0] < 60:
        return hit[1]
    try:
        ok = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15).returncode == 0
    except (subprocess.SubprocessError, OSError):
        ok = False
    _IMAGE_CACHE[image] = (time.monotonic(), ok)
    return ok


_HAS_CACHE: dict[tuple[str, str], bool] = {}


def _image_has(image: str, binary: str) -> bool:
    key = (image, binary)
    if key not in _HAS_CACHE:
        try:
            r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c",
                                f"command -v {binary}"], capture_output=True, timeout=60)
            _HAS_CACHE[key] = r.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False
    return _HAS_CACHE[key]


# ----------------------------------------------------------------------------- runners used by the worker
class DirectDockerRunner:
    """Worker uses Docker itself (development / single-user). Not recommended for shared deployments."""

    kind = "docker-direct"

    def __init__(self, settings: Settings) -> None:
        self.executor = DockerJobExecutor(settings)

    def run(self, profile: str, scan_id: str, params: dict) -> JobResult:
        res = self.executor.run(profile, scan_id, params)
        res.runner = self.kind
        return res

    def capabilities(self) -> dict:
        return self.executor.capabilities()


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


class BrokerRunner:
    """Talks to ``dfa.broker`` over a Unix socket; the worker has no Docker access at all."""

    kind = "broker"

    def __init__(self, settings: Settings) -> None:
        self.socket = str(settings.broker_socket)
        self.token = settings.broker_token

    def _call(self, method: str, path: str, body: dict | None = None, timeout: float = 30) -> dict:
        conn = _UnixHTTPConnection(self.socket, timeout)
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
            resp = conn.getresponse()
            data = json.loads(resp.read() or b"{}")
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as exc:
            raise JobError(f"sandbox broker unreachable at {self.socket}: {exc}") from None
        finally:
            conn.close()
        if resp.status == 400:
            raise JobRejected(data.get("error", "rejected by broker"))
        if resp.status != 200:
            raise JobError(data.get("error", f"broker returned HTTP {resp.status}"))
        return data

    def run(self, profile: str, scan_id: str, params: dict) -> JobResult:
        data = self._call("POST", "/v1/jobs", {"profile": profile, "scan_id": scan_id, "params": params},
                          timeout=24 * 3600)
        res = JobResult(**{k: data[k] for k in JobResult.__dataclass_fields__ if k in data})
        res.runner = self.kind
        return res

    def capabilities(self) -> dict:
        try:
            return self._call("GET", "/v1/capabilities")
        except JobError as exc:
            return {"docker": False, "images": {}, "error": str(exc)}


def get_runner(settings: Settings) -> DirectDockerRunner | BrokerRunner:
    if settings.broker_socket:
        return BrokerRunner(settings)
    return DirectDockerRunner(settings)


def new_scan_id() -> str:
    return str(uuid.uuid4())
