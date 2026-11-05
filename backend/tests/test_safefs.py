"""Worker-side access to scan directories that untrusted containers wrote to."""
import os
import threading

import pytest

from dfa import safefs


def test_reads_refuse_links_and_special_files(tmp_path):
    work = tmp_path / "scan"
    (work / "tools" / "x").mkdir(parents=True)
    (work / "tools" / "x" / "out.json").write_text('{"ok": 1}')
    assert safefs.read_bytes(work, "tools/x/out.json", 100) == b'{"ok": 1}'
    secret = tmp_path / "dfa.db"
    secret.write_text("database")
    (work / "manifest.json").symlink_to(secret)
    with pytest.raises(safefs.UnsafeEntry):
        safefs.read_bytes(work, "manifest.json", 1000)
    (work / "linkdir").symlink_to(tmp_path)  # intermediate component
    with pytest.raises(safefs.UnsafeEntry):
        safefs.read_bytes(work, "linkdir/dfa.db", 1000)
    os.mkfifo(work / "progress.log")  # must not block the worker
    done = threading.Event()

    def read_fifo():
        with pytest.raises(safefs.UnsafeEntry):
            safefs.read_bytes(work, "progress.log", 1000)
        done.set()
    threading.Thread(target=read_fifo, daemon=True).start()
    assert done.wait(5), "reading a FIFO blocked"
    with pytest.raises(safefs.UnsafeEntry):
        safefs.read_bytes(work, "tools/x/out.json", 3)  # size limit
    with pytest.raises(FileNotFoundError):
        safefs.read_bytes(work, "missing.json", 10)
    for bad in ("../dfa.db", "/etc/passwd", "tools/../../dfa.db", ""):
        with pytest.raises(safefs.UnsafeEntry):
            safefs.read_bytes(work, bad, 10)


def test_writes_replace_planted_links_instead_of_following_them(tmp_path):
    work = tmp_path / "scan"
    work.mkdir()
    db = tmp_path / "dfa.db"
    db.write_text("database")
    (work / "findings.json").symlink_to(db)
    safefs.write_text(work, "findings.json", "[]")
    assert db.read_text() == "database"
    assert not (work / "findings.json").is_symlink() and (work / "findings.json").read_text() == "[]"
    (work / "tools").symlink_to(tmp_path)  # a swapped directory is refused, not written through
    with pytest.raises(safefs.UnsafeEntry):
        safefs.write_text(work, "tools/fact/firmware_0.json", "{}")
    with pytest.raises(safefs.UnsafeEntry):
        safefs.ensure_dir(work, "tools/cwe_checker")
    assert not (tmp_path / "fact").exists() and not (tmp_path / "cwe_checker").exists()
    assert safefs.ensure_dir(work, "out/a") == work / "out" / "a" and (work / "out" / "a").is_dir()
    assert [p.name for p in work.iterdir() if p.name.endswith(".tmp")] == []


def test_safejson_keeps_documents_with_non_finite_or_huge_numbers():
    """Python's json accepts NaN/Infinity, turns 1e999 into inf and refuses ints over 4,300 digits; untrusted JSON
    (containers, manifest, tool output) parses with those values as None and the rest of the document kept."""
    import json
    import math

    from dfa.core import safejson
    doc = safejson.loads('{"a": NaN, "b": [1e999, -Infinity, 2.5, -1e-999], "big": 1' + "0" * 5000
                         + ', "id": -123456789012345678901234567890, "ok": 1e3, "s": "NaN"}')
    assert doc == {"a": None, "b": [None, None, 2.5, -0.0], "big": None, "id": -123456789012345678901234567890,
                   "ok": 1000.0, "s": "NaN"}
    with pytest.raises(json.JSONDecodeError):
        safejson.loads("{broken")
    x = {"z": 1, "n": {"f": math.nan, "l": [math.inf, 1.0, (2, -math.inf)]}, "k": "s"}
    assert safejson.finite(x) == {"z": 1, "n": {"f": None, "l": [None, 1.0, [2, None]]}, "k": "s"}
    assert list(safejson.finite(x)) == ["z", "n", "k"] and math.isnan(x["n"]["f"])  # order kept, input untouched
    deep = cur = []
    for _ in range(50_000):  # deeper than the recursion limit
        cur.append([])
        cur = cur[0]
    cur.append(math.nan)
    safejson.finite(deep)


def test_manifest_with_non_finite_numbers_loads_as_null(settings, tmp_path):
    import json

    from dfa.sandbox import load_manifest
    work = tmp_path / "w"
    work.mkdir()
    (work / "manifest.json").write_text(json.dumps({"fatal_error": "x", "n": float("nan"), "i": float("inf")}))
    assert load_manifest(work, "manifest.json", settings) == {"fatal_error": "x", "n": None, "i": None}
