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
