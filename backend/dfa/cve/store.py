"""Read-only access to the local CVE database built by :mod:`dfa.cve.build`."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

from . import SCHEMA_VERSION

_BATCH = 900  # stay well below SQLite's bound-parameter limit


class CveDbError(Exception):
    """The database exists but is unreadable or was built by an incompatible version."""


class CveStore:
    def __init__(self, path: Path) -> None:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        try:
            self.conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._meta = {r[0]: r[1] for r in self.conn.execute("SELECT key, value FROM meta")}
        except sqlite3.DatabaseError as exc:
            raise CveDbError(f"not a valid CVE database ({exc}); rebuild it with `make cve-db`") from exc
        if self._meta.get("schema_version") != str(SCHEMA_VERSION):
            self.conn.close()
            raise CveDbError(f"CVE database schema {self._meta.get('schema_version')!r} does not match "
                             f"this version ({SCHEMA_VERSION}); rebuild it with `make cve-db`")

    def __enter__(self) -> CveStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def meta(self) -> dict[str, str]:
        return dict(self._meta)

    def cpe_rows(self, vendor: str, product: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT cve_id, version, start_incl, start_excl, end_incl, end_excl FROM cpe_match "
            "WHERE vendor = ? AND product = ?", (vendor, product)).fetchall()

    def cna_rows(self, vendor: str, product: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT cve_id, default_status, versions FROM cna_affected WHERE vendor = ? AND product = ?",
            (vendor, product)).fetchall()

    def _in(self, sql: str, ids: Iterable[str]) -> list[sqlite3.Row]:
        ids = sorted(set(ids))
        out: list[sqlite3.Row] = []
        for i in range(0, len(ids), _BATCH):
            chunk = ids[i:i + _BATCH]
            out += self.conn.execute(sql.format(",".join("?" * len(chunk))), chunk).fetchall()
        return out

    def cves(self, ids: Iterable[str]) -> dict[str, sqlite3.Row]:
        return {r["id"]: r for r in self._in("SELECT * FROM cve WHERE id IN ({})", ids)}

    def kev(self, ids: Iterable[str]) -> dict[str, sqlite3.Row]:
        return {r["cve_id"]: r for r in self._in("SELECT * FROM kev WHERE cve_id IN ({})", ids)}

    def exploits(self, ids: Iterable[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for r in self._in("SELECT cve_id, edb_id FROM exploit WHERE cve_id IN ({}) ORDER BY edb_id", ids):
            out.setdefault(r["cve_id"], []).append(r["edb_id"])
        return out
