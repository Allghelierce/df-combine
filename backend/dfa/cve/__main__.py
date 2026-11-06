"""CLI: ``python -m dfa.cve update`` builds the local CVE database; ``info`` describes it."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .build import BuildError, update
from .store import CveDbError, CveStore


def _default_db() -> Path:
    from ..config import get_settings
    return get_settings().cve_db_file


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m dfa.cve", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("update", help="download the public feeds and (re)build the CVE database")
    up.add_argument("--db", type=Path, help="database path (default: <data_dir>/cve.db)")
    for name in ("nvd", "kev", "exploitdb"):
        up.add_argument(f"--{name}", help=f"use a local {name} feed file or URL instead of the default download")
    info = sub.add_parser("info", help="show what the CVE database contains")
    info.add_argument("--db", type=Path)
    args = p.parse_args(argv)
    db = args.db or _default_db()

    if args.cmd == "update":
        print(f"Building CVE database at {db}")
        sources = {k: getattr(args, k) for k in ("nvd", "kev", "exploitdb") if getattr(args, k)}
        try:
            meta = update(db, sources, log=lambda m: print(m, flush=True))
        except BuildError as exc:
            print(f"error: {exc}\nThe previous database (if any) was left unchanged.", file=sys.stderr)
            return 1
        print(f"Done in {meta['build_seconds']}s: {int(meta['cve_count']):,} CVEs "
              f"(NVD data {meta['nvd_timestamp'][:10]}), {int(meta['kev_count']):,} known exploited, "
              f"{int(meta['exploit_rows']):,} Exploit-DB links")
        return 0

    try:
        with CveStore(db) as st:
            meta = st.meta()
    except FileNotFoundError:
        print(f"No CVE database at {db}. Build it with `make cve-db`.", file=sys.stderr)
        return 1
    except CveDbError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for k, v in sorted(meta.items()):
        print(f"{k:16s} {v}")
    print(f"{'size':16s} {db.stat().st_size / 1e6:.0f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
