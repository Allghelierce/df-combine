"""Database engine/session helpers (SQLite by default, WAL mode)."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def init_engine(url: str) -> Engine:
    global _engine, _SessionLocal
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    _engine = create_engine(url, future=True, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _pragmas(conn, _record):  # pragma: no cover - trivial
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    from . import models  # noqa: F401 - register tables
    Base.metadata.create_all(_engine)
    _migrate(_engine)
    return _engine


# Additive schema migrations for databases created by earlier versions (create_all never alters tables).
MIGRATIONS: list[tuple[str, str, str]] = [
    ("scans", "owner_id", "ALTER TABLE scans ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("scans", "packages", "ALTER TABLE scans ADD COLUMN packages JSON"),
    ("findings", "package", "ALTER TABLE findings ADD COLUMN package VARCHAR(256)"),
]


def _migrate(engine: Engine) -> None:
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, column, ddl in MIGRATIONS:
            if table in insp.get_table_names() and column not in {c["name"] for c in insp.get_columns(table)}:
                conn.execute(text(ddl))


def get_engine() -> Engine:
    if _engine is None:
        from .config import get_settings
        init_engine(get_settings().db_url)
    assert _engine is not None
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    assert _SessionLocal is not None
    s = _SessionLocal()
    try:
        yield s
        s.commit()
    except BaseException:
        s.rollback()
        raise
    finally:
        s.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    with session_scope() as s:
        yield s
