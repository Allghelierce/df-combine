"""Authentication and authorization.

* Users with scrypt-hashed passwords and one of three roles:
    admin    - manage users, see and act on every scan
    analyst  - upload scans; see and act on their own scans
    viewer   - read-only access to all scans
* Opaque random tokens (session tokens for the browser, API tokens for automation). Only a
  SHA-256 hash of each token is stored; tokens expire and can be revoked.
* Browser sessions use an HttpOnly, SameSite=Strict cookie. State-changing requests that
  authenticate with the cookie must also send the ``X-DFA-CSRF`` header (custom headers cannot
  be sent cross-site without a CORS pre-flight, which is not granted to other origins).
* API clients send ``Authorization: Bearer <token>`` (no CSRF header needed).
* Failed logins are throttled per username and client address.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_session
from .models import ApiToken, Scan, User

ROLES = ("admin", "analyst", "viewer")
SESSION_COOKIE = "dfa_session"
CSRF_HEADER = "x-dfa-csrf"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
SESSION_TTL = timedelta(hours=12)
MIN_PASSWORD = 10


def utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


# ----------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024**2)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                            maxmem=128 * 1024**2)
        return hmac.compare_digest(dk, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    return _DUMMY_HASH


# ----------------------------------------------------------------------------- tokens
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(db: Session, user: User, kind: str = "session", label: str = "",
                ttl: timedelta | None = SESSION_TTL) -> tuple[str, ApiToken]:
    token = ("dfa_s_" if kind == "session" else "dfa_t_") + secrets.token_urlsafe(32)
    row = ApiToken(user_id=user.id, token_hash=_token_hash(token), kind=kind, label=label[:100],
                   expires_at=(utcnow() + ttl) if ttl else None)
    db.add(row)
    db.flush()
    return token, row


def resolve_token(db: Session, token: str) -> User | None:
    if not token or len(token) > 200:
        return None
    row = db.execute(select(ApiToken).where(ApiToken.token_hash == _token_hash(token))).scalar_one_or_none()
    if row is None or row.revoked:
        return None
    if row.expires_at is not None and _aware(row.expires_at) < utcnow():
        return None
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    if row.last_used_at is None or utcnow() - _aware(row.last_used_at) > timedelta(minutes=5):
        row.last_used_at = utcnow()
    return user


# ----------------------------------------------------------------------------- login throttling
class LoginThrottle:
    def __init__(self, max_failures: int = 5, window_s: int = 300) -> None:
        self.max, self.window = max_failures, window_s
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _key(self, username: str, client: str) -> str:
        return f"{username.lower()}|{client}"

    def blocked(self, username: str, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._fails.get(self._key(username, client), []) if now - t < self.window]
            self._fails[self._key(username, client)] = hits
            return len(hits) >= self.max

    def failure(self, username: str, client: str) -> None:
        with self._lock:
            self._fails.setdefault(self._key(username, client), []).append(time.monotonic())

    def success(self, username: str, client: str) -> None:
        with self._lock:
            self._fails.pop(self._key(username, client), None)


# ----------------------------------------------------------------------------- request principal
@dataclass
class Principal:
    user: User | None  # None only when authentication is disabled (local development)
    via: str  # cookie | bearer | disabled

    @property
    def role(self) -> str:
        return self.user.role if self.user else "admin"

    @property
    def id(self) -> int | None:
        return self.user.id if self.user else None

    def can_write(self) -> bool:
        return self.role in ("admin", "analyst")

    def can_see(self, scan: Scan) -> bool:
        return self.role in ("admin", "viewer") or scan.owner_id is None or scan.owner_id == self.id

    def can_modify(self, scan: Scan) -> bool:
        return self.role == "admin" or (self.role == "analyst" and scan.owner_id == self.id)


def current_principal(request: Request, db: Session = Depends(get_session)) -> Principal:
    settings = request.app.state.settings
    if settings.auth_mode == "disabled":
        return Principal(None, "disabled")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        user = resolve_token(db, auth[7:].strip())
        if user is None:
            raise HTTPException(401, "invalid or expired token")
        return Principal(user, "bearer")
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        user = resolve_token(db, cookie)
        if user is None:
            raise HTTPException(401, "session expired")
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "missing CSRF header")
        return Principal(user, "cookie")
    raise HTTPException(401, "authentication required")


def require_writer(p: Principal = Depends(current_principal)) -> Principal:
    if not p.can_write():
        raise HTTPException(403, "your role is read-only")
    return p


def require_admin(p: Principal = Depends(current_principal)) -> Principal:
    if p.role != "admin":
        raise HTTPException(403, "administrator role required")
    return p


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None or user.disabled:
        verify_password(password, _dummy_hash())  # equalise timing for unknown users
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = utcnow()
    return user


def create_user(db: Session, username: str, password: str, role: str) -> User:
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    username = username.strip()
    if not (3 <= len(username) <= 64) or not all(c.isalnum() or c in "._-@" for c in username):
        raise ValueError("username must be 3-64 characters: letters, digits, . _ - @")
    if db.execute(select(User).where(User.username == username)).scalar_one_or_none():
        raise ValueError("user already exists")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user


def user_dict(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "disabled": u.disabled,
            "created_at": _aware(u.created_at).isoformat() if u.created_at else None,
            "last_login_at": _aware(u.last_login_at).isoformat() if u.last_login_at else None}
