"""Authentication, roles, ownership and upload hardening."""
import time

import pytest
from conftest import ADMIN_PASSWORD, login

from dfa.auth import hash_password, verify_password


def test_password_hashing():
    h = hash_password("a-long-password")
    assert h.startswith("scrypt$") and verify_password("a-long-password", h)
    assert not verify_password("wrong-password!", h)
    with pytest.raises(ValueError):
        hash_password("short")


def test_unauthenticated_access_is_rejected(make_client):
    anon = make_client(authenticate=False)
    assert anon.get("/api/health").status_code == 200
    assert anon.get("/api/auth/status").json() == {"auth_mode": "users", "setup_required": False}
    for path in ("/api/scans", "/api/config", "/api/tools", "/api/stats", "/api/users"):
        assert anon.get(path).status_code == 401, path
    assert anon.post("/api/scans", files={"file": ("a.bin", b"x")}).status_code == 401


def test_login_logout_and_csrf(make_client):
    c = make_client(authenticate=False)
    assert c.post("/api/auth/login", json={"username": "admin", "password": "nope-nope-nope"}).status_code == 401
    info = login(c)
    assert info["user"]["role"] == "admin"
    assert c.get("/api/auth/me").json()["via"] == "cookie"
    del c.headers["X-DFA-CSRF"]
    # cookie-authenticated mutation without the CSRF header is refused
    assert c.post("/api/users", json={"username": "x"}).status_code == 403
    c.headers["X-DFA-CSRF"] = "1"
    assert c.post("/api/auth/logout").status_code == 200
    assert c.get("/api/scans").status_code == 401


def test_login_throttling(make_client):
    c = make_client(authenticate=False)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"username": "admin", "password": "bad-password-1"}).status_code == 401
    r = c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert r.status_code == 429


def _add_user(admin, name, role):
    r = admin.post("/api/users", json={"username": name, "password": f"{name}-password-123", "role": role})
    assert r.status_code == 201, r.text


def test_roles_and_ownership(make_client, settings, fixtures):
    admin = make_client()
    _add_user(admin, "alice", "analyst")
    _add_user(admin, "bob", "analyst")
    _add_user(admin, "vera", "viewer")
    alice, bob, vera = make_client(False, False), make_client(False, False), make_client(False, False)
    login(alice, "alice", "alice-password-123")
    login(bob, "bob", "bob-password-123")
    login(vera, "vera", "vera-password-123")
    with open(fixtures["px4"], "rb") as fp:
        s = alice.post("/api/scans", files={"file": ("a.px4", fp)}).json()
    # owner and admin see it; another analyst does not; viewer can read but not modify
    assert alice.get(f"/api/scans/{s['id']}").status_code == 200
    assert admin.get(f"/api/scans/{s['id']}").status_code == 200
    assert bob.get(f"/api/scans/{s['id']}").status_code == 404
    assert bob.get("/api/scans").json()["total"] == 0
    assert vera.get(f"/api/scans/{s['id']}").status_code == 200
    assert vera.delete(f"/api/scans/{s['id']}").status_code == 403
    with open(fixtures["px4"], "rb") as fp:
        assert vera.post("/api/scans", files={"file": ("v.px4", fp)}).status_code == 403
    assert bob.delete(f"/api/scans/{s['id']}").status_code == 404
    assert vera.get("/api/users").status_code == 403
    assert alice.delete(f"/api/scans/{s['id']}").status_code == 204


def test_api_tokens(make_client):
    from fastapi.testclient import TestClient
    admin = make_client()
    r = admin.post("/api/auth/tokens", json={"label": "ci", "days": 7})
    assert r.status_code == 201
    token = r.json()["token"]
    api = TestClient(admin.app)
    h = {"Authorization": f"Bearer {token}"}
    assert api.get("/api/scans", headers=h).status_code == 200
    assert api.get("/api/auth/me", headers=h).json()["via"] == "bearer"
    assert api.get("/api/scans", headers={"Authorization": "Bearer nope"}).status_code == 401
    tid = admin.get("/api/auth/tokens").json()["items"][0]["id"]
    assert admin.delete(f"/api/auth/tokens/{tid}").status_code == 204
    assert api.get("/api/scans", headers=h).status_code == 401


def test_disabling_user_revokes_sessions(make_client):
    admin = make_client()
    _add_user(admin, "carol", "analyst")
    carol = make_client(False, False)
    login(carol, "carol", "carol-password-123")
    uid = next(u["id"] for u in admin.get("/api/users").json()["items"] if u["username"] == "carol")
    assert admin.patch(f"/api/users/{uid}", json={"disabled": True}).status_code == 200
    assert carol.get("/api/scans").status_code == 401
    me = admin.get("/api/auth/me").json()["user"]["id"]
    assert admin.patch(f"/api/users/{me}", json={"disabled": True}).status_code == 400


def test_upload_requires_content_length_and_respects_limit(client, settings):
    import httpx
    settings.max_upload_mb = 1
    big = b"\0" * (2 * 1024 * 1024)
    r = client.post("/api/scans", files={"file": ("big.bin", big)})
    assert r.status_code == 413
    assert not list(settings.uploads_dir.iterdir())
    # no Content-Length (chunked) is refused before any body is read
    req = httpx.Request("POST", "http://testserver/api/scans", content=iter([b"--x\r\n"]),
                        headers={"Content-Type": "multipart/form-data; boundary=x", "X-DFA-CSRF": "1"})
    assert client.send(req).status_code == 411


def test_upload_rate_limit(client, settings, fixtures):
    settings.upload_rate_per_hour = 2
    for i in range(2):
        with open(fixtures["px4"], "rb") as fp:
            assert client.post("/api/scans", files={"file": (f"{i}.px4", fp)}).status_code == 201
    with open(fixtures["px4"], "rb") as fp:
        assert client.post("/api/scans", files={"file": ("x.px4", fp)}).status_code == 429


def test_security_headers(client):
    r = client.get("/api/health")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_auth_disabled_mode(settings):
    from fastapi.testclient import TestClient

    from dfa.main import create_app
    settings.auth_mode = "disabled"
    with TestClient(create_app(settings, start_worker=False)) as c:
        assert c.get("/api/scans").status_code == 200
        assert c.get("/api/auth/me").json()["role"] == "admin"
    time.sleep(0)
