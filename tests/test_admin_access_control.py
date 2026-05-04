import pathlib
import sys
import types
from datetime import datetime, timedelta

import pytest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "web"))

psycopg2_stub = types.ModuleType("psycopg2")
psycopg2_stub.connect = lambda *args, **kwargs: (_ for _ in ()).throw(
    RuntimeError("psycopg2 stub should not be called")
)

extras_stub = types.ModuleType("psycopg2.extras")
extras_stub.RealDictCursor = object

psycopg2_stub.extras = extras_stub

sys.modules.setdefault("psycopg2", psycopg2_stub)
sys.modules.setdefault("psycopg2.extras", extras_stub)

from app.app import create_app
import app.app as app_module
from app.routes import admin as admin_routes


@pytest.fixture
def app():
    test_app = create_app()
    test_app.config.update(TESTING=True)
    return test_app


@pytest.fixture
def client(app):
    return app.test_client()


def login_as(client, user_id, username):
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = username


def test_admin_user_can_access_admin_routes(monkeypatch, client):
    users_payload = [
        {"id": 1, "username": "alice", "is_disabled": False, "session_revoked_at": None},
        {"id": 2, "username": "bob", "is_disabled": True, "session_revoked_at": None},
    ]
    changes = []
    revoked_sessions = []

    monkeypatch.setattr(admin_routes, "get_all_users", lambda: users_payload)
    monkeypatch.setattr(
        admin_routes,
        "set_user_disabled",
        lambda user_id, disabled: changes.append((str(user_id), disabled)),
    )
    monkeypatch.setattr(
        admin_routes,
        "revoke_user_sessions",
        lambda user_id: revoked_sessions.append(str(user_id)) or True,
    )

    login_as(client, user_id=99, username="admin")

    dashboard_response = client.get("/admin/dashboard")
    assert dashboard_response.status_code == 200

    users_response = client.get("/admin/users")
    assert users_response.status_code == 200
    assert users_response.get_json() == users_payload

    enable_response = client.post("/admin/users/enable", data={"user_id": "2"})
    assert enable_response.status_code == 200
    assert enable_response.get_json()["status"] == "enabled"

    disable_response = client.post("/admin/users/disable", data={"user_id": "1"})
    assert disable_response.status_code == 200
    assert disable_response.get_json()["status"] == "disabled"

    revoke_response = client.post(
        "/admin/users/revoke-sessions",
        data={"user_id": "1"},
    )
    assert revoke_response.status_code == 200
    assert revoke_response.get_json()["status"] == "sessions_revoked"

    assert changes == [("2", False), ("1", True)]
    assert revoked_sessions == ["1"]


def test_non_admin_user_cannot_access_admin_routes(monkeypatch, client):
    monkeypatch.setattr(
        admin_routes,
        "get_all_users",
        lambda: pytest.fail("Non-admin should not query users"),
    )
    monkeypatch.setattr(
        admin_routes,
        "set_user_disabled",
        lambda user_id, disabled: pytest.fail("Non-admin should not change user status"),
    )
    monkeypatch.setattr(
        admin_routes,
        "revoke_user_sessions",
        lambda user_id: pytest.fail("Non-admin should not revoke sessions"),
    )

    login_as(client, user_id=1, username="alice")

    assert client.get("/admin/dashboard").status_code == 403
    assert client.get("/admin/users").status_code == 403
    assert client.post("/admin/users/enable", data={"user_id": "2"}).status_code == 403
    assert client.post("/admin/users/disable", data={"user_id": "2"}).status_code == 403
    assert client.post(
        "/admin/users/revoke-sessions",
        data={"user_id": "2"},
    ).status_code == 403


def test_anonymous_user_is_redirected_to_login_on_admin_routes(client):
    responses = [
        client.get("/admin/dashboard"),
        client.get("/admin/users"),
        client.post("/admin/users/enable", data={"user_id": "2"}),
        client.post("/admin/users/disable", data={"user_id": "2"}),
        client.post("/admin/users/revoke-sessions", data={"user_id": "2"}),
    ]

    for response in responses:
        assert response.status_code in (302, 303)
        assert "/login" in response.headers.get("Location", "")


def test_admin_cannot_revoke_their_own_sessions(monkeypatch, client):
    monkeypatch.setattr(
        admin_routes,
        "revoke_user_sessions",
        lambda user_id: pytest.fail("Admin should not revoke their own sessions"),
    )

    login_as(client, user_id=99, username="admin")

    response = client.post("/admin/users/revoke-sessions", data={"user_id": "99"})

    assert response.status_code == 400
    assert response.get_json()["error"] == "Cannot revoke your own sessions"


def test_revoked_session_is_forced_to_login(monkeypatch, client):
    authenticated_at = datetime(2026, 5, 4, 12, 0, 0)
    revoked_at = authenticated_at + timedelta(seconds=1)

    monkeypatch.setattr(
        app_module,
        "get_user_session_revoked_at",
        lambda user_id: revoked_at,
    )

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "alice"
        session["authenticated_at"] = authenticated_at.isoformat()
        session["last_active"] = authenticated_at.isoformat()

    response = client.get("/")

    assert response.status_code in (302, 303)
    assert "/login" in response.headers.get("Location", "")

    with client.session_transaction() as session:
        assert "user_id" not in session
