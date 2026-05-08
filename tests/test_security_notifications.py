import logging
import pathlib
import sys
import types

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

logger_stub = types.ModuleType("app.logger.logger")
logger_stub.get_logger = lambda name: logging.getLogger(name)
sys.modules["app.logger.logger"] = logger_stub

from app.app import create_app
from app.auth.security import (
    clear_failed_login_attempts,
    clear_request_volume_tracking,
)
from app.routes import admin as admin_routes
from app.routes import auth as auth_routes
from app.services.security_alerts import (
    clear_security_alerts,
    create_security_alert,
    get_recent_security_alerts,
)


class FakeCursor:
    def __init__(self, user=None):
        self.user = user

    def execute(self, query, params=None):
        pass

    def fetchone(self):
        return self.user

    def close(self):
        pass


class FakeConnection:
    def __init__(self, user=None):
        self.cursor_obj = FakeCursor(user)

    def cursor(self, *args, **kwargs):
        return self.cursor_obj

    def close(self):
        pass


@pytest.fixture(autouse=True)
def reset_security_state():
    clear_failed_login_attempts()
    clear_request_volume_tracking()
    clear_security_alerts()
    yield
    clear_failed_login_attempts()
    clear_request_volume_tracking()
    clear_security_alerts()


@pytest.fixture
def app():
    test_app = create_app()
    test_app.config.update(
        TESTING=True,
        LOGIN_MAX_FAILED_ATTEMPTS=3,
        LOGIN_LOCKOUT_SECONDS=60,
        SECURITY_REQUEST_VOLUME_THRESHOLD=2,
        SECURITY_REQUEST_VOLUME_WINDOW_SECONDS=60,
        SECURITY_REQUEST_VOLUME_ALERT_COOLDOWN_SECONDS=300,
    )
    return test_app


@pytest.fixture
def client(app):
    return app.test_client()


def login_as_admin(client):
    with client.session_transaction() as session:
        session["user_id"] = 99
        session["username"] = "admin"


def test_high_request_volume_creates_admin_notification(client):
    client.get("/health")
    client.get("/health")

    alerts = get_recent_security_alerts()

    assert alerts[0]["category"] == "request_volume"
    assert alerts[0]["message"] == "High request volume detected"


def test_brute_force_lockout_creates_admin_notification(monkeypatch, client):
    monkeypatch.setattr(auth_routes, "get_db", lambda: FakeConnection(user=None))

    for _ in range(3):
        client.post(
            "/login",
            data={
                "username": "alice",
                "password": "wrong-password",
            },
        )

    alerts = get_recent_security_alerts()

    assert alerts[0]["category"] == "brute_force"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["details"]["username"] == "alice"


def test_admin_dashboard_shows_and_clears_security_notifications(monkeypatch, client):
    monkeypatch.setattr(admin_routes, "get_all_users", lambda: [])
    create_security_alert(
        "brute_force",
        "Login brute force threshold reached",
        severity="critical",
        username="alice",
        client_id="127.0.0.1",
    )

    login_as_admin(client)

    dashboard_response = client.get("/admin/dashboard")

    assert dashboard_response.status_code == 200
    assert b"Security notifications" in dashboard_response.data
    assert b"Login brute force threshold reached" in dashboard_response.data
    assert b"username=alice" in dashboard_response.data

    clear_response = client.post("/admin/security-alerts/clear")

    assert clear_response.status_code == 200
    assert clear_response.get_json() == {"success": True}
    assert get_recent_security_alerts() == []
