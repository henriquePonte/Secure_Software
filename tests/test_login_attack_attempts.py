import pathlib
import sys
import types
import logging

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
from app.auth.security import clear_failed_login_attempts
from app.routes import auth as auth_routes


class FakeCursor:
    def __init__(self, user=None):
        self.user = user
        self.executed_queries = []

    def execute(self, query, params=None):
        self.executed_queries.append((query, params))

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
def reset_login_attempts():
    clear_failed_login_attempts()
    yield
    clear_failed_login_attempts()


@pytest.fixture
def app():
    test_app = create_app()
    test_app.config.update(
        TESTING=True,
        LOGIN_MAX_FAILED_ATTEMPTS=3,
        LOGIN_LOCKOUT_SECONDS=60,
    )
    return test_app


@pytest.fixture
def client(app):
    return app.test_client()


def test_login_rejects_sql_injection_payload_before_database(monkeypatch, client):
    def fail_if_database_is_queried():
        pytest.fail("SQL injection payload should be rejected before database access")

    monkeypatch.setattr(auth_routes, "get_db", fail_if_database_is_queried)

    response = client.post(
        "/login",
        data={
            "username": "admin' OR '1'='1' --",
            "password": "anything",
        },
    )

    assert response.status_code == 400
    assert b"Invalid credentials." in response.data


def test_brute_force_login_attempts_are_temporarily_blocked(monkeypatch, client):
    fake_connection = FakeConnection(user=None)
    monkeypatch.setattr(auth_routes, "get_db", lambda: fake_connection)

    for _ in range(3):
        response = client.post(
            "/login",
            data={
                "username": "alice",
                "password": "wrong-password",
            },
            follow_redirects=False,
        )

        assert response.status_code in (302, 303)

    blocked_response = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "wrong-password",
        },
    )

    assert blocked_response.status_code == 429
    assert b"Too many failed login attempts." in blocked_response.data
    assert len(fake_connection.cursor_obj.executed_queries) == 3
