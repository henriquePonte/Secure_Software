import pathlib
import sys
from datetime import datetime, timedelta

import flask
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "web"))

from app.auth.security import (
    clear_failed_login_attempts,
    is_login_temporarily_blocked,
    record_failed_login_attempt,
    reset_failed_login_attempts,
)


@pytest.fixture(autouse=True)
def clear_login_attempts():
    clear_failed_login_attempts()
    yield
    clear_failed_login_attempts()


@pytest.fixture
def app():
    test_app = flask.Flask(__name__)
    test_app.config.update(
        LOGIN_MAX_FAILED_ATTEMPTS=3,
        LOGIN_LOCKOUT_SECONDS=60,
    )
    return test_app


def test_login_is_temporarily_blocked_after_three_failed_attempts(app):
    now = datetime(2026, 5, 1, 12, 0, 0)

    with app.app_context():
        assert record_failed_login_attempt("alice", "127.0.0.1", now) == (1, 0)
        assert record_failed_login_attempt("alice", "127.0.0.1", now) == (2, 0)
        assert record_failed_login_attempt("alice", "127.0.0.1", now) == (3, 60)

        blocked, retry_after = is_login_temporarily_blocked(
            "alice", "127.0.0.1", now
        )

    assert blocked is True
    assert retry_after == 60


def test_login_block_expires_after_lockout_window(app):
    now = datetime(2026, 5, 1, 12, 0, 0)

    with app.app_context():
        record_failed_login_attempt("alice", "127.0.0.1", now)
        record_failed_login_attempt("alice", "127.0.0.1", now)
        record_failed_login_attempt("alice", "127.0.0.1", now)

        blocked, retry_after = is_login_temporarily_blocked(
            "alice", "127.0.0.1", now + timedelta(seconds=61)
        )

    assert blocked is False
    assert retry_after == 0


def test_successful_login_resets_failed_attempts(app):
    now = datetime(2026, 5, 1, 12, 0, 0)

    with app.app_context():
        record_failed_login_attempt("alice", "127.0.0.1", now)
        record_failed_login_attempt("alice", "127.0.0.1", now)

        reset_failed_login_attempts("alice", "127.0.0.1")

        assert record_failed_login_attempt("alice", "127.0.0.1", now) == (1, 0)
