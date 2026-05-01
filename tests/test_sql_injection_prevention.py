import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "web"))

from app import db
from app.auth.security import (
    find_sql_injection_indicators,
    validate_login_input,
)


class FakeCursor:
    def __init__(self):
        self.executed_query = None
        self.executed_params = None

    def execute(self, query, params=None):
        self.executed_query = query
        self.executed_params = params

    def fetchone(self):
        return None


def test_get_user_by_username_uses_parameterized_query():
    cur = FakeCursor()
    payload = "admin' OR '1'='1' --"

    db.get_user_by_username(cur, payload)

    assert payload not in cur.executed_query
    assert cur.executed_query.endswith("WHERE username = %s")
    assert cur.executed_params == (payload,)


def test_sql_injection_username_is_rejected_by_login_validation():
    errors = validate_login_input("admin' OR '1'='1' --", "anything")

    assert "username_sql_comment" in errors
    assert "username_boolean_tautology" in errors


def test_normal_validator_credentials_are_allowed_by_login_validation():
    assert validate_login_input("bob", "De586:Iq6}?!") == []
    assert find_sql_injection_indicators("bob") == []
