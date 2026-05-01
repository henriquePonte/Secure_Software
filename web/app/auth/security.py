import flask
import re
from functools import wraps

_MAX_USERNAME_LENGTH = 150
_MAX_PASSWORD_LENGTH = 1024

_SQL_INJECTION_SIGNATURES = {
    "sql_comment": re.compile(r"(--|#|/\*|\*/)", re.IGNORECASE),
    "stacked_statement": re.compile(
        r";\s*(select|insert|update|delete|drop|alter|create|truncate|grant|revoke)\b",
        re.IGNORECASE,
    ),
    "union_or_catalog_probe": re.compile(
        r"\b(union\s+select|information_schema|pg_catalog|pg_sleep|sleep\s*\(|benchmark\s*\()\b",
        re.IGNORECASE,
    ),
    "boolean_tautology": re.compile(
        r"\b(or|and)\b\s+(['\"]?\w+['\"]?|\d+)\s*=\s*(['\"]?\w+['\"]?|\d+)",
        re.IGNORECASE,
    ),
}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:
            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("auth.login"))
        return fn(*args, **kwargs)

    return wrapper


def get_current_user_id():
    return flask.session.get("user_id")


def get_current_username():
    return flask.session.get("username")


def is_authenticated():
    return "user_id" in flask.session


def find_sql_injection_indicators(value):
    if not isinstance(value, str):
        return []

    normalized = " ".join(value.split())
    return [
        name
        for name, signature in _SQL_INJECTION_SIGNATURES.items()
        if signature.search(normalized)
    ]


def validate_login_input(username, password):
    reasons = []

    if not isinstance(username, str) or not isinstance(password, str):
        return ["invalid_credentials_type"]

    if not username or not password:
        reasons.append("missing_credentials")

    if len(username) > _MAX_USERNAME_LENGTH:
        reasons.append("username_too_long")

    if len(password) > _MAX_PASSWORD_LENGTH:
        reasons.append("password_too_long")

    if "\x00" in username or "\x00" in password:
        reasons.append("null_byte")

    for indicator in find_sql_injection_indicators(username):
        reasons.append(f"username_{indicator}")

    return reasons


def log_rejected_login_input(reasons):
    remote_addr = flask.request.headers.get("X-Forwarded-For", flask.request.remote_addr)
    user_agent = flask.request.headers.get("User-Agent", "")

    flask.current_app.logger.warning(
        "Rejected suspicious login input: reasons=%s remote_addr=%s path=%s user_agent=%s",
        ",".join(reasons),
        remote_addr,
        flask.request.path,
        user_agent,
    )
