import flask
from functools import wraps
import bcrypt
import re
from datetime import datetime, timedelta
from threading import Lock

_MAX_USERNAME_LENGTH = 150
_MAX_PASSWORD_LENGTH = 150
_MAX_FAILED_LOGIN_ATTEMPTS = 3
_LOGIN_LOCKOUT_SECONDS = 300
_FAILED_LOGIN_ATTEMPTS = {}
_FAILED_LOGIN_ATTEMPTS_LOCK = Lock()

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

def find_sql_injection_indicators(value):
    if not isinstance(value, str):
        return []

    normalized = " ".join(value.split())
    return [
        name
        for name, signature in _SQL_INJECTION_SIGNATURES.items()
        if signature.search(normalized)
    ]


def _get_suspicious_limits(config=None):
    config = config or {}

    return {
        "path_max_length": config.get("SUSPICIOUS_PATH_MAX_LENGTH", 256),
        "query_max_length": config.get("SUSPICIOUS_QUERY_MAX_LENGTH", 1024),
        "max_query_params": config.get("SUSPICIOUS_MAX_QUERY_PARAMS", 30),
    }


def detect_suspicious_request_patterns(request, config=None):
    limits = _get_suspicious_limits(config)
    indicators = set()

    method = (request.method or "").upper()
    path = request.path or ""
    query_string = request.query_string.decode("utf-8", errors="ignore")

    if method in {"TRACE", "CONNECT"}:
        indicators.add("unexpected_http_method")

    if len(path) > limits["path_max_length"]:
        indicators.add("path_too_long")

    if len(query_string) > limits["query_max_length"]:
        indicators.add("query_too_long")

    if len(request.args) > limits["max_query_params"]:
        indicators.add("too_many_query_params")

    normalized_probe = f"{path} {query_string}".lower()
    if "../" in normalized_probe or "..\\" in normalized_probe or "%2e%2e" in normalized_probe:
        indicators.add("path_traversal_probe")

    if "<script" in normalized_probe or "%3cscript" in normalized_probe:
        indicators.add("xss_probe")

    for source, value in (
        ("path", path),
        ("query", query_string),
    ):
        for marker in find_sql_injection_indicators(value):
            indicators.add(f"{source}_{marker}")

    for key in request.args:
        value = request.args.get(key, "")
        for marker in find_sql_injection_indicators(value):
            indicators.add(f"query_param_{marker}")

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        for key in request.form:
            value = request.form.get(key, "")
            for marker in find_sql_injection_indicators(value):
                indicators.add(f"form_{marker}")

    return sorted(indicators)


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


def get_login_client_id():
    trust_proxy_headers = flask.current_app.config.get("TRUST_PROXY_HEADERS", False)
    forwarded_for = flask.request.headers.get("X-Forwarded-For", "")
    if trust_proxy_headers and forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return flask.request.remote_addr or "unknown"


def _login_attempt_key(username, client_id):
    normalized_username = username.strip().lower() if isinstance(username, str) else ""
    return f"{client_id}:{normalized_username}"


def _login_limit_config():
    if not flask.has_app_context():
        return _MAX_FAILED_LOGIN_ATTEMPTS, _LOGIN_LOCKOUT_SECONDS

    max_attempts = flask.current_app.config.get(
        "LOGIN_MAX_FAILED_ATTEMPTS", _MAX_FAILED_LOGIN_ATTEMPTS
    )
    lockout_seconds = flask.current_app.config.get(
        "LOGIN_LOCKOUT_SECONDS", _LOGIN_LOCKOUT_SECONDS
    )
    return max_attempts, lockout_seconds


def is_login_temporarily_blocked(username, client_id, now=None):
    now = now or datetime.utcnow()
    key = _login_attempt_key(username, client_id)

    with _FAILED_LOGIN_ATTEMPTS_LOCK:
        attempt = _FAILED_LOGIN_ATTEMPTS.get(key)
        if not attempt:
            return False, 0

        locked_until = attempt.get("locked_until")
        if not locked_until:
            return False, 0

        if locked_until <= now:
            _FAILED_LOGIN_ATTEMPTS.pop(key, None)
            return False, 0

        return True, int((locked_until - now).total_seconds())


def record_failed_login_attempt(username, client_id, now=None):
    now = now or datetime.utcnow()
    max_attempts, lockout_seconds = _login_limit_config()
    key = _login_attempt_key(username, client_id)

    with _FAILED_LOGIN_ATTEMPTS_LOCK:
        attempt = _FAILED_LOGIN_ATTEMPTS.get(key, {"count": 0, "locked_until": None})

        locked_until = attempt.get("locked_until")
        if locked_until and locked_until <= now:
            attempt = {"count": 0, "locked_until": None}

        attempt["count"] += 1

        if attempt["count"] >= max_attempts:
            attempt["locked_until"] = now + timedelta(seconds=lockout_seconds)

        _FAILED_LOGIN_ATTEMPTS[key] = attempt

        remaining = 0
        if attempt.get("locked_until"):
            remaining = max(0, int((attempt["locked_until"] - now).total_seconds()))

        return attempt["count"], remaining


def reset_failed_login_attempts(username, client_id):
    key = _login_attempt_key(username, client_id)
    with _FAILED_LOGIN_ATTEMPTS_LOCK:
        _FAILED_LOGIN_ATTEMPTS.pop(key, None)


def clear_failed_login_attempts():
    with _FAILED_LOGIN_ATTEMPTS_LOCK:
        _FAILED_LOGIN_ATTEMPTS.clear()


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


def hash_password(password):
    """
    Hash a plaintext password using bcrypt.
    
    Args:
        password: plaintext password string
    
    Returns:
        bcrypt hash as bytes (will be stored as string in DB)
    """
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')



def verify_password(password, hashed_password):
    """
    Verify a plaintext password against its bcrypt hash.

    Args:
        password: plaintext password to verify
        hashed_password: bcrypt hash from database

    Returns:
        True if password matches, False otherwise
    """
    if not password or not hashed_password:
        return False

    if isinstance(password, str):
        password = password.encode("utf-8")

    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode("utf-8")

    try:
        return bcrypt.checkpw(password, hashed_password)
    except (ValueError, TypeError):
        # Invalid bcrypt format (bad DB data)
        return False
