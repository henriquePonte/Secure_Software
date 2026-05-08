import flask
import pathlib
from datetime import datetime, timedelta
from .routes import auth, documents, admin, health
from .auth.security import (
    detect_suspicious_request_patterns,
    get_request_client_id,
    record_request_for_volume_alert,
)
from .services.security_alerts import create_security_alert
from .services.user import get_user_session_revoked_at
from .logger.logger import get_logger


logger = get_logger(__name__)


def _parse_session_timestamp(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None

def create_app():
    BASE_DIR = pathlib.Path(__file__).resolve().parents[1]

    app = flask.Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    # Basic secret (keep using proper secret in production via env var)
    app.secret_key = "dev-secret"

    # Session security & expiration configuration
    app.config.update(
        {
            # Lifetime used for inactivity/absolute checks below
            "PERMANENT_SESSION_LIFETIME": timedelta(minutes=10),
            # Ensure cookies are not accessible from JavaScript
            "SESSION_COOKIE_HTTPONLY": True,
            # Only send cookies over HTTPS (set to True for production)
            "SESSION_COOKIE_SECURE": True,
            # Helpful mitigation for CSRF in some cases
            "SESSION_COOKIE_SAMESITE": "Lax",
            # We'll manage refresh of last_active ourselves
            "SESSION_REFRESH_EACH_REQUEST": False,
            # Generate URLs assuming HTTPS-only deployment
            "PREFERRED_URL_SCHEME": "https",
            # Rate limiting / throttling for repeated failed login attempts
            "LOGIN_MAX_FAILED_ATTEMPTS": 3,
            "LOGIN_LOCKOUT_SECONDS": 300,
            "TRUST_PROXY_HEADERS": False,
            "SUSPICIOUS_PATH_MAX_LENGTH": 256,
            "SUSPICIOUS_QUERY_MAX_LENGTH": 1024,
            "SUSPICIOUS_MAX_QUERY_PARAMS": 30,
            "SECURITY_REQUEST_VOLUME_WINDOW_SECONDS": 60,
            "SECURITY_REQUEST_VOLUME_THRESHOLD": 100,
            "SECURITY_REQUEST_VOLUME_ALERT_COOLDOWN_SECONDS": 300,
        }
    )

    @app.before_request
    def monitor_suspicious_request_patterns():
        if flask.request.endpoint == "static":
            return None

        client_id = get_request_client_id(flask.request, app.config)
        should_alert, request_count, window_seconds = record_request_for_volume_alert(
            client_id,
            app.config,
        )

        if should_alert:
            create_security_alert(
                "request_volume",
                "High request volume detected",
                severity="warning",
                client_id=client_id,
                request_count=request_count,
                window_seconds=window_seconds,
                path=flask.request.path,
                method=flask.request.method,
            )
            logger.warning(
                "suspicious.high_request_volume client_id=%s request_count=%s "
                "window_seconds=%s path=%s",
                client_id,
                request_count,
                window_seconds,
                flask.request.path,
            )

        indicators = detect_suspicious_request_patterns(flask.request, app.config)

        if not indicators:
            return None

        user_id = flask.session.get("user_id", "anonymous")
        create_security_alert(
            "suspicious_request",
            "Suspicious request pattern detected",
            severity="warning",
            client_id=client_id,
            user_id=user_id,
            method=flask.request.method,
            path=flask.request.path,
            indicators=indicators,
        )

        logger.warning(
            "suspicious.request_detected method=%s path=%s remote_addr=%s user_id=%s indicators=%s",
            flask.request.method,
            flask.request.path,
            client_id,
            user_id,
            ",".join(indicators),
        )

        return None

    @app.before_request
    def enforce_session_timeout():
        # Only check authenticated sessions
        if "user_id" not in flask.session:
            return None

        authenticated_at = _parse_session_timestamp(flask.session.get("authenticated_at"))
        if authenticated_at:
            revoked_at = get_user_session_revoked_at(flask.session["user_id"])
            if revoked_at and authenticated_at <= revoked_at:
                username = flask.session.get("username")
                flask.session.clear()
                app.logger.info(f"Session revoked for user: {username}")

                if flask.request.endpoint == "auth.login":
                    return None

                flask.flash("Your session was revoked. Please log in again.", "error")
                return flask.redirect(flask.url_for("auth.login"))

        if flask.session.get("password_reset_required"):
            allowed_endpoints = {"auth.change_password", "auth.logout", "static"}
            if flask.request.endpoint not in allowed_endpoints:
                return flask.redirect(flask.url_for("auth.change_password"))

        last_active = flask.session.get("last_active")
        if last_active:
            try:
                last_dt = datetime.fromisoformat(last_active)
            except Exception:
                # Corrupt timestamp -> clear session
                flask.session.clear()
                return flask.redirect(flask.url_for("auth.login"))

            if datetime.utcnow() - last_dt > app.config["PERMANENT_SESSION_LIFETIME"]:
                username = flask.session.get("username")
                flask.session.clear()
                app.logger.info(f"Session expired for user: {username}")
                return flask.redirect(flask.url_for("auth.login"))

        # Update last_active on each valid request to implement inactivity timeout
        flask.session["last_active"] = datetime.utcnow().isoformat()

    app.register_blueprint(auth.bp)
    app.register_blueprint(documents.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(health.bp)

    return app
