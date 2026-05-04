import flask
import pathlib
from datetime import datetime, timedelta
from .routes import auth, documents, admin, health
from .auth.security import detect_suspicious_request_patterns
from .logger.logger import get_logger


logger = get_logger(__name__)

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
        }
    )

    @app.before_request
    def monitor_suspicious_request_patterns():
        indicators = detect_suspicious_request_patterns(flask.request, app.config)

        if not indicators:
            return None

        remote_addr = flask.request.headers.get("X-Forwarded-For", flask.request.remote_addr)
        user_id = flask.session.get("user_id", "anonymous")

        logger.warning(
            "suspicious.request_detected method=%s path=%s remote_addr=%s user_id=%s indicators=%s",
            flask.request.method,
            flask.request.path,
            remote_addr,
            user_id,
            ",".join(indicators),
        )

        return None

    @app.before_request
    def enforce_session_timeout():
        # Only check authenticated sessions
        if "user_id" not in flask.session:
            return None

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
