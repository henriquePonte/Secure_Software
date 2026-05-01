import flask
from datetime import datetime
from ..extensions import get_db
from ..services.user import get_user_by_username
from app.logger.logger import get_logger
from ..auth.rbac import is_admin_user
from ..auth.security import (
    get_login_client_id,
    is_login_temporarily_blocked,
    log_rejected_login_input,
    login_required,
    record_failed_login_attempt,
    reset_failed_login_attempts,
    validate_login_input,
    verify_password,
)

bp = flask.Blueprint("auth", __name__)

logger = get_logger(__name__)


@bp.route("/")
def index():
    user_id = flask.session.get("user_id")
    if flask.session.get("user_id"):
        logger.info(f"Authenticated user_id={user_id} redirected to documents_page")
        return flask.redirect(flask.url_for("documents.documents_page"))
    logger.info("Anonymous user redirected to login page")
    return flask.redirect(flask.url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if flask.request.method == "POST":
        username = flask.request.form.get("username", "")
        password = flask.request.form.get("password", "")
        client_id = get_login_client_id()

        is_blocked, retry_after = is_login_temporarily_blocked(username, client_id)
        if is_blocked:
            logger.warning(
                f"Login throttled username={username} client_id={client_id} "
                f"retry_after_seconds={retry_after}"
            )
            flask.flash("Too many failed login attempts. Please try again later.", "error")
            return flask.render_template("login.html"), 429

        validation_errors = validate_login_input(username, password)

        if validation_errors:
            log_rejected_login_input(validation_errors)
            failed_count, lockout_seconds = record_failed_login_attempt(username, client_id)

            logger.warning(
                f"Blocked suspicious login attempt username={username} "
                f"client_id={client_id} reasons={validation_errors} "
                f"failed_count={failed_count} lockout_seconds={lockout_seconds}"
            )

            flask.flash("Invalid credentials.", "error")
            return flask.render_template("login.html"), 400

        logger.info(f"Login attempt for username={username}")

        conn = get_db()
        cur = conn.cursor()

        user = get_user_by_username(cur, username)

        cur.close()
        conn.close()

        if user and verify_password(password, user[2]) and not user[3]:
            reset_failed_login_attempts(username, client_id)
            flask.session.clear()
            flask.session["user_id"] = user[0]
            flask.session["username"] = username
            # Make the session permanent so Flask will consider the
            # `PERMANENT_SESSION_LIFETIME` configuration value.
            flask.session.permanent = True
            # Track last activity to enforce inactivity expiration.
            flask.session["last_active"] = datetime.utcnow().isoformat()

            logger.info(f"Login successful for user_id={user[0]}, username={username}")

            if is_admin_user():
                logger.info("Admin redirected to dashboard")
                return flask.redirect(flask.url_for("admin.dashboard"))
            else:
                logger.info("user redirected to documents_page")
                return flask.redirect(flask.url_for("documents.documents_page"))

        failed_count, lockout_seconds = record_failed_login_attempt(username, client_id)

        logger.warning(
            f"Login failed - invalid password or disabled user: {username} "
            f"client_id={client_id} failed_count={failed_count} "
            f"lockout_seconds={lockout_seconds}"
        )

        flask.flash("Invalid credentials.", "error")
        return flask.redirect(flask.url_for("auth.login"))

    return flask.render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    username = flask.session.get("username")
    flask.session.clear()
    logger.info(f"User logged out: {username}")
    return flask.redirect(flask.url_for("auth.login"))
