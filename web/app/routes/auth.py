import flask
from datetime import datetime
from ..extensions import get_db
from ..services.user import get_user_by_username
from app.logger.logger import get_logger
from ..auth.rbac import is_admin_user
from ..auth.security import login_required, verify_password, validate_login_input,log_rejected_login_input

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

        validation_errors = validate_login_input(username, password)

        if validation_errors:
            log_rejected_login_input(validation_errors)

            logger.warning(
                f"Blocked suspicious login attempt username={username} reasons={validation_errors}"
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

        logger.warning(f"Login failed - invalid password or disabled user: {username}")

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