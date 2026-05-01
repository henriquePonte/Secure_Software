import flask
from ..extensions import get_db
from .. import db
from ..auth.security import log_rejected_login_input, validate_login_input

bp = flask.Blueprint("auth", __name__)


@bp.route("/")
def index():
    if flask.session.get("user_id"):
        return flask.redirect(flask.url_for("documents.documents_page"))
    return flask.redirect(flask.url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if flask.request.method == "POST":
        username = flask.request.form.get("username", "")
        password = flask.request.form.get("password", "")

        validation_errors = validate_login_input(username, password)
        if validation_errors:
            log_rejected_login_input(validation_errors)
            flask.flash("Invalid credentials.", "error")
            return flask.render_template("login.html"), 400

        conn = get_db()
        cur = conn.cursor()

        user = db.get_user_by_username(cur, username)

        cur.close()
        conn.close()

        if user and user[2] == password and not user[3]:
            flask.session.clear()
            flask.session["user_id"] = user[0]
            flask.session["username"] = user[1]

            return flask.redirect(flask.url_for("documents.documents_page"))

        flask.flash("Invalid credentials.", "error")

    return flask.render_template("login.html")


@bp.route("/logout")
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for("auth.login"))
