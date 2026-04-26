import flask
from ..extensions import get_db
from ..services.user import get_user_by_username

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

        conn = get_db()
        cur = conn.cursor()

        user = get_user_by_username(cur, username)

        cur.close()
        conn.close()

        if user and user[2] == password and not user[3]:
            flask.session.clear()
            flask.session["user_id"] = user[0]
            flask.session["username"] = username

            if username == "admin":
                return flask.redirect(flask.url_for("admin.dashboard"))
            else:
                return flask.redirect(flask.url_for("documents.documents_page"))

        flask.flash("Invalid credentials.", "error")

    return flask.render_template("login.html")


@bp.route("/logout")
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for("auth.login"))