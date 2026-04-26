import flask
from ..services.user import get_all_users

bp = flask.Blueprint("admin", __name__)

@bp.route("/admin/dashboard")
def dashboard():

    username = flask.session.get("username")

    if username != "admin":
        flask.abort(403)

    users = get_all_users()

    return flask.render_template(
        "adminDashboard.html",
        users=users,
    )

@bp.route("/admin/users")
def admin_users():

    if flask.session.get("username") != "admin":
        flask.abort(403)

    users = get_all_users()

    return flask.jsonify([
        {
            "id": u["id"],
            "username": u["username"],
            "is_disabled": u["is_disabled"]
        }
        for u in users
    ])
