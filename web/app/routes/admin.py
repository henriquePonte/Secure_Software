import flask
from ..services.user import get_all_users,set_user_disabled

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

@bp.route("/admin/users/enable", methods=["POST"])
def enable_user():

    if flask.session.get("username") != "admin":
        flask.abort(403)

    user_id = flask.request.form.get("user_id")

    if str(user_id) == str(flask.session.get("user_id")):
        return flask.jsonify({"error": "Cannot modify yourself"}), 400

    set_user_disabled(user_id, False)

    return flask.jsonify({"success": True, "status": "enabled"})

@bp.route("/admin/users/disable", methods=["POST"])
def disable_user():

    if flask.session.get("username") != "admin":
        flask.abort(403)

    user_id = flask.request.form.get("user_id")

    if str(user_id) == str(flask.session.get("user_id")):
        return flask.jsonify({"error": "Cannot modify yourself"}), 400

    set_user_disabled(user_id, True)

    return flask.jsonify({"success": True, "status": "disabled"})