import flask
from ..services.user import get_all_users,set_user_disabled
from app.logger.logger import get_logger
from ..auth.security import login_required

bp = flask.Blueprint("admin", __name__)
logger = get_logger(__name__)

@bp.route("/admin/dashboard")
@login_required
def dashboard():

    username = flask.session.get("username")

    if username != "admin":
        logger.warning(f"Unauthorized dashboard access attempt by {username}")
        flask.abort(403)

    logger.info(f"Admin accessed dashboard")
    users = get_all_users()

    return flask.render_template(
        "adminDashboard.html",
        users=users,
    )

@bp.route("/admin/users")
@login_required
def admin_users():

    if flask.session.get("username") != "admin":
        logger.warning("Unauthorized attempt to access users list")
        flask.abort(403)

    logger.info("Admin fetched users list")
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
@login_required
def enable_user():

    if flask.session.get("username") != "admin":
        logger.warning("Unauthorized enable attempt")
        flask.abort(403)

    user_id = flask.request.form.get("user_id")

    if str(user_id) == str(flask.session.get("user_id")):
        logger.warning(f"Admin tried to enable themselves (user_id={user_id})")
        return flask.jsonify({"error": "Cannot modify yourself"}), 400

    logger.info(f"Admin enabled user_id={user_id}")
    set_user_disabled(user_id, False)

    return flask.jsonify({"success": True, "status": "enabled"})

@bp.route("/admin/users/disable", methods=["POST"])
@login_required
def disable_user():

    if flask.session.get("username") != "admin":
        logger.warning("Unauthorized disable attempt")
        flask.abort(403)

    user_id = flask.request.form.get("user_id")

    if str(user_id) == str(flask.session.get("user_id")):
        logger.warning(f"Admin tried to disable themselves (user_id={user_id})")
        return flask.jsonify({"error": "Cannot modify yourself"}), 400

    logger.info(f"Admin disabled user_id={user_id}")
    set_user_disabled(user_id, True)

    return flask.jsonify({"success": True, "status": "disabled"})