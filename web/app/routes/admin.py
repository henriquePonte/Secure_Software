import flask
from ..services.user import get_all_users, revoke_user_sessions, set_user_disabled
from app.logger.logger import get_logger
from ..auth.rbac import admin_required

bp = flask.Blueprint("admin", __name__)
logger = get_logger(__name__)

@bp.route("/admin/dashboard")
@admin_required
def dashboard():
    logger.info(f"Admin accessed dashboard")
    users = get_all_users()

    return flask.render_template(
        "adminDashboard.html",
        users=users,
    )

@bp.route("/admin/users")
@admin_required
def admin_users():
    logger.info("Admin fetched users list")
    users = get_all_users()

    return flask.jsonify([
        {
            "id": u["id"],
            "username": u["username"],
            "is_disabled": u["is_disabled"],
            "session_revoked_at": u["session_revoked_at"],
        }
        for u in users
    ])

@bp.route("/admin/users/enable", methods=["POST"])
@admin_required
def enable_user():
    user_id = flask.request.form.get("user_id")

    if str(user_id) == str(flask.session.get("user_id")):
        logger.warning(f"Admin tried to enable themselves (user_id={user_id})")
        return flask.jsonify({"error": "Cannot modify yourself"}), 400

    logger.info(f"Admin enabled user_id={user_id}")
    set_user_disabled(user_id, False)

    return flask.jsonify({"success": True, "status": "enabled"})

@bp.route("/admin/users/disable", methods=["POST"])
@admin_required
def disable_user():
    user_id = flask.request.form.get("user_id")

    if str(user_id) == str(flask.session.get("user_id")):
        logger.warning(f"Admin tried to disable themselves (user_id={user_id})")
        return flask.jsonify({"error": "Cannot modify yourself"}), 400

    logger.info(f"Admin disabled user_id={user_id}")
    set_user_disabled(user_id, True)

    return flask.jsonify({"success": True, "status": "disabled"})


@bp.route("/admin/users/revoke-sessions", methods=["POST"])
@admin_required
def revoke_sessions():
    user_id = flask.request.form.get("user_id")

    if str(user_id) == str(flask.session.get("user_id")):
        logger.warning(f"Admin tried to revoke their own sessions (user_id={user_id})")
        return flask.jsonify({"error": "Cannot revoke your own sessions"}), 400

    if not revoke_user_sessions(user_id):
        logger.warning(f"Admin tried to revoke sessions for missing user_id={user_id}")
        return flask.jsonify({"error": "User not found"}), 404

    logger.info(f"Admin revoked sessions for user_id={user_id}")
    return flask.jsonify({"success": True, "status": "sessions_revoked"})
