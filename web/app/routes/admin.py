import flask

bp = flask.Blueprint("admin", __name__)

@bp.route("/admin/users")
def users():
    return "Admin users page (TODO)"