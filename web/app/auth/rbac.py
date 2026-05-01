import flask
from functools import wraps

from .authorization import user_can_access_document
from ..services.document import get_document_by_id


def is_admin_user():
    return flask.session.get("username") == "admin"


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:
            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("auth.login"))

        if not is_admin_user():
            flask.abort(403)

        return fn(*args, **kwargs)

    return wrapper


def can_access_document(user_id, document_id):
    return user_can_access_document(user_id, document_id)


def require_document_access(user_id, document_id):
    if not can_access_document(user_id, document_id):
        flask.abort(403)


def get_owned_document_or_abort(user_id, document_id, missing_status=404):
    document = get_document_by_id(document_id)

    if not document:
        flask.abort(missing_status)

    if document["owner_id"] != user_id:
        flask.abort(403)

    return document