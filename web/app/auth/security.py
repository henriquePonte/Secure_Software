import flask
from functools import wraps


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:
            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("auth.login"))
        return fn(*args, **kwargs)

    return wrapper


def get_current_user_id():
    return flask.session.get("user_id")


def get_current_username():
    return flask.session.get("username")


def is_authenticated():
    return "user_id" in flask.session