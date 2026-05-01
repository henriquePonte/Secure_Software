import flask
from functools import wraps
import bcrypt


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


def hash_password(password):
    """
    Hash a plaintext password using bcrypt.
    
    Args:
        password: plaintext password string
    
    Returns:
        bcrypt hash as bytes (will be stored as string in DB)
    """
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password, hashed_password):
    """
    Verify a plaintext password against its bcrypt hash.
    
    Args:
        password: plaintext password to verify
        hashed_password: bcrypt hash from database
    
    Returns:
        True if password matches, False otherwise
    """
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    return bcrypt.checkpw(password, hashed_password)