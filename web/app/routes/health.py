import flask
from ..extensions import get_db
from ..auth.security import login_required

bp = flask.Blueprint("health", __name__)

@bp.route("/health")
@login_required
def health():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        return {"status": "ok"}, 200
    except Exception:
        return {"status": "error"}, 500