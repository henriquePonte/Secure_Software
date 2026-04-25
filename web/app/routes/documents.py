import flask
import psycopg2.extras
from ..extensions import get_db
from ..security import login_required

bp = flask.Blueprint("documents", __name__)


@bp.route("/documents")
@login_required
def documents_page():
    requested_user_id = flask.request.args.get("user_id")
    current_user_id = flask.session.get("user_id")

    owner_id = requested_user_id or current_user_id

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, title, filename, uploaded_at
                FROM documents
                WHERE owner_id = %s
                ORDER BY uploaded_at DESC
                """, (owner_id,))

    docs = cur.fetchall()

    cur.close()
    conn.close()

    return flask.render_template("documents.html", documents=docs)


@bp.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    user_id = flask.session.get("user_id")
    title = flask.request.form.get("title", "Untitled")
    uploaded_file = flask.request.files.get("document")

    if not uploaded_file or uploaded_file.filename == "":
        return flask.redirect(flask.url_for("documents.documents_page"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                INSERT INTO documents (owner_id, title, filename)
                VALUES (%s, %s, %s)
                """, (user_id, title, uploaded_file.filename))

    conn.commit()
    cur.close()
    conn.close()

    return flask.redirect(flask.url_for("documents.documents_page"))


@bp.route("/documents/<int:document_id>")
@login_required
def document_details(document_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, title, filename, uploaded_at, owner_id
                FROM documents
                WHERE id = %s
                """, (document_id,))

    doc = cur.fetchone()

    cur.close()
    conn.close()

    if not doc:
        flask.abort(404)

    return flask.render_template("document_details.html", document=doc)