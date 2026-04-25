import flask
from ..security import login_required
from ..services.documents_service import (
    get_user_documents,
    create_document,
    get_document_by_id
)

bp = flask.Blueprint("documents", __name__)


@bp.route("/documents")
@login_required
def documents_page():
    requested_user_id = flask.request.args.get("user_id")
    current_user_id = flask.session.get("user_id")

    owner_id = requested_user_id or current_user_id

    docs = get_user_documents(owner_id)

    return flask.render_template("documents.html", documents=docs)


@bp.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    user_id = flask.session.get("user_id")
    title = flask.request.form.get("title", "Untitled")
    uploaded_file = flask.request.files.get("document")

    if not uploaded_file or uploaded_file.filename == "":
        return flask.redirect(flask.url_for("documents.documents_page"))

    create_document(user_id, title, uploaded_file.filename)

    return flask.redirect(flask.url_for("documents.documents_page"))


@bp.route("/documents/<int:document_id>")
@login_required
def document_details(document_id):
    doc = get_document_by_id(document_id)

    if not doc:
        flask.abort(404)

    return flask.render_template("document_details.html", document=doc)