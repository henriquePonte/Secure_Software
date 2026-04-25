import flask
from ..auth.security import login_required
from ..services.documents_service import (
    get_user_by_id,
    share_document,
    get_user_documents,
    create_document,
    get_document_by_id
)

from ..services.user_service import get_all_users_for_sharing

bp = flask.Blueprint("documents", __name__)


@bp.route("/documents")
@login_required
def documents_page():
    requested_user_id = flask.request.args.get("user_id")
    current_user_id = flask.session.get("user_id")

    owner_id = requested_user_id or current_user_id

    docs = get_user_documents(owner_id)
    users = get_all_users_for_sharing(owner_id)

    return flask.render_template(
            "documents.html",
            documents=docs,
            users=users
        )


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


@bp.route("/documents/<int:document_id>/share", methods=["POST"])
@login_required
def share_document_route(document_id):
    doc = get_document_by_id(document_id)

    if doc["owner_id"] != flask.session["user_id"]:
        flask.abort(403)

    shared_with_id = flask.request.form.get("shared_with")

    # validar input
    if not shared_with_id:
        flask.abort(400)

    try:
        shared_with_id = int(shared_with_id)
    except ValueError:
        flask.abort(400)

    # validar user destino
    user = get_user_by_id(shared_with_id)

    if not user:
        flask.abort(404)

    if user[2]:  # is_disabled
        flask.abort(403)

    # criar relação na BD
    share_document(document_id, shared_with_id)

    return flask.redirect(
        flask.url_for("documents.document_details", document_id=document_id)
    )