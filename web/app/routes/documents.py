import flask
from ..auth.security import login_required
from ..auth.authorization import user_can_access_document

from ..services.documents_service import (
    get_user_by_id,
    share_document,
    get_user_documents,
    create_document,
    get_document_by_id,
    get_documents_shared_with_user
)

from ..services.user_service import get_all_users_for_sharing

bp = flask.Blueprint("documents", __name__)


# LIST USER DOCUMENTS
@bp.route("/documents")
@login_required
def documents_page():
    user_id = flask.session.get("user_id")

    my_docs = get_user_documents(user_id)
    shared_docs = get_documents_shared_with_user(user_id)

    for d in my_docs:
        d["is_owner"] = True

    for d in shared_docs:
        d["is_owner"] = False

    docs = my_docs + shared_docs

    users = get_all_users_for_sharing(user_id)

    return flask.render_template(
        "documents.html",
        documents=docs,
        users=users,
        current_user_id=user_id
    )

# UPLOAD
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


# DETAILS
@bp.route("/documents/<int:document_id>")
@login_required
def document_details(document_id):
    user_id = flask.session.get("user_id")

    if not user_can_access_document(user_id, document_id):
        flask.abort(403)

    doc = get_document_by_id(document_id)

    if not doc:
        flask.abort(404)

    return flask.render_template(
        "document_details.html",
        document=doc
    )


# SHARE
@bp.route("/documents/<int:document_id>/share", methods=["POST"])
@login_required
def share_document_route(document_id):
    user_id = flask.session.get("user_id")

    doc = get_document_by_id(document_id)

    if not doc:
        flask.abort(404)

    if doc["owner_id"] != user_id:
        flask.abort(403)

    shared_with_id = flask.request.form.get("shared_with")

    if not shared_with_id:
        flask.abort(400)

    try:
        shared_with_id = int(shared_with_id)
    except ValueError:
        flask.abort(400)

    user = get_user_by_id(shared_with_id)

    if not user:
        flask.abort(404)

    if user[2]:  # is_disabled
        flask.abort(403)

    share_document(document_id, shared_with_id)

    return flask.redirect(
        flask.url_for("documents.document_details", document_id=document_id)
    )


# SHARED WITH ME
@bp.route("/shared")
@login_required
def shared_documents():
    user_id = flask.session.get("user_id")

    docs = get_documents_shared_with_user(user_id)

    return flask.jsonify(docs)


# DOWNLOAD
@bp.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    doc = get_document_by_id(document_id)
    user_id = flask.session.get("user_id")

    if not doc:
        flask.abort(404)

    if not user_can_access_document(user_id, document_id):
        flask.abort(403)

    return flask.send_file(
        f"uploads/{doc['filename']}",
        as_attachment=True
    )