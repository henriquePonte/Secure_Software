import flask
from ..auth.security import login_required
from ..auth.authorization import user_can_access_document
from ..services.user import get_all_users_for_sharing
from app.logger.logger import get_logger
from app.document.upload import is_allowed_file


from ..services.document import (
    get_user_by_id,
    share_document,
    get_user_documents,
    create_document,
    get_document_by_id,
    get_documents_shared_with_user,
)

logger = get_logger(__name__)
bp = flask.Blueprint("documents", __name__)


# LIST USER DOCUMENTS
@bp.route("/documents")
@login_required
def documents_page():
    user_id = flask.session.get("user_id")

    logger.info(f"documents.list accessed user_id={user_id}")

    my_docs = get_user_documents(user_id)
    shared_docs = get_documents_shared_with_user(user_id)

    my_docs = [dict(d) if not isinstance(d, dict) else d for d in my_docs]
    shared_docs = [dict(d) if not isinstance(d, dict) else d for d in shared_docs]

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
        logger.warning(f"upload.failed empty_file user_id={user_id}")
        return flask.redirect(flask.url_for("documents.documents_page"))

    # SECURITY CHECK
    ok, reason = is_allowed_file(uploaded_file.filename, uploaded_file)

    if not ok:
        logger.warning(
            f"upload.blocked user_id={user_id} file={uploaded_file.filename} reason={reason}"
        )
        flask.abort(400)

    logger.info(
        f"document.uploaded user_id={user_id} title={title} file={uploaded_file.filename}"
    )

    create_document(user_id, title, uploaded_file.filename)

    return flask.redirect(flask.url_for("documents.documents_page"))
# DETAILS
@bp.route("/documents/<int:document_id>")
@login_required
def document_details(document_id):
    user_id = flask.session.get("user_id")

    if not user_can_access_document(user_id, document_id):
        logger.warning(f"document.access_denied user_id={user_id} doc_id={document_id}")
        flask.abort(403)

    doc = get_document_by_id(document_id)

    if not doc:
        logger.warning(f"document.not_found doc_id={document_id}")
        flask.abort(404)

    logger.info(f"document.viewed user_id={user_id} doc_id={document_id}")

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
        logger.warning(f"share.failed doc_not_found doc_id={document_id}")
        flask.abort(404)

    if doc["owner_id"] != user_id:
        logger.warning(f"share.forbidden user_id={user_id} doc_id={document_id}")
        flask.abort(403)

    shared_with_id = flask.request.form.get("shared_with")

    if not shared_with_id:
        logger.warning(f"share.invalid_missing_target user_id={user_id} doc_id={document_id}")
        flask.abort(400)

    try:
        shared_with_id = int(shared_with_id)
    except ValueError:
        logger.warning(f"share.invalid_target_format user_id={user_id}")
        flask.abort(400)

    user = get_user_by_id(shared_with_id)

    if not user:
        logger.warning(f"share.target_not_found target_id={shared_with_id}")
        flask.abort(404)

    if user[2]:  # is_disabled
        logger.warning(f"share.target_disabled target_id={shared_with_id}")
        flask.abort(403)

    share_document(document_id, shared_with_id)
    logger.info(f"document.shared doc_id={document_id} from={user_id} to={shared_with_id}")

    return flask.redirect(
        flask.url_for("documents.document_details", document_id=document_id)
    )


# SHARED WITH ME
@bp.route("/shared")
@login_required
def shared_documents():
    user_id = flask.session.get("user_id")

    logger.info(f"shared.documents.access user_id={user_id}")

    docs = get_documents_shared_with_user(user_id)

    logger.info(f"shared.documents.returned user_id={user_id} count={len(docs)}")

    return flask.jsonify(docs)


def download_doc(document_id):
    doc = get_document_by_id(document_id)
    user_id = flask.session.get("user_id")

    if not doc:
        logger.warning(f"download.not_found user_id={user_id} doc_id={document_id}")
        flask.abort(404)

    if not user_can_access_document(user_id, document_id):
        logger.warning(f"download.denied user_id={user_id} doc_id={document_id}")
        flask.abort(403)

    logger.info(f"document.downloaded user_id={user_id} doc_id={document_id}")

    return flask.send_file(
        f"uploads/{doc['filename']}",
        as_attachment=True
    )

# MY DOCUMENTS DOWNLOAD
@bp.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    user_id = flask.session.get("user_id")
    logger.info(f"document.download.request user_id={user_id} doc_id={document_id}")

    return download_doc(document_id)

# SHARED DOCUMENTS DOWNLOAD
@bp.route("/shared/<int:document_id>/download")
@login_required
def download_shared_document(document_id):
    user_id = flask.session.get("user_id")
    logger.info(f"document.download.request user_id={user_id} doc_id={document_id}")
    return download_doc(document_id)
