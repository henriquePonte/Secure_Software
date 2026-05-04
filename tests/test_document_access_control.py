import io
import pathlib
import sys
import types

import flask
import pytest
from werkzeug.datastructures import FileStorage


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "web"))

psycopg2_stub = types.ModuleType("psycopg2")
psycopg2_stub.connect = lambda *args, **kwargs: (_ for _ in ()).throw(
    RuntimeError("psycopg2 stub should not be called")
)

extras_stub = types.ModuleType("psycopg2.extras")
extras_stub.RealDictCursor = object

psycopg2_stub.extras = extras_stub

sys.modules.setdefault("psycopg2", psycopg2_stub)
sys.modules.setdefault("psycopg2.extras", extras_stub)

from app.app import create_app
from app.routes import documents as documents_routes


@pytest.fixture
def app():
    test_app = create_app()
    test_app.config.update(TESTING=True)
    return test_app


@pytest.fixture
def client(app):
    return app.test_client()


def login_as(client, user_id, username="user"):
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = username


def test_owner_can_crud_document(monkeypatch, client):
    document = {
        "id": 7,
        "title": "Owner Document",
        "filename": "owner.pdf",
        "owner_id": 1,
    }
    calls = {"created": None, "updated_title": None, "updated_file": None, "deleted": None}

    monkeypatch.setattr(documents_routes, "can_access_document", lambda user_id, document_id: True)
    monkeypatch.setattr(documents_routes, "get_document_by_id", lambda document_id: document)
    monkeypatch.setattr(
        documents_routes,
        "get_owned_document_or_abort",
        lambda user_id, document_id, missing_status=404: document,
    )
    monkeypatch.setattr(documents_routes, "is_allowed_file", lambda filename, file_stream: (True, "OK"))
    monkeypatch.setattr(
        documents_routes,
        "create_document",
        lambda user_id, title, filename: calls.__setitem__("created", (user_id, title, filename)),
    )
    monkeypatch.setattr(
        documents_routes,
        "update_document_title",
        lambda document_id, new_title: calls.__setitem__("updated_title", (document_id, new_title)),
    )
    monkeypatch.setattr(
        documents_routes,
        "update_document_file",
        lambda document_id, filename: calls.__setitem__("updated_file", (document_id, filename)),
    )
    monkeypatch.setattr(
        documents_routes,
        "delete_document_by_id",
        lambda document_id: calls.__setitem__("deleted", document_id),
    )
    monkeypatch.setattr(documents_routes.os.path, "exists", lambda path: True)
    monkeypatch.setattr(documents_routes.os, "remove", lambda path: None)
    monkeypatch.setattr(
        documents_routes.flask,
        "send_file",
        lambda path, as_attachment=True: flask.Response("download-ok", status=200),
    )
    monkeypatch.setattr(FileStorage, "save", lambda self, dst, buffer_size=16384: None)

    login_as(client, user_id=1, username="alice")

    upload_response = client.post(
        "/documents/upload",
        data={
            "title": "New Document",
            "document": (io.BytesIO(b"sample"), "new.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code in (302, 303)
    assert calls["created"] is not None
    assert calls["created"][0] == 1
    assert calls["created"][1] == "New Document"
    assert calls["created"][2].endswith(".pdf")

    details_response = client.get("/documents/7")
    assert details_response.status_code == 200

    download_response = client.get("/documents/7/download")
    assert download_response.status_code == 200

    edit_response = client.post(
        "/documents/7/edit",
        data={
            "title": "Updated Title",
            "document": (io.BytesIO(b"updated"), "updated.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert edit_response.status_code in (302, 303)
    assert calls["updated_title"] == (7, "Updated Title")
    assert calls["updated_file"] is not None
    assert calls["updated_file"][0] == 7
    assert calls["updated_file"][1].endswith(".pdf")

    delete_response = client.post("/documents/7/delete")
    assert delete_response.status_code in (302, 303)
    assert calls["deleted"] == 7


def test_shared_user_can_view_and_download_but_not_modify(monkeypatch, client):
    document = {
        "id": 11,
        "title": "Shared Document",
        "filename": "shared.pdf",
        "owner_id": 1,
    }

    monkeypatch.setattr(documents_routes, "can_access_document", lambda user_id, document_id: True)
    monkeypatch.setattr(documents_routes, "get_document_by_id", lambda document_id: document)
    monkeypatch.setattr(
        documents_routes,
        "get_owned_document_or_abort",
        lambda user_id, document_id, missing_status=404: flask.abort(403),
    )
    monkeypatch.setattr(documents_routes.os.path, "exists", lambda path: True)
    monkeypatch.setattr(
        documents_routes.flask,
        "send_file",
        lambda path, as_attachment=True: flask.Response("download-ok", status=200),
    )

    login_as(client, user_id=2, username="bob")

    details_response = client.get("/documents/11")
    assert details_response.status_code == 200

    download_response = client.get("/shared/11/download")
    assert download_response.status_code == 200

    edit_response = client.post("/documents/11/edit", data={"title": "Nope"})
    assert edit_response.status_code == 403

    delete_response = client.post("/documents/11/delete")
    assert delete_response.status_code == 403

    share_response = client.post("/documents/11/share", data={"shared_with": "3"})
    assert share_response.status_code == 403


def test_unauthorized_user_cannot_access_document(monkeypatch, client):
    document = {
        "id": 22,
        "title": "Private Document",
        "filename": "private.pdf",
        "owner_id": 1,
    }

    monkeypatch.setattr(documents_routes, "can_access_document", lambda user_id, document_id: False)
    monkeypatch.setattr(documents_routes, "get_document_by_id", lambda document_id: document)
    monkeypatch.setattr(
        documents_routes,
        "get_owned_document_or_abort",
        lambda user_id, document_id, missing_status=404: flask.abort(403),
    )

    login_as(client, user_id=3, username="eve")

    details_response = client.get("/documents/22")
    assert details_response.status_code == 403

    owned_download_response = client.get("/documents/22/download")
    assert owned_download_response.status_code == 403

    shared_download_response = client.get("/shared/22/download")
    assert shared_download_response.status_code == 403

    edit_response = client.post("/documents/22/edit", data={"title": "Blocked"})
    assert edit_response.status_code == 403

    delete_response = client.post("/documents/22/delete")
    assert delete_response.status_code == 403

    share_response = client.post("/documents/22/share", data={"shared_with": "2"})
    assert share_response.status_code == 403
