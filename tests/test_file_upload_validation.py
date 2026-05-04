import io
import pathlib
import sys
import types

import pytest


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


def test_invalid_upload_returns_400_and_does_not_create_document(monkeypatch, client):
    called = {"create": False}

    monkeypatch.setattr(
        documents_routes,
        "is_allowed_file",
        lambda filename, file_stream: (False, "Invalid file extension"),
    )
    monkeypatch.setattr(
        documents_routes,
        "create_document",
        lambda user_id, title, filename: called.__setitem__("create", True),
    )

    login_as(client, user_id=1, username="alice")

    response = client.post(
        "/documents/upload",
        data={
            "title": "Malicious",
            "document": (io.BytesIO(b"payload"), "payload.exe"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert called["create"] is False


def test_invalid_file_on_edit_returns_400_and_does_not_update_file(monkeypatch, client):
    document = {
        "id": 3,
        "title": "Stable title",
        "filename": "existing.pdf",
        "owner_id": 1,
    }
    called = {"update_file": False}

    monkeypatch.setattr(
        documents_routes,
        "get_owned_document_or_abort",
        lambda user_id, document_id, missing_status=404: document,
    )
    monkeypatch.setattr(
        documents_routes,
        "is_allowed_file",
        lambda filename, file_stream: (False, "Invalid file extension"),
    )
    monkeypatch.setattr(
        documents_routes,
        "update_document_file",
        lambda document_id, filename: called.__setitem__("update_file", True),
    )

    login_as(client, user_id=1, username="alice")

    response = client.post(
        "/documents/3/edit",
        data={
            "title": "Stable title",
            "document": (io.BytesIO(b"payload"), "payload.exe"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert called["update_file"] is False
