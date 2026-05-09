import logging
import pathlib
import sys
import types

import pytest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "web"))

psycopg2_stub = types.ModuleType("psycopg2")
psycopg2_stub.connect = lambda *args, **kwargs: (_ for _ in ()).throw(
	RuntimeError("psycopg2 stub should not be called")
)

extras_stub = types.ModuleType("psycopg2.extras")
extras_stub.RealDictCursor = object

psycopg2_stub.extras = extras_stub

sys.modules.setdefault("psycopg2", psycopg2_stub)
sys.modules.setdefault("psycopg2.extras", extras_stub)

logger_stub = types.ModuleType("app.logger.logger")
logger_stub.get_logger = lambda name: logging.getLogger(name)
sys.modules["app.logger.logger"] = logger_stub

from app.app import create_app
from app.auth import rbac as rbac_helpers
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


def test_student_cannot_access_other_profile(monkeypatch, client):
	bob_document = {
		"id": 22,
		"title": "Bob Secret",
		"filename": "bob.pdf",
		"owner_id": 2,
	}

	monkeypatch.setattr(documents_routes, "can_access_document", lambda user_id, document_id: False)
	monkeypatch.setattr(documents_routes, "get_document_by_id", lambda document_id: bob_document)
	monkeypatch.setattr(rbac_helpers, "get_document_by_id", lambda document_id: bob_document)

	login_as(client, user_id=1, username="alice")

	assert client.get("/documents/22").status_code == 403
	assert client.get("/documents/22/download").status_code == 403
	assert client.get("/shared/22/download").status_code == 403


def test_student_cannot_update_grades(monkeypatch, client):
	bob_document = {
		"id": 7,
		"title": "Bob Grade Sheet",
		"filename": "bob-grade-sheet.pdf",
		"owner_id": 2,
	}
	updates = {"title": False, "file": False}

	monkeypatch.setattr(rbac_helpers, "get_document_by_id", lambda document_id: bob_document)
	monkeypatch.setattr(
		documents_routes,
		"update_document_title",
		lambda document_id, new_title: updates.__setitem__("title", True),
	)
	monkeypatch.setattr(
		documents_routes,
		"update_document_file",
		lambda document_id, filename: updates.__setitem__("file", True),
	)

	login_as(client, user_id=1, username="alice")

	response = client.post(
		"/documents/7/edit",
		data={"title": "Grade tampering attempt"},
	)

	assert response.status_code == 403
	assert updates == {"title": False, "file": False}
