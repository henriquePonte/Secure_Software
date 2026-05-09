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


@pytest.mark.parametrize(
	"shared_with_value, content_type, body, expected_status",
	[
		("999", "application/x-www-form-urlencoded", {"shared_with": "999"}, 404),
		("-5", "application/x-www-form-urlencoded", {"shared_with": "-5"}, 404),
		("A+", "application/x-www-form-urlencoded", {"shared_with": "A+"}, 400),
		("malformed_json", "application/json", '{"shared_with":', 400),
	],
)
def test_invalid_grade_rejected(monkeypatch, client, shared_with_value, content_type, body, expected_status):
	document = {
		"id": 7,
		"title": "Alice Document",
		"filename": "alice.pdf",
		"owner_id": 1,
	}
	shared_calls = {"called": False}

	monkeypatch.setattr(
		documents_routes,
		"get_owned_document_or_abort",
		lambda user_id, document_id, missing_status=404: document,
	)
	monkeypatch.setattr(documents_routes, "get_user_by_id", lambda user_id: None)
	monkeypatch.setattr(
		documents_routes,
		"share_document",
		lambda document_id, shared_with_id: shared_calls.__setitem__("called", True),
	)

	login_as(client, user_id=1, username="alice")

	response = client.post(
		"/documents/7/share",
		data=body,
		content_type=content_type,
	)

	assert response.status_code == expected_status
	assert shared_calls["called"] is False
