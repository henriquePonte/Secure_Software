import io
import logging
import pathlib
import sys
import types

import pytest
from werkzeug.datastructures import FileStorage


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
	"filename",
	[
		"../../etc/passwd.pdf",
		"..%2F..%2Fetc%2Fpasswd.pdf",
		"/etc/passwd.pdf",
	],
)
def test_path_traversal_blocked(monkeypatch, client, filename):
	captured = {"save_path": None, "created_filename": None}

	monkeypatch.setattr(documents_routes, "is_allowed_file", lambda filename, file_stream: (True, "OK"))
	monkeypatch.setattr(
		documents_routes,
		"create_document",
		lambda user_id, title, new_filename: captured.__setitem__("created_filename", new_filename),
	)
	monkeypatch.setattr(
		FileStorage,
		"save",
		lambda self, dst, buffer_size=16384: captured.__setitem__("save_path", dst),
	)

	login_as(client, user_id=1, username="alice")

	response = client.post(
		"/documents/upload",
		data={"title": "Traversal attempt", "document": (io.BytesIO(b"payload"), filename)},
		content_type="multipart/form-data",
	)

	assert response.status_code in (302, 303)
	assert captured["save_path"] is not None
	assert captured["save_path"].startswith("uploads")
	assert ".." not in captured["save_path"]
	assert "/" not in captured["save_path"].replace("uploads/", "", 1)
	assert "\\" not in captured["save_path"].replace("uploads\\", "", 1)
	assert captured["created_filename"] is not None
	assert captured["created_filename"].endswith(".pdf")
