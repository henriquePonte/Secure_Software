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


@pytest.fixture
def app():
	test_app = create_app()
	test_app.config.update(TESTING=True)
	return test_app


@pytest.fixture
def client(app):
	return app.test_client()


def test_unauthenticated_user_cannot_access_profile(client):
	responses = [
		client.get("/documents"),
		client.get("/documents/1"),
		client.get("/documents/1/edit"),
		client.post("/documents/1/delete"),
		client.get("/logout"),
		client.get("/change-password"),
	]

	for response in responses:
		assert response.status_code in (302, 303)
		assert "/login" in response.headers.get("Location", "")
