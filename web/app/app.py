import flask
import pathlib
from .routes import auth, documents, admin, health

def create_app():
    BASE_DIR = pathlib.Path(__file__).resolve().parents[1]

    app = flask.Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.secret_key = "dev-secret"

    app.register_blueprint(auth.bp)
    app.register_blueprint(documents.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(health.bp)

    return app