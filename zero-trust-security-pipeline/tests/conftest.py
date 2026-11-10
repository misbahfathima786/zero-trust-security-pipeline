"""Shared pytest setup. Tests run against an in-memory database."""
import os
import sys
from pathlib import Path

# Must be set before app.py is imported (Config reads the environment at import).
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-real")
os.environ["DATABASE_URL"] = "sqlite://"

APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

import pytest  # noqa: E402


@pytest.fixture()
def app():
    from app import app as flask_app
    from extensions import db
    from models.user import User

    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with flask_app.app_context():
        db.create_all()
        user = User(display_name="Test User", email="test@example.com")
        user.set_password("not-a-real-password")
        db.session.add(user)
        db.session.commit()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def logged_in(client):
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    return client
