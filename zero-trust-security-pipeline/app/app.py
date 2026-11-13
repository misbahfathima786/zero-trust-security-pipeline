
import os
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables before importing Config.
for _parent in Path(__file__).resolve().parents:
    _env = _parent / ".env"
    if _env.is_file():
        load_dotenv(_env)
        break

from flask import Flask, redirect, url_for
from flask_login import current_user

from app.config import Config
from app.extensions import db, login_manager, csrf
from app.models import User, Project, ScanRun
from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.pipeline import pipeline_bp
from app.routes.scans import scans_bp
from app.routes.vulnerabilities import vulnerabilities_bp
from app.routes.sbom import sbom_bp
from app.routes.history import history_bp
from app.template_helpers import register as register_template_helpers


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_object(Config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY is missing. Please configure it in the .env file."
        )

    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize extensions.
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Load the logged-in user.
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (ValueError, TypeError):
            return None

    # Register application routes.
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(pipeline_bp, url_prefix="/pipeline")
    app.register_blueprint(scans_bp, url_prefix="/scans")
    app.register_blueprint(vulnerabilities_bp, url_prefix="/vulnerabilities")
    app.register_blueprint(sbom_bp, url_prefix="/sbom")
    app.register_blueprint(history_bp, url_prefix="/history")
    register_template_helpers(app)

    # Aliases for vulnerability scan routes.
    @app.route("/scans/trivy")
    @app.route("/scans/vulnerabilities")
    def scans_trivy_alias():
        return redirect(url_for("vulnerabilities.index"))

    @app.route("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))

        return redirect(url_for("auth.login"))

    # Create database tables.
    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
