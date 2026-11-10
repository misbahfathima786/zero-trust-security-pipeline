
import os


class Config:
    # Application security
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///securebuild.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Team registration
    TEAM_INVITE_CODE = os.environ.get("TEAM_INVITE_CODE")

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Enable True when deployed with HTTPS

    # CSRF protection
    WTF_CSRF_ENABLED = True
