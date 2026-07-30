import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration shared by the WIDS API."""

    APP_ENV = os.getenv("APP_ENV", "development")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "development-only-change-this-value",
    )

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        ("postgresql+psycopg://wids_user:wids_local_dev_2026@localhost:5432/wids_db"),
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }


class TestingConfig(Config):
    """Configuration used by automated tests."""

    TESTING = True
    APP_ENV = "testing"
    SECRET_KEY = "testing-secret-key"

    SQLALCHEMY_DATABASE_URI = "sqlite+pysqlite:///:memory:"

    SQLALCHEMY_ENGINE_OPTIONS = {}
