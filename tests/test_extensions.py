"""Tests for Flask database extension initialization."""

from flask import Flask

from app.extensions import db


def test_database_extensions_are_initialized(app: Flask) -> None:
    """SQLAlchemy and Flask-Migrate should initialize successfully."""
    assert "sqlalchemy" in app.extensions
    assert "migrate" in app.extensions

    with app.app_context():
        assert db.engine.url.drivername == "sqlite+pysqlite"
        assert db.engine.url.database == ":memory:"

