"""Shared pytest fixtures for the WIDS backend."""

from collections.abc import Generator

import pytest
from flask import Flask
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy

from app import create_app
from app.extensions import db


@pytest.fixture()
def app() -> Generator[Flask, None, None]:
    """Create an isolated Flask application for each test."""
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": (
                "sqlite+pysqlite:///:memory:"
            ),
        }
    )

    yield application


@pytest.fixture()
def database(
    app: Flask,
) -> Generator[SQLAlchemy, None, None]:
    """Create and clean tables in the isolated test database."""
    with app.app_context():
        db.create_all()

        try:
            yield db
        finally:
            db.session.remove()
            db.drop_all()


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Create an HTTP test client for the Flask application."""
    return app.test_client()
