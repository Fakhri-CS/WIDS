"""Shared pytest fixtures for the WIDS backend."""

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app import create_app


@pytest.fixture()
def app() -> Flask:
    """Create an isolated Flask application for each test."""
    application = create_app()

    application.config.update(
        TESTING=True,
    )

    yield application


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Create an HTTP test client for the Flask application."""
    return app.test_client()
