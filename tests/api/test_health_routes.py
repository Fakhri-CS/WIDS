from flask import Flask

from wids import create_app
from wids.config import TestingConfig


def test_create_app_returns_flask_application() -> None:
    app = create_app(TestingConfig)

    assert isinstance(app, Flask)
    assert app.config["TESTING"] is True
    assert app.config["APP_ENV"] == "testing"


def test_health_endpoint_returns_api_and_database_status() -> None:
    app = create_app(TestingConfig)
    client = app.test_client()

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.content_type == "application/json"

    response_data = response.get_json()

    assert response_data == {
        "database": "up",
        "environment": "testing",
        "service": "wids-api",
        "status": "up",
    }


def test_unknown_endpoint_returns_not_found() -> None:
    app = create_app(TestingConfig)
    client = app.test_client()

    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
