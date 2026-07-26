"""Tests for the health controller."""

from http import HTTPStatus

from flask.testing import FlaskClient


def test_get_health_returns_success(client: FlaskClient) -> None:
    """GET /health should return the backend health information."""
    response = client.get("/health")

    assert response.status_code == HTTPStatus.OK
    assert response.content_type == "application/json"

    assert response.get_json() == {
        "service": "wids-backend",
        "status": "ok",
    }


def test_unknown_endpoint_returns_not_found(client: FlaskClient) -> None:
    """An unregistered endpoint should return HTTP 404."""
    response = client.get("/endpoint-that-does-not-exist")

    assert response.status_code == HTTPStatus.NOT_FOUND
