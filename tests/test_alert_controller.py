"""Tests for the alert controller."""

from http import HTTPStatus

from flask.testing import FlaskClient


def test_get_alerts_returns_empty_collection(
    client: FlaskClient,
) -> None:
    response = client.get("/api/v1/alerts")

    assert response.status_code == HTTPStatus.OK
    assert response.content_type == "application/json"

    assert response.get_json() == {
        "alerts": [],
        "count": 0,
    }
