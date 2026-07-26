"""Tests for the device controller."""

from http import HTTPStatus

from flask.testing import FlaskClient


def test_get_devices_returns_empty_collection(
    client: FlaskClient,
) -> None:
    response = client.get("/api/v1/devices")

    assert response.status_code == HTTPStatus.OK
    assert response.content_type == "application/json"

    assert response.get_json() == {
        "devices": [],
        "count": 0,
    }
