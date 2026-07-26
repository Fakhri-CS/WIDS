"""Tests for the access-point controller."""

from http import HTTPStatus

from flask.testing import FlaskClient


def test_get_access_points_returns_empty_collection(
    client: FlaskClient,
) -> None:
    response = client.get("/api/v1/access-points")

    assert response.status_code == HTTPStatus.OK
    assert response.content_type == "application/json"

    assert response.get_json() == {
        "access_points": [],
        "count": 0,
    }
