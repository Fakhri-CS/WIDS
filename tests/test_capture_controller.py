"""Tests for the capture controller."""

from http import HTTPStatus

from flask.testing import FlaskClient


def test_start_capture_returns_accepted(
    client: FlaskClient,
) -> None:
    response = client.post(
        "/api/v1/capture/start",
        json={
            "interface": "wlan0mon",
        },
    )

    assert response.status_code == HTTPStatus.ACCEPTED

    assert response.get_json() == {
        "capture": {
            "interface": "wlan0mon",
            "status": "running",
        },
        "message": "Capture start accepted.",
    }


def test_start_capture_rejects_empty_interface(
    client: FlaskClient,
) -> None:
    response = client.post(
        "/api/v1/capture/start",
        json={
            "interface": "",
        },
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST

    assert response.get_json() == {
        "error": "A valid capture interface is required.",
    }
