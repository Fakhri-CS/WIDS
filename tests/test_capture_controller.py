"""Tests for the capture controller."""

from http import HTTPStatus

from flask.testing import FlaskClient


def ensure_capture_is_stopped(client: FlaskClient) -> None:
    """Ensure in-memory capture state is stopped before a test."""
    client.post("/api/v1/capture/stop")


def test_start_capture_returns_accepted(
    client: FlaskClient,
) -> None:
    ensure_capture_is_stopped(client)

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
    ensure_capture_is_stopped(client)

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


def test_stop_capture_returns_success(
    client: FlaskClient,
) -> None:
    ensure_capture_is_stopped(client)

    start_response = client.post(
        "/api/v1/capture/start",
        json={
            "interface": "wlan0mon",
        },
    )

    assert start_response.status_code == HTTPStatus.ACCEPTED

    stop_response = client.post(
        "/api/v1/capture/stop",
    )

    assert stop_response.status_code == HTTPStatus.OK

    assert stop_response.get_json() == {
        "capture": {
            "interface": "wlan0mon",
            "status": "stopped",
        },
        "message": "Capture stopped successfully.",
    }


def test_stop_capture_returns_conflict_when_not_running(
    client: FlaskClient,
) -> None:
    ensure_capture_is_stopped(client)

    response = client.post(
        "/api/v1/capture/stop",
    )

    assert response.status_code == HTTPStatus.CONFLICT

    assert response.get_json() == {
        "error": "No capture session is currently running.",
    }
def test_get_capture_status_returns_stopped(
    client: FlaskClient,
) -> None:
    ensure_capture_is_stopped(client)

    response = client.get(
        "/api/v1/capture/status",
    )

    assert response.status_code == HTTPStatus.OK

    assert response.get_json() == {
        "capture": {
            "status": "stopped",
            "interface": None,
        }
    }


def test_get_capture_status_returns_running(
    client: FlaskClient,
) -> None:
    ensure_capture_is_stopped(client)

    client.post(
        "/api/v1/capture/start",
        json={
            "interface": "wlan0mon",
        },
    )

    response = client.get(
        "/api/v1/capture/status",
    )

    assert response.status_code == HTTPStatus.OK

    assert response.get_json() == {
        "capture": {
            "status": "running",
            "interface": "wlan0mon",
        }
    }