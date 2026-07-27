"""Tests for the capture service."""

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select

from app.models import CaptureSession
from app.services.capture_service import CaptureService


def get_sessions(database: SQLAlchemy) -> list[CaptureSession]:
    """Return all persisted capture sessions in creation order."""
    statement = select(CaptureSession).order_by(CaptureSession.id)
    return list(database.session.scalars(statement))


def test_start_changes_capture_status_to_running(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    result = service.start("wlan0mon")

    assert result == {
        "status": "running",
        "interface": "wlan0mon",
    }

    sessions = get_sessions(database)

    assert len(sessions) == 1
    assert sessions[0].interface == "wlan0mon"
    assert sessions[0].status == "running"
    assert sessions[0].packet_count == 0


def test_start_returns_none_when_already_running(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    service.start("wlan0mon")
    second_result = service.start("wlan1mon")

    assert second_result is None
    assert len(get_sessions(database)) == 1


def test_stop_changes_capture_status_to_stopped(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    service.start("wlan0mon")
    result = service.stop()

    assert result == {
        "status": "stopped",
        "interface": "wlan0mon",
    }

    capture_session = get_sessions(database)[0]

    assert capture_session.status == "stopped"
    assert capture_session.stopped_at is not None


def test_stop_returns_none_when_not_running(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    result = service.stop()

    assert result is None
    assert get_sessions(database) == []


def test_capture_can_start_again_after_stopping(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    service.start("wlan0mon")
    service.stop()

    result = service.start("wlan1mon")

    assert result == {
        "status": "running",
        "interface": "wlan1mon",
    }

    sessions = get_sessions(database)

    assert [session.status for session in sessions] == [
        "stopped",
        "running",
    ]


def test_get_status_returns_stopped_initially(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    result = service.get_status()

    assert result == {
        "status": "stopped",
        "interface": None,
    }
    assert get_sessions(database) == []


def test_get_status_returns_running_after_start(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    service.start("wlan0mon")
    result = service.get_status()

    assert result == {
        "status": "running",
        "interface": "wlan0mon",
    }
    assert len(get_sessions(database)) == 1


def test_get_status_returns_stopped_after_stop(
    database: SQLAlchemy,
) -> None:
    service = CaptureService()

    service.start("wlan0mon")
    service.stop()

    result = service.get_status()

    assert result == {
        "status": "stopped",
        "interface": None,
    }
    assert get_sessions(database)[0].status == "stopped"


def test_capture_state_is_shared_between_service_instances(
    database: SQLAlchemy,
) -> None:
    first_service = CaptureService()
    second_service = CaptureService()

    first_service.start("wlan0mon")

    assert second_service.get_status() == {
        "status": "running",
        "interface": "wlan0mon",
    }
    assert len(get_sessions(database)) == 1
