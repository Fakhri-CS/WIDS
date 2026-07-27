"""Tests for the capture-session database model."""

from datetime import datetime, timezone

import pytest
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

from app.models import CaptureSession


def test_capture_session_defaults_are_persisted(
    database: SQLAlchemy,
) -> None:
    """A new session should receive safe initial values."""
    capture = CaptureSession(interface="wlan0mon")

    database.session.add(capture)
    database.session.commit()

    assert capture.id is not None
    assert capture.interface == "wlan0mon"
    assert capture.status == "running"
    assert isinstance(capture.started_at, datetime)
    assert capture.stopped_at is None
    assert capture.packet_count == 0
    assert capture.error_message is None


def test_capture_session_completion_is_persisted(
    database: SQLAlchemy,
) -> None:
    """Stopping a session should preserve its final information."""
    capture = CaptureSession(interface="wlan0mon")

    database.session.add(capture)
    database.session.commit()

    capture.status = "stopped"
    capture.stopped_at = datetime.now(timezone.utc)
    capture.packet_count = 125

    database.session.commit()

    capture_id = capture.id
    database.session.remove()

    stored = database.session.get(CaptureSession, capture_id)

    assert stored is not None
    assert stored.status == "stopped"
    assert stored.stopped_at is not None
    assert stored.packet_count == 125


def test_capture_session_rejects_unknown_status(
    database: SQLAlchemy,
) -> None:
    """The database should reject unsupported session states."""
    capture = CaptureSession(
        interface="wlan0mon",
        status="unknown",
    )

    database.session.add(capture)

    with pytest.raises(IntegrityError):
        database.session.commit()

    database.session.rollback()
