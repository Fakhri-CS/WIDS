"""Tests for the capture service."""

from app.services.capture_service import CaptureService


def test_start_changes_capture_status_to_running() -> None:
    service = CaptureService()

    result = service.start("wlan0mon")

    assert result == {
        "status": "running",
        "interface": "wlan0mon",
    }


def test_start_returns_none_when_already_running() -> None:
    service = CaptureService()

    service.start("wlan0mon")
    second_result = service.start("wlan1mon")

    assert second_result is None
