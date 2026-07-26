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


def test_stop_changes_capture_status_to_stopped() -> None:
    service = CaptureService()

    service.start("wlan0mon")
    result = service.stop()

    assert result == {
        "status": "stopped",
        "interface": "wlan0mon",
    }


def test_stop_returns_none_when_not_running() -> None:
    service = CaptureService()

    result = service.stop()

    assert result is None


def test_capture_can_start_again_after_stopping() -> None:
    service = CaptureService()

    service.start("wlan0mon")
    service.stop()

    result = service.start("wlan1mon")

    assert result == {
        "status": "running",
        "interface": "wlan1mon",
    }
