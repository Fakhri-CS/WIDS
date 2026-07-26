"""Tests for the device service."""

from app.services.device_service import DeviceService


def test_get_all_returns_empty_list_initially() -> None:
    service = DeviceService()

    devices = service.get_all()

    assert devices == []
