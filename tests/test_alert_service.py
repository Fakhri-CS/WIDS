"""Tests for the alert service."""

from app.services.alert_service import AlertService


def test_get_all_returns_empty_list_initially() -> None:
    service = AlertService()

    alerts = service.get_all()

    assert alerts == []
