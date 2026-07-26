"""Tests for the access-point service."""

from app.services.access_point_service import AccessPointService


def test_get_all_returns_empty_list_initially() -> None:
    service = AccessPointService()

    access_points = service.get_all()

    assert access_points == []
