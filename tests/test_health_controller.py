from app.services.health_service import HealthService


def test_health_service_returns_ok_status():
    service = HealthService()

    result = service.get_status()

    assert result == {
        "status": "ok",
        "service": "wids-backend",
    }