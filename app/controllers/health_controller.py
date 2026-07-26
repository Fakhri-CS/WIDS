"""Health-related HTTP endpoints."""
from http import HTTPStatus
from flask import Blueprint, jsonify
from app.services.health_service import HealthService


health_controller = Blueprint(
    "health_controller",
    __name__,
)

health_service = HealthService()


@health_controller.get("/health")
def get_health():
    """Return the current backend status."""
    result = health_service.get_status()

    return jsonify(result), HTTPStatus.OK