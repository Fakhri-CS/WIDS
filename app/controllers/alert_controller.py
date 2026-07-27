"""HTTP endpoints for WIDS alerts."""

from http import HTTPStatus

from flask import Blueprint, jsonify

from app.services.alert_service import AlertService

alert_controller = Blueprint(
    "alert_controller",
    __name__,
    url_prefix="/api/v1/alerts",
)

alert_service = AlertService()


@alert_controller.get("")
def get_alerts():
    """Return all detected WIDS alerts."""
    alerts = alert_service.get_all()

    return jsonify(
        {
            "alerts": alerts,
            "count": len(alerts),
        }
    ), HTTPStatus.OK
