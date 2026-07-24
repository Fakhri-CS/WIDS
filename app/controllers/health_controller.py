"""Health-related HTTP endpoints."""

from http import HTTPStatus

from flask import Blueprint, Response, jsonify


health_controller = Blueprint(
    "health_controller",
    __name__,
)


@health_controller.get("/health")
def get_health() -> tuple[Response, int]:
    """Return the current status of the WIDS backend."""
    response = jsonify(
        {
            "status": "ok",
            "service": "wids-backend",
        }
    )

    return response, int(HTTPStatus.OK)
