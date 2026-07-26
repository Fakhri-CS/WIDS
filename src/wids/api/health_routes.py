from flask import Blueprint, Response, current_app, jsonify

health_blueprint = Blueprint(
    "health",
    __name__,
)


@health_blueprint.get("/health")
def get_health() -> tuple[Response, int]:
    """Return the current API health status."""

    return (
        jsonify(
            {
                "service": "wids-api",
                "status": "up",
                "environment": current_app.config["APP_ENV"],
            }
        ),
        200,
    )
