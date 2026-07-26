from flask import Blueprint, Response, current_app, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from wids.extensions import db

health_blueprint = Blueprint(
    "health",
    __name__,
)


@health_blueprint.get("/health")
def get_health() -> tuple[Response, int]:
    """Return the API and database health status."""

    try:
        db.session.execute(text("SELECT 1")).scalar_one()
    except SQLAlchemyError:
        db.session.rollback()

        current_app.logger.exception(
            "Database health check failed.",
        )

        return (
            jsonify(
                {
                    "service": "wids-api",
                    "status": "degraded",
                    "environment": current_app.config["APP_ENV"],
                    "database": "down",
                }
            ),
            503,
        )

    return (
        jsonify(
            {
                "service": "wids-api",
                "status": "up",
                "environment": current_app.config["APP_ENV"],
                "database": "up",
            }
        ),
        200,
    )
