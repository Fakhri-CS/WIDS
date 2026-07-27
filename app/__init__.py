"""WIDS backend application package."""

from flask import Flask

from app.config import get_config
from app.controllers.access_point_controller import access_point_controller
from app.controllers.alert_controller import alert_controller
from app.controllers.capture_controller import capture_controller
from app.controllers.device_controller import device_controller
from app.controllers.health_controller import health_controller
from app.controllers.rule_controller import rule_controller
from app.extensions import db, migrate
from app.models import CaptureSession  # noqa: F401


def create_app(
    test_config: dict[str, object] | None = None,
) -> Flask:
    """Create and configure the Flask application."""
    application = Flask(__name__)

    application.config.from_mapping(get_config())

    if test_config is not None:
        application.config.update(test_config)

    if not application.config.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError(
            "DATABASE_URL is not configured."
        )

    db.init_app(application)
    migrate.init_app(application, db)

    application.register_blueprint(health_controller)
    application.register_blueprint(capture_controller)
    application.register_blueprint(alert_controller)
    application.register_blueprint(device_controller)
    application.register_blueprint(access_point_controller)
    application.register_blueprint(rule_controller)

    return application
