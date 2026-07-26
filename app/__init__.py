"""WIDS backend application package."""

from flask import Flask

from app.config import get_config
from app.controllers.alert_controller import alert_controller
from app.controllers.capture_controller import capture_controller
from app.controllers.device_controller import device_controller
from app.controllers.health_controller import health_controller


def create_app() -> Flask:
    """Create and configure the Flask application."""
    application = Flask(__name__)

    application.config.from_mapping(get_config())

    application.register_blueprint(health_controller)
    application.register_blueprint(capture_controller)
    application.register_blueprint(alert_controller)
    application.register_blueprint(device_controller)

    return application
