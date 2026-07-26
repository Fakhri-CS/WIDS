"""WIDS backend application package."""

from flask import Flask

from app.config import get_config
from app.controllers.health_controller import health_controller


def create_app() -> Flask:
    """Create and configure the Flask application."""
    application = Flask(__name__)

    application.config.from_mapping(get_config())

    application.register_blueprint(health_controller)

    return application
