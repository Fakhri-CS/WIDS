"""WIDS backend application package."""

from flask import Flask

from app.controllers.health_controller import health_controller


def create_app() -> Flask:
    """Create and configure the WIDS Flask application."""
    application = Flask(__name__)

    application.register_blueprint(health_controller)

    return application