"""WIDS backend application package."""

from flask import Flask

from app.controllers.health_controller import health_controller


def create_app() -> Flask:
    """Create the Flask application."""
    application = Flask(__name__)

    application.register_blueprint(health_controller)

    return application