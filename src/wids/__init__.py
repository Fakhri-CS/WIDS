from flask import Flask

from wids.config import Config


def create_app(
    config_class: type[Config] = Config,
) -> Flask:
    """Create and configure the WIDS Flask application."""

    app = Flask(__name__)
    app.config.from_object(config_class)

    register_blueprints(app)

    return app


def register_blueprints(app: Flask) -> None:
    """Register all API blueprints."""

    from wids.api.health_routes import health_blueprint

    app.register_blueprint(
        health_blueprint,
        url_prefix="/api/v1",
    )
