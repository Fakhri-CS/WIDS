from flask import Flask

from wids.config import Config
from wids.extensions import db, migrate


def create_app(
    config_class: type[Config] = Config,
) -> Flask:
    """Create and configure the WIDS Flask application."""

    app = Flask(__name__)
    app.config.from_object(config_class)

    register_extensions(app)
    register_models()
    register_blueprints(app)

    return app


def register_extensions(app: Flask) -> None:
    """Initialize Flask extensions."""

    db.init_app(app)
    migrate.init_app(app, db)


def register_models() -> None:
    """Import SQLAlchemy models so they are registered."""

    from wids.models import DetectionRule

    _ = DetectionRule


def register_blueprints(app: Flask) -> None:
    """Register all API blueprints."""

    from wids.api.health_routes import health_blueprint

    app.register_blueprint(
        health_blueprint,
        url_prefix="/api/v1",
    )
