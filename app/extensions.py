"""Flask extension instances for the WIDS backend."""

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all WIDS database models."""


db = SQLAlchemy(model_class=Base)
migrate = Migrate()
