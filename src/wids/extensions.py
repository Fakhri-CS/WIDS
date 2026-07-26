from typing import TYPE_CHECKING

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


db = SQLAlchemy(model_class=Base)
migrate = Migrate()


if TYPE_CHECKING:
    BaseModel = Base
else:
    BaseModel = db.Model
