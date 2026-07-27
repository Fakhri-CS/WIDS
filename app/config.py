"""Configuration loading for the WIDS backend."""

import os


def get_config() -> dict[str, object]:
    """Read application settings from environment variables."""
    return {
        "SECRET_KEY": os.getenv("WIDS_SECRET_KEY"),
        "CAPTURE_INTERFACE": os.getenv(
            "WIDS_CAPTURE_INTERFACE",
            "not-configured",
        ),
        "LOG_LEVEL": os.getenv(
            "WIDS_LOG_LEVEL",
            "INFO",
        ),
        "SQLALCHEMY_DATABASE_URI": os.getenv("DATABASE_URL"),
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    }
