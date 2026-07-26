import os


class Config:
    """Base configuration shared by the WIDS API."""

    APP_ENV = os.getenv("APP_ENV", "development")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # Development fallback only.
    # A real secret will be required before authentication is added.
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "development-only-change-this-value",
    )


class TestingConfig(Config):
    """Configuration used by automated tests."""

    TESTING = True
    APP_ENV = "testing"
    SECRET_KEY = "testing-secret-key"
