"""Tests for application configuration."""

from app import create_app


def test_create_app_loads_environment_configuration(
    monkeypatch,
) -> None:
    """The application should read WIDS settings from the environment."""
    monkeypatch.setenv(
        "WIDS_CAPTURE_INTERFACE",
        "wlan-test",
    )
    monkeypatch.setenv(
        "WIDS_LOG_LEVEL",
        "DEBUG",
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        "sqlite+pysqlite:///:memory:",
    )

    application = create_app()

    assert application.config["CAPTURE_INTERFACE"] == "wlan-test"
    assert application.config["LOG_LEVEL"] == "DEBUG"
    assert (
        application.config["SQLALCHEMY_DATABASE_URI"]
        == "sqlite+pysqlite:///:memory:"
    )
    assert application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] is False
