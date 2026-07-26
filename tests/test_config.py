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

    application = create_app()

    assert application.config["CAPTURE_INTERFACE"] == "wlan-test"
    assert application.config["LOG_LEVEL"] == "DEBUG"
