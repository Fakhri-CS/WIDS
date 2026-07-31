"""Unit tests for the YAML detection configuration loader."""

from pathlib import Path

import pytest

from wids.detection.config_loader import load_rule_configs


def write_config(
    tmp_path: Path,
    content: str,
) -> Path:
    """Write one temporary YAML configuration file."""

    config_path = tmp_path / "detection_rules.yaml"
    config_path.write_text(content, encoding="utf-8")
    return config_path


def test_loads_valid_rate_based_rule_config(
    tmp_path: Path,
) -> None:
    config_path = write_config(
        tmp_path,
        """
rules:
  WIDS-R001:
    event_type: deauthentication_flood
    enabled: true
    severity: high
    correlation_window_seconds: 60
    cooldown_seconds: 30
    threshold: 20
    window_seconds: 10
""",
    )

    configs = load_rule_configs(config_path)
    config = configs["WIDS-R001"]

    assert config.code == "WIDS-R001"
    assert config.event_type == "deauthentication_flood"
    assert config.enabled is True
    assert config.severity.value == "high"
    assert config.correlation_window_seconds == 60
    assert config.cooldown_seconds == 30
    assert config.threshold == 20
    assert config.window_seconds == 10
    assert config.is_rate_based is True


def test_rejects_invalid_yaml(
    tmp_path: Path,
) -> None:
    config_path = write_config(
        tmp_path,
        """
rules:
  WIDS-R001:
    event_type: [
""",
    )

    with pytest.raises(
        ValueError,
        match="Invalid YAML detection configuration",
    ):
        load_rule_configs(config_path)


def test_rejects_missing_rules_mapping(
    tmp_path: Path,
) -> None:
    config_path = write_config(
        tmp_path,
        """
application:
  name: WIDS
""",
    )

    with pytest.raises(
        ValueError,
        match="rules must be a YAML mapping",
    ):
        load_rule_configs(config_path)


def test_rejects_threshold_without_window(
    tmp_path: Path,
) -> None:
    config_path = write_config(
        tmp_path,
        """
rules:
  WIDS-R001:
    event_type: deauthentication_flood
    enabled: true
    severity: high
    correlation_window_seconds: 60
    cooldown_seconds: 30
    threshold: 20
""",
    )

    with pytest.raises(
        ValueError,
        match=(
            "threshold and window_seconds "
            "must be provided together"
        ),
    ):
        load_rule_configs(config_path)


def test_rejects_unknown_configuration_field(
    tmp_path: Path,
) -> None:
    config_path = write_config(
        tmp_path,
        """
rules:
  WIDS-R001:
    event_type: deauthentication_flood
    enabled: true
    severity: high
    correlation_window_seconds: 60
    cooldown_seconds: 30
    threshold: 20
    window_seconds: 10
    threshhold: 50
""",
    )

    with pytest.raises(
        ValueError,
        match="Unknown fields for WIDS-R001: threshhold",
    ):
        load_rule_configs(config_path)
