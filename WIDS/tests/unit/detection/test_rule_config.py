import pytest

from wids.common.enums import AlertSeverity
from wids.detection.config import RuleConfig


def test_rate_based_rule_config_is_valid() -> None:
    config = RuleConfig(
        code="WIDS-R001",
        event_type="deauthentication_flood",
        enabled=True,
        severity=AlertSeverity.HIGH,
        threshold=20,
        window_seconds=10,
        correlation_window_seconds=30,
        cooldown_seconds=30,
    )

    assert config.is_rate_based is True
    assert config.threshold == 20
    assert config.window_seconds == 10


def test_baseline_rule_config_is_valid() -> None:
    config = RuleConfig(
        code="WIDS-R007",
        event_type="unauthorized_bssid",
        enabled=True,
        severity=AlertSeverity.HIGH,
        correlation_window_seconds=300,
        cooldown_seconds=300,
    )

    assert config.is_rate_based is False
    assert config.threshold is None
    assert config.window_seconds is None


def test_rule_config_rejects_partial_rate_configuration() -> None:
    with pytest.raises(
        ValueError,
        match="must be provided together",
    ):
        RuleConfig(
            code="WIDS-R001",
            event_type="deauthentication_flood",
            enabled=True,
            severity=AlertSeverity.HIGH,
            threshold=20,
            window_seconds=None,
            correlation_window_seconds=30,
            cooldown_seconds=30,
        )


def test_rule_config_rejects_invalid_rule_code() -> None:
    with pytest.raises(
        ValueError,
        match="WIDS-R000",
    ):
        RuleConfig(
            code="DEAUTH-1",
            event_type="deauthentication_flood",
            enabled=True,
            severity=AlertSeverity.HIGH,
            threshold=20,
            window_seconds=10,
            correlation_window_seconds=30,
            cooldown_seconds=30,
        )
