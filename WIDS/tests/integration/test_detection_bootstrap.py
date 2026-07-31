"""Integration tests for detection-engine configuration bootstrap."""

from pathlib import Path

from wids.detection.bootstrap import (
    build_detection_engine_from_yaml,
)
from wids.detection.config_loader import load_rule_configs
from wids.detection.default_registry import DEFAULT_RULE_CODES

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_DEVELOPMENT_CONFIG_PATH = (
    _PROJECT_ROOT
    / "config"
    / "detection_rules.dev.yaml"
)


def test_builds_five_rule_engine_from_development_yaml() -> None:
    engine = build_detection_engine_from_yaml(
        _DEVELOPMENT_CONFIG_PATH
    )

    assert engine.rule_count == 5


def test_development_yaml_contains_only_supported_rules() -> None:
    configs = load_rule_configs(
        _DEVELOPMENT_CONFIG_PATH
    )

    assert set(configs) == set(DEFAULT_RULE_CODES)


def test_development_configs_are_rate_based() -> None:
    configs = load_rule_configs(
        _DEVELOPMENT_CONFIG_PATH
    )

    assert all(
        config.is_rate_based
        for config in configs.values()
    )


def test_development_event_types_are_correct() -> None:
    configs = load_rule_configs(
        _DEVELOPMENT_CONFIG_PATH
    )

    event_types = {
        code: config.event_type
        for code, config in configs.items()
    }

    assert event_types == {
        "WIDS-R001": "deauthentication_flood",
        "WIDS-R002": "disassociation_flood",
        "WIDS-R003": "authentication_flood",
        "WIDS-R004": "probe_request_flood",
        "WIDS-R005": "beacon_flood",
    }
