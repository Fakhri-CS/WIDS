"""Tests for the standard five-rule registry."""

from typing import cast

import pytest

from wids.detection.config import RuleConfig
from wids.detection.default_registry import (
    DEFAULT_RULE_CODES,
    build_default_rule_registry,
)


def make_fake_configs() -> dict[str, RuleConfig]:
    """Create placeholder configs for registry-composition tests."""

    fake_config = cast(RuleConfig, object())

    return {
        rule_code: fake_config
        for rule_code in DEFAULT_RULE_CODES
    }


def test_default_registry_contains_five_rules() -> None:
    registry = build_default_rule_registry(
        make_fake_configs()
    )

    assert registry.rule_count == 5


def test_default_registry_preserves_official_rule_order() -> None:
    registry = build_default_rule_registry(
        make_fake_configs()
    )

    assert registry.rule_codes == (
        "WIDS-R001",
        "WIDS-R002",
        "WIDS-R003",
        "WIDS-R004",
        "WIDS-R005",
    )


def test_default_registry_rejects_missing_configuration() -> None:
    configs = make_fake_configs()
    del configs["WIDS-R005"]

    with pytest.raises(
        ValueError,
        match="missing configurations: WIDS-R005",
    ):
        build_default_rule_registry(configs)


def test_default_registry_rejects_unexpected_configuration() -> None:
    configs = make_fake_configs()
    configs["WIDS-R006"] = cast(RuleConfig, object())

    with pytest.raises(
        ValueError,
        match="unexpected configurations: WIDS-R006",
    ):
        build_default_rule_registry(configs)
