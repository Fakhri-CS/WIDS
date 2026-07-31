"""Unit tests for the detection-rule registry."""

from dataclasses import dataclass

import pytest

from wids.contracts.detection_event import DetectionEvent
from wids.detection.registry import (
    RegisteredRule,
    RuleRegistry,
)


@dataclass(frozen=True, slots=True)
class FrameStub:
    """Represent one frame during registry tests."""

    packet_number: int = 1


@dataclass(frozen=True, slots=True)
class ResultStub:
    """Represent the minimum rule evaluation result."""

    event: DetectionEvent | None = None


class RuleStub:
    """Represent one rule constructed by the registry."""

    def __init__(self, rule_code: str) -> None:
        self._rule_code = rule_code

    @property
    def rule_code(self) -> str:
        """Return the rule identifier."""
        return self._rule_code

    def evaluate(self, frame: FrameStub) -> ResultStub:
        """Return a non-detection result."""
        return ResultStub()


def test_registry_builds_engine_from_registered_rules() -> None:
    registry = RuleRegistry[FrameStub](
        [
            RegisteredRule(
                rule_code="WIDS-R001",
                factory=lambda: RuleStub("WIDS-R001"),
            ),
            RegisteredRule(
                rule_code="WIDS-R002",
                factory=lambda: RuleStub("WIDS-R002"),
            ),
        ]
    )

    engine = registry.build_engine()

    assert registry.rule_count == 2
    assert engine.rule_count == 2


def test_registry_preserves_rule_execution_order() -> None:
    registry = RuleRegistry[FrameStub](
        [
            RegisteredRule(
                rule_code="WIDS-R003",
                factory=lambda: RuleStub("WIDS-R003"),
            ),
            RegisteredRule(
                rule_code="WIDS-R001",
                factory=lambda: RuleStub("WIDS-R001"),
            ),
            RegisteredRule(
                rule_code="WIDS-R005",
                factory=lambda: RuleStub("WIDS-R005"),
            ),
        ]
    )

    assert registry.rule_codes == (
        "WIDS-R003",
        "WIDS-R001",
        "WIDS-R005",
    )


def test_registry_rejects_empty_registration_list() -> None:
    with pytest.raises(
        ValueError,
        match="At least one detection rule",
    ):
        RuleRegistry[FrameStub]([])


def test_registry_rejects_duplicate_rule_codes() -> None:
    with pytest.raises(
        ValueError,
        match="Duplicate detection rule code: WIDS-R001",
    ):
        RuleRegistry[FrameStub](
            [
                RegisteredRule(
                    rule_code="WIDS-R001",
                    factory=lambda: RuleStub("WIDS-R001"),
                ),
                RegisteredRule(
                    rule_code="WIDS-R001",
                    factory=lambda: RuleStub("WIDS-R001"),
                ),
            ]
        )


def test_registry_rejects_factory_rule_code_mismatch() -> None:
    registry = RuleRegistry[FrameStub](
        [
            RegisteredRule(
                rule_code="WIDS-R001",
                factory=lambda: RuleStub("WIDS-R002"),
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match="expected WIDS-R001, received WIDS-R002",
    ):
        registry.build_engine()


def test_registry_creates_fresh_rules_for_each_engine() -> None:
    created_rules: list[RuleStub] = []

    def create_rule() -> RuleStub:
        rule = RuleStub("WIDS-R001")
        created_rules.append(rule)
        return rule

    registry = RuleRegistry[FrameStub](
        [
            RegisteredRule(
                rule_code="WIDS-R001",
                factory=create_rule,
            )
        ]
    )

    first_engine = registry.build_engine()
    second_engine = registry.build_engine()

    assert first_engine.rule_count == 1
    assert second_engine.rule_count == 1
    assert len(created_rules) == 2
    assert created_rules[0] is not created_rules[1]
