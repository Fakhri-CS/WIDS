"""Registry and factory utilities for detection rules."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from wids.detection.engine import (
    DetectionEngine,
    DetectionRuleProtocol,
)

type RuleFactory[FrameT] = Callable[
    [],
    DetectionRuleProtocol[FrameT],
]


@dataclass(frozen=True, slots=True)
class RegisteredRule[FrameT]:
    """Describe one detection rule registered with the system."""

    rule_code: str
    factory: RuleFactory[FrameT]


class RuleRegistry[FrameT]:
    """Validate registered rules and build detection engines."""

    def __init__(
        self,
        registrations: Iterable[RegisteredRule[FrameT]],
    ) -> None:
        self._registrations = tuple(registrations)

        if not self._registrations:
            raise ValueError(
                "At least one detection rule must be registered"
            )

        self._validate_unique_rule_codes()

    @property
    def rule_count(self) -> int:
        """Return the number of registered rules."""
        return len(self._registrations)

    @property
    def rule_codes(self) -> tuple[str, ...]:
        """Return registered rule codes in execution order."""
        return tuple(
            registration.rule_code
            for registration in self._registrations
        )

    def build_engine(self) -> DetectionEngine[FrameT]:
        """Create a detection engine using fresh rule instances."""

        rules: list[DetectionRuleProtocol[FrameT]] = []

        for registration in self._registrations:
            rule = registration.factory()

            if rule.rule_code != registration.rule_code:
                raise ValueError(
                    "Rule factory returned an unexpected rule code: "
                    f"expected {registration.rule_code}, "
                    f"received {rule.rule_code}"
                )

            rules.append(rule)

        return DetectionEngine(rules)

    def _validate_unique_rule_codes(self) -> None:
        """Reject duplicate rule-code registrations."""

        seen_rule_codes: set[str] = set()

        for registration in self._registrations:
            if registration.rule_code in seen_rule_codes:
                raise ValueError(
                    "Duplicate detection rule code: "
                    f"{registration.rule_code}"
                )

            seen_rule_codes.add(registration.rule_code)
