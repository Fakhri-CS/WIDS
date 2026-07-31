"""Central orchestration for wireless detection rules."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Protocol
from uuid import UUID

from wids.contracts.detection_event import DetectionEvent

logger = logging.getLogger(__name__)


class RuleEvaluationProtocol(Protocol):
    """Represent the minimum result required by the detection engine."""

    @property
    def event(self) -> DetectionEvent | None:
        """Return the generated detection event, when available."""
        ...


class DetectionRuleProtocol[FrameT](Protocol):
    """Represent the minimum interface required from a detection rule."""

    @property
    def rule_code(self) -> str:
        """Return the stable rule identifier."""
        ...

    def evaluate(
        self,
        frame: FrameT,
    ) -> RuleEvaluationProtocol:
        """Evaluate one normalized wireless frame."""
        ...

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Remove state associated with one capture session."""
        ...


class DetectionEngine[FrameT]:
    """Run registered detection rules against normalized wireless frames."""

    def __init__(
        self,
        rules: Iterable[DetectionRuleProtocol[FrameT]],
    ) -> None:
        self._rules = tuple(rules)

    @property
    def rule_count(self) -> int:
        """Return the number of registered rules."""

        return len(self._rules)

    def evaluate(
        self,
        frame: FrameT,
    ) -> tuple[DetectionEvent, ...]:
        """Evaluate one frame and return generated detection events."""

        events: list[DetectionEvent] = []

        for rule in self._rules:
            try:
                result = rule.evaluate(frame)
            except Exception:
                logger.exception(
                    "Detection rule %s failed while evaluating a frame",
                    rule.rule_code,
                )
                continue

            if result.event is not None:
                events.append(result.event)

        return tuple(events)

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Reset one capture session across all registered rules."""

        for rule in self._rules:
            try:
                rule.reset_session(capture_session_id)
            except Exception:
                logger.exception(
                    "Detection rule %s failed while resetting session %s",
                    rule.rule_code,
                    capture_session_id,
                )
