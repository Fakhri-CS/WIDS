"""Unit tests for the central detection engine."""

from dataclasses import dataclass
from typing import cast
from uuid import UUID, uuid4

from wids.contracts.detection_event import DetectionEvent
from wids.detection.engine import DetectionEngine


@dataclass(frozen=True, slots=True)
class FrameStub:
    """Represent one normalized frame during engine tests."""

    packet_number: int = 1


@dataclass(frozen=True, slots=True)
class ResultStub:
    """Represent the minimum rule result required by the engine."""

    event: DetectionEvent | None


class RuleStub:
    """Return a predefined result when evaluated."""

    def __init__(
        self,
        rule_code: str,
        result: ResultStub,
    ) -> None:
        self.rule_code = rule_code
        self.result = result
        self.evaluation_count = 0
        self.reset_session_ids: list[UUID] = []

    def evaluate(
        self,
        frame: FrameStub,
    ) -> ResultStub:
        """Return the configured evaluation result."""

        self.evaluation_count += 1
        return self.result

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Record one session reset request."""

        self.reset_session_ids.append(capture_session_id)


class FailingRuleStub:
    """Raise an exception during frame evaluation."""

    rule_code = "WIDS-R999"

    def evaluate(
        self,
        frame: FrameStub,
    ) -> ResultStub:
        """Simulate a rule evaluation failure."""

        raise RuntimeError("Simulated rule failure")

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Accept a session reset without retaining state."""


class FailingResetRuleStub:
    """Raise an exception during session reset."""

    rule_code = "WIDS-R998"

    def evaluate(
        self,
        frame: FrameStub,
    ) -> ResultStub:
        """Return a non-detection result."""

        return ResultStub(event=None)

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Simulate a session reset failure."""

        raise RuntimeError("Simulated reset failure")


def test_engine_returns_empty_tuple_when_no_rule_detects() -> None:
    frame = FrameStub()

    rule = RuleStub(
        rule_code="WIDS-R001",
        result=ResultStub(event=None),
    )

    engine = DetectionEngine[FrameStub]([rule])

    events = engine.evaluate(frame)

    assert events == ()
    assert rule.evaluation_count == 1


def test_engine_returns_event_generated_by_rule() -> None:
    frame = FrameStub()
    event = cast(DetectionEvent, object())

    rule = RuleStub(
        rule_code="WIDS-R001",
        result=ResultStub(event=event),
    )

    engine = DetectionEngine[FrameStub]([rule])

    events = engine.evaluate(frame)

    assert events == (event,)
    assert rule.evaluation_count == 1


def test_engine_collects_events_from_multiple_rules() -> None:
    frame = FrameStub()

    first_event = cast(DetectionEvent, object())
    second_event = cast(DetectionEvent, object())

    first_rule = RuleStub(
        rule_code="WIDS-R001",
        result=ResultStub(event=first_event),
    )
    second_rule = RuleStub(
        rule_code="WIDS-R002",
        result=ResultStub(event=None),
    )
    third_rule = RuleStub(
        rule_code="WIDS-R003",
        result=ResultStub(event=second_event),
    )

    engine = DetectionEngine[FrameStub](
        [
            first_rule,
            second_rule,
            third_rule,
        ]
    )

    events = engine.evaluate(frame)

    assert events == (
        first_event,
        second_event,
    )

    assert first_rule.evaluation_count == 1
    assert second_rule.evaluation_count == 1
    assert third_rule.evaluation_count == 1


def test_engine_continues_when_one_rule_fails() -> None:
    frame = FrameStub()
    event = cast(DetectionEvent, object())

    failing_rule = FailingRuleStub()

    working_rule = RuleStub(
        rule_code="WIDS-R001",
        result=ResultStub(event=event),
    )

    engine = DetectionEngine[FrameStub](
        [
            failing_rule,
            working_rule,
        ]
    )

    events = engine.evaluate(frame)

    assert events == (event,)
    assert working_rule.evaluation_count == 1


def test_engine_reports_registered_rule_count() -> None:
    first_rule = RuleStub(
        rule_code="WIDS-R001",
        result=ResultStub(event=None),
    )
    second_rule = RuleStub(
        rule_code="WIDS-R002",
        result=ResultStub(event=None),
    )

    engine = DetectionEngine[FrameStub](
        [
            first_rule,
            second_rule,
        ]
    )

    assert engine.rule_count == 2


def test_engine_resets_session_across_all_rules() -> None:
    capture_session_id = uuid4()

    first_rule = RuleStub(
        rule_code="WIDS-R001",
        result=ResultStub(event=None),
    )
    second_rule = RuleStub(
        rule_code="WIDS-R002",
        result=ResultStub(event=None),
    )

    engine = DetectionEngine[FrameStub](
        [
            first_rule,
            second_rule,
        ]
    )

    engine.reset_session(capture_session_id)

    assert first_rule.reset_session_ids == [
        capture_session_id
    ]
    assert second_rule.reset_session_ids == [
        capture_session_id
    ]


def test_engine_continues_when_one_rule_reset_fails() -> None:
    capture_session_id = uuid4()

    failing_rule = FailingResetRuleStub()

    working_rule = RuleStub(
        rule_code="WIDS-R001",
        result=ResultStub(event=None),
    )

    engine = DetectionEngine[FrameStub](
        [
            failing_rule,
            working_rule,
        ]
    )

    engine.reset_session(capture_session_id)

    assert working_rule.reset_session_ids == [
        capture_session_id
    ]
