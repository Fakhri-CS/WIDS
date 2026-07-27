from datetime import UTC, datetime, timedelta

from wids.detection.state.cooldown_tracker import (
    CooldownTracker,
)


def test_first_detection_is_allowed() -> None:
    tracker = CooldownTracker()

    allowed = tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=datetime.now(UTC),
        cooldown_seconds=30,
    )

    assert allowed is True


def test_detection_inside_cooldown_is_suppressed() -> None:
    tracker = CooldownTracker()
    detected_at = datetime.now(UTC)

    tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=detected_at,
        cooldown_seconds=30,
    )

    allowed = tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=detected_at + timedelta(seconds=29),
        cooldown_seconds=30,
    )

    assert allowed is False


def test_detection_at_cooldown_boundary_is_allowed() -> None:
    tracker = CooldownTracker()
    detected_at = datetime.now(UTC)

    tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=detected_at,
        cooldown_seconds=30,
    )

    allowed = tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=detected_at + timedelta(seconds=30),
        cooldown_seconds=30,
    )

    assert allowed is True


def test_different_correlation_keys_are_independent() -> None:
    tracker = CooldownTracker()
    detected_at = datetime.now(UTC)

    tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=detected_at,
        cooldown_seconds=30,
    )

    allowed = tracker.should_emit_and_record(
        correlation_key="b" * 64,
        detected_at=detected_at,
        cooldown_seconds=30,
    )

    assert allowed is True


def test_older_detection_is_suppressed() -> None:
    tracker = CooldownTracker()
    detected_at = datetime.now(UTC)

    tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=detected_at,
        cooldown_seconds=30,
    )

    allowed = tracker.should_emit_and_record(
        correlation_key="a" * 64,
        detected_at=detected_at - timedelta(seconds=1),
        cooldown_seconds=30,
    )

    assert allowed is False
