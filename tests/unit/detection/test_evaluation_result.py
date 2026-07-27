from datetime import UTC, datetime
from uuid import uuid4

import pytest

from wids.common.enums import (
    AlertSeverity,
    DetectionDisposition,
)
from wids.contracts.detection_event import DetectionEvent
from wids.detection.result import RuleEvaluationResult


def create_event() -> DetectionEvent:
    return DetectionEvent(
        event_id=uuid4(),
        frame_contract_version="1.0",
        rule_code="WIDS-R001",
        event_type="deauthentication_flood",
        capture_session_id=uuid4(),
        detected_at=datetime.now(UTC),
        severity=AlertSeverity.HIGH,
        correlation_key="a" * 64,
        correlation_window_seconds=30,
        transmitter_mac=None,
        receiver_mac=None,
        source_mac=None,
        destination_mac=None,
        bssid=None,
        ssid=None,
        ssid_hex=None,
        channel=None,
        title="Test detection",
        description="Test description",
    )


def test_detected_result_contains_event() -> None:
    event = create_event()

    result = RuleEvaluationResult.detected(event)

    assert result.disposition is DetectionDisposition.DETECTED
    assert result.event is event
    assert result.reason is None


def test_not_detected_result_contains_no_event() -> None:
    result = RuleEvaluationResult.not_detected()

    assert result.disposition is DetectionDisposition.NOT_DETECTED
    assert result.event is None


def test_skipped_result_contains_reason() -> None:
    result = RuleEvaluationResult.skipped("missing addresses.bssid")

    assert result.disposition is DetectionDisposition.SKIPPED
    assert result.reason == "missing addresses.bssid"


def test_skipped_result_rejects_empty_reason() -> None:
    with pytest.raises(
        ValueError,
        match="must include a reason",
    ):
        RuleEvaluationResult(
            disposition=DetectionDisposition.SKIPPED,
        )
