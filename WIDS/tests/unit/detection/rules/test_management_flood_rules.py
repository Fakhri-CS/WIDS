from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from tests.fixtures.wireless_frame_stub import (
    create_wireless_frame,
)
from wids.common.enums import (
    AlertSeverity,
    DetectionDisposition,
)
from wids.detection.config import RuleConfig
from wids.detection.rules import (
    AuthenticationFloodRule,
    BeaconFloodRule,
    DisassociationFloodRule,
    ProbeRequestFloodRule,
)


def create_config(
    *,
    code: str,
    event_type: str,
    threshold: int = 3,
) -> RuleConfig:
    return RuleConfig(
        code=code,
        event_type=event_type,
        enabled=True,
        severity=AlertSeverity.HIGH,
        threshold=threshold,
        window_seconds=10,
        correlation_window_seconds=30,
        cooldown_seconds=30,
    )


def evaluate_until_threshold(
    *,
    rule,
    capture_session_id: UUID,
    frame_subtype: str,
    authentication_sequence: int | None = None,
    ssid_state: str = "present",
) -> object:
    started_at = datetime.now(UTC)
    result = None

    for sequence_number in range(1, 4):
        result = rule.evaluate(
            create_wireless_frame(
                capture_session_id=(capture_session_id),
                observed_at=(started_at + timedelta(seconds=sequence_number)),
                sequence_number=sequence_number,
                frame_subtype=frame_subtype,
                authentication_sequence=(authentication_sequence),
                ssid_state=ssid_state,
            )
        )

    return result


@pytest.mark.parametrize(
    ("rule", "subtype", "expected_code"),
    [
        (
            DisassociationFloodRule(
                create_config(
                    code="WIDS-R002",
                    event_type="disassociation_flood",
                )
            ),
            "disassociation",
            "WIDS-R002",
        ),
        (
            AuthenticationFloodRule(
                create_config(
                    code="WIDS-R003",
                    event_type="authentication_flood",
                )
            ),
            "authentication",
            "WIDS-R003",
        ),
        (
            ProbeRequestFloodRule(
                create_config(
                    code="WIDS-R004",
                    event_type="probe_request_flood",
                )
            ),
            "probe_request",
            "WIDS-R004",
        ),
        (
            BeaconFloodRule(
                create_config(
                    code="WIDS-R005",
                    event_type="beacon_flood",
                )
            ),
            "beacon",
            "WIDS-R005",
        ),
    ],
)
def test_flood_rules_detect_at_threshold(
    rule,
    subtype: str,
    expected_code: str,
) -> None:
    authentication_sequence = 1 if subtype == "authentication" else None

    result = evaluate_until_threshold(
        rule=rule,
        capture_session_id=uuid4(),
        frame_subtype=subtype,
        authentication_sequence=(authentication_sequence),
    )

    assert result.disposition is DetectionDisposition.DETECTED
    assert result.event is not None
    assert result.event.rule_code == expected_code
    assert result.event.metrics["observed_count"] == 3


def test_authentication_response_is_not_counted() -> None:
    rule = AuthenticationFloodRule(
        create_config(
            code="WIDS-R003",
            event_type="authentication_flood",
        )
    )

    result = rule.evaluate(
        create_wireless_frame(
            capture_session_id=uuid4(),
            observed_at=datetime.now(UTC),
            sequence_number=1,
            frame_subtype="authentication",
            authentication_sequence=2,
        )
    )

    assert result.disposition is DetectionDisposition.NOT_DETECTED


def test_probe_request_does_not_require_bssid() -> None:
    rule = ProbeRequestFloodRule(
        create_config(
            code="WIDS-R004",
            event_type="probe_request_flood",
        )
    )
    capture_session_id = uuid4()
    started_at = datetime.now(UTC)
    result = None

    for sequence_number in range(1, 4):
        result = rule.evaluate(
            create_wireless_frame(
                capture_session_id=capture_session_id,
                observed_at=(started_at + timedelta(seconds=sequence_number)),
                sequence_number=sequence_number,
                frame_subtype="probe_request",
                bssid=None,
                ssid=None,
                ssid_hex=None,
                ssid_state="wildcard",
            )
        )

    assert result is not None


def test_probe_request_metrics_count_wildcards() -> None:
    rule = ProbeRequestFloodRule(
        create_config(
            code="WIDS-R004",
            event_type="probe_request_flood",
        )
    )

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)
    result = None

    for sequence_number in range(1, 4):
        result = rule.evaluate(
            create_wireless_frame(
                capture_session_id=(capture_session_id),
                observed_at=(started_at + timedelta(seconds=sequence_number)),
                sequence_number=sequence_number,
                frame_subtype="probe_request",
                ssid=None,
                ssid_hex=None,
                ssid_state="wildcard",
                bssid=None,
            )
        )

    assert result is not None
    assert result.event is not None

    assert result.event.metrics["wildcard_probe_count"] == 3


def test_disassociation_missing_bssid_is_skipped() -> None:
    rule = DisassociationFloodRule(
        create_config(
            code="WIDS-R002",
            event_type="disassociation_flood",
        )
    )

    result = rule.evaluate(
        create_wireless_frame(
            capture_session_id=uuid4(),
            observed_at=datetime.now(UTC),
            sequence_number=1,
            frame_subtype="disassociation",
            bssid=None,
        )
    )

    assert result.disposition is DetectionDisposition.SKIPPED


def test_beacon_metrics_count_hidden_ssids() -> None:
    rule = BeaconFloodRule(
        create_config(
            code="WIDS-R005",
            event_type="beacon_flood",
        )
    )

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)
    result = None

    for sequence_number in range(1, 4):
        result = rule.evaluate(
            create_wireless_frame(
                capture_session_id=(capture_session_id),
                observed_at=(started_at + timedelta(seconds=sequence_number)),
                sequence_number=sequence_number,
                frame_subtype="beacon",
                ssid="",
                ssid_hex="",
                ssid_state="hidden",
            )
        )

    assert result is not None
    assert result.event is not None

    assert result.event.metrics["hidden_ssid_count"] == 3
