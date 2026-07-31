from datetime import UTC, datetime
from uuid import uuid4

import pytest

from wids.common.enums import AlertSeverity
from wids.contracts.detection_event import (
    DETECTION_EVENT_CONTRACT_VERSION,
    DetectionEvent,
    EvidenceReference,
)


def test_detection_event_serializes_to_json_compatible_data() -> None:
    capture_session_id = uuid4()
    observed_at = datetime(
        2026,
        7,
        27,
        12,
        30,
        tzinfo=UTC,
    )

    evidence = EvidenceReference(
        frame_id=uuid4(),
        capture_session_id=capture_session_id,
        packet_number=42,
        observed_at=observed_at,
        pcap_reference="pcap_samples/deauth_flood.pcap",
        frame_sha256=None,
    )

    event = DetectionEvent(
        event_id=uuid4(),
        frame_contract_version="1.0",
        rule_code="WIDS-R001",
        event_type="deauthentication_flood",
        capture_session_id=capture_session_id,
        detected_at=observed_at,
        severity=AlertSeverity.HIGH,
        correlation_key="a" * 64,
        correlation_window_seconds=30,
        transmitter_mac="AA:BB:CC:DD:EE:FF",
        receiver_mac="11:22:33:44:55:66",
        source_mac="AA:BB:CC:DD:EE:FF",
        destination_mac="11:22:33:44:55:66",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid=None,
        ssid_hex=None,
        channel=6,
        title="Deauthentication Flood Detected",
        description="The configured frame threshold was exceeded.",
        metrics={
            "observed_count": 25,
            "threshold": 20,
            "window_seconds": 10,
        },
        evidence=(evidence,),
    )

    serialized = event.to_dict()

    assert serialized["event_contract_version"] == DETECTION_EVENT_CONTRACT_VERSION
    assert serialized["rule_code"] == "WIDS-R001"
    assert serialized["severity"] == "high"
    assert serialized["detected_at"].endswith("Z")
    assert serialized["evidence"][0]["packet_number"] == 42


def test_detection_event_rejects_naive_datetime() -> None:
    with pytest.raises(
        ValueError,
        match="detected_at must be timezone-aware",
    ):
        DetectionEvent(
            event_id=uuid4(),
            frame_contract_version="1.0",
            rule_code="WIDS-R001",
            event_type="deauthentication_flood",
            capture_session_id=uuid4(),
            detected_at=datetime(2026, 7, 27, 12, 30),
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


def test_detection_event_rejects_invalid_correlation_key() -> None:
    with pytest.raises(
        ValueError,
        match="correlation_key must be",
    ):
        DetectionEvent(
            event_id=uuid4(),
            frame_contract_version="1.0",
            rule_code="WIDS-R001",
            event_type="deauthentication_flood",
            capture_session_id=uuid4(),
            detected_at=datetime.now(UTC),
            severity=AlertSeverity.HIGH,
            correlation_key="not-a-valid-hash",
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


def test_event_rejects_evidence_from_another_session() -> None:
    event_session_id = uuid4()

    evidence = EvidenceReference(
        frame_id=uuid4(),
        capture_session_id=uuid4(),
        packet_number=10,
        observed_at=datetime.now(UTC),
        pcap_reference="pcap_samples/test.pcap",
    )

    with pytest.raises(
        ValueError,
        match="All evidence must belong",
    ):
        DetectionEvent(
            event_id=uuid4(),
            frame_contract_version="1.0",
            rule_code="WIDS-R001",
            event_type="deauthentication_flood",
            capture_session_id=event_session_id,
            detected_at=datetime.now(UTC),
            severity=AlertSeverity.HIGH,
            correlation_key="b" * 64,
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
            evidence=(evidence,),
        )
