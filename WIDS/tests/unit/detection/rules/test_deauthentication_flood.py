from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from wids.common.enums import (
    AlertSeverity,
    DetectionDisposition,
)
from wids.detection.config import RuleConfig
from wids.detection.rules.deauthentication_flood import (
    DeauthenticationFloodRule,
)


@dataclass(frozen=True, slots=True)
class AddressesStub:
    receiver_mac: str
    transmitter_mac: str
    destination_mac: str | None
    source_mac: str | None
    bssid: str | None


@dataclass(frozen=True, slots=True)
class SequenceStub:
    sequence_number: int | None
    fragment_number: int | None


@dataclass(frozen=True, slots=True)
class FlagsStub:
    retry: bool


@dataclass(frozen=True, slots=True)
class RadioStub:
    channel: int | None


@dataclass(frozen=True, slots=True)
class ManagementStub:
    reason_code: int | None


@dataclass(frozen=True, slots=True)
class EvidenceStub:
    pcap_reference: str
    frame_sha256: str | None


@dataclass(frozen=True, slots=True)
class FrameStub:
    contract_version: str
    frame_id: UUID
    capture_session_id: UUID
    packet_number: int
    observed_at: datetime
    frame_subtype: str
    addresses: AddressesStub
    sequence: SequenceStub
    flags: FlagsStub
    radio: RadioStub
    management: ManagementStub
    evidence: EvidenceStub


def create_config(
    *,
    threshold: int = 3,
    window_seconds: int = 10,
    cooldown_seconds: int = 30,
) -> RuleConfig:
    return RuleConfig(
        code="WIDS-R001",
        event_type="deauthentication_flood",
        enabled=True,
        severity=AlertSeverity.HIGH,
        threshold=threshold,
        window_seconds=window_seconds,
        correlation_window_seconds=30,
        cooldown_seconds=cooldown_seconds,
    )


def create_frame(
    *,
    capture_session_id: UUID,
    observed_at: datetime,
    sequence_number: int,
    retry: bool = False,
    frame_subtype: str = "deauthentication",
    bssid: str | None = "AA:BB:CC:DD:EE:FF",
    receiver_mac: str = "11:22:33:44:55:66",
) -> FrameStub:
    return FrameStub(
        contract_version="1.0",
        frame_id=uuid4(),
        capture_session_id=capture_session_id,
        packet_number=sequence_number + 1,
        observed_at=observed_at,
        frame_subtype=frame_subtype,
        addresses=AddressesStub(
            receiver_mac=receiver_mac,
            transmitter_mac="77:88:99:AA:BB:CC",
            destination_mac=receiver_mac,
            source_mac="77:88:99:AA:BB:CC",
            bssid=bssid,
        ),
        sequence=SequenceStub(
            sequence_number=sequence_number,
            fragment_number=0,
        ),
        flags=FlagsStub(
            retry=retry,
        ),
        radio=RadioStub(
            channel=6,
        ),
        management=ManagementStub(
            reason_code=7,
        ),
        evidence=EvidenceStub(
            pcap_reference=("pcap_samples/deauth_flood.pcap"),
            frame_sha256=None,
        ),
    )


def test_irrelevant_subtype_is_not_detected() -> None:
    rule = DeauthenticationFloodRule(create_config())

    result = rule.evaluate(
        create_frame(
            capture_session_id=uuid4(),
            observed_at=datetime.now(UTC),
            sequence_number=1,
            frame_subtype="beacon",
        )
    )

    assert result.disposition is DetectionDisposition.NOT_DETECTED


def test_missing_bssid_causes_skip() -> None:
    rule = DeauthenticationFloodRule(create_config())

    result = rule.evaluate(
        create_frame(
            capture_session_id=uuid4(),
            observed_at=datetime.now(UTC),
            sequence_number=1,
            bssid=None,
        )
    )

    assert result.disposition is DetectionDisposition.SKIPPED
    assert result.reason is not None
    assert "addresses.bssid" in result.reason


def test_frames_below_threshold_do_not_detect() -> None:
    rule = DeauthenticationFloodRule(create_config(threshold=3))

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)

    first_result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at,
            sequence_number=1,
        )
    )

    second_result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=1),
            sequence_number=2,
        )
    )

    assert first_result.disposition is DetectionDisposition.NOT_DETECTED
    assert second_result.disposition is DetectionDisposition.NOT_DETECTED


def test_threshold_generates_detection_event() -> None:
    rule = DeauthenticationFloodRule(create_config(threshold=3))

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)

    rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at,
            sequence_number=1,
        )
    )

    rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=1),
            sequence_number=2,
        )
    )

    result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=2),
            sequence_number=3,
        )
    )

    assert result.disposition is DetectionDisposition.DETECTED

    assert result.event is not None
    assert result.event.rule_code == "WIDS-R001"
    assert result.event.severity is AlertSeverity.HIGH

    assert result.event.metrics["observed_count"] == 3

    assert result.event.metrics["threshold"] == 3

    assert len(result.event.evidence) == 3


def test_expired_frames_leave_the_window() -> None:
    rule = DeauthenticationFloodRule(
        create_config(
            threshold=3,
            window_seconds=10,
        )
    )

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)

    rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at,
            sequence_number=1,
        )
    )

    rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=1),
            sequence_number=2,
        )
    )

    result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=12),
            sequence_number=3,
        )
    )

    assert result.disposition is DetectionDisposition.NOT_DETECTED


def test_duplicate_retry_does_not_increase_count() -> None:
    rule = DeauthenticationFloodRule(create_config(threshold=3))

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)

    rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at,
            sequence_number=10,
        )
    )

    retry_result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=1),
            sequence_number=10,
            retry=True,
        )
    )

    second_unique_result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=2),
            sequence_number=11,
        )
    )

    assert retry_result.disposition is DetectionDisposition.SUPPRESSED
    assert retry_result.reason == "duplicate_retry"

    assert second_unique_result.disposition is DetectionDisposition.NOT_DETECTED

    detection_result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=3),
            sequence_number=12,
        )
    )

    assert detection_result.disposition is DetectionDisposition.DETECTED


def test_cooldown_suppresses_repeated_event() -> None:
    rule = DeauthenticationFloodRule(
        create_config(
            threshold=3,
            window_seconds=60,
            cooldown_seconds=30,
        )
    )

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)

    for sequence_number in range(1, 4):
        result = rule.evaluate(
            create_frame(
                capture_session_id=capture_session_id,
                observed_at=started_at
                + timedelta(
                    seconds=sequence_number,
                ),
                sequence_number=sequence_number,
            )
        )

    assert result.disposition is DetectionDisposition.DETECTED

    suppressed_result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=4),
            sequence_number=4,
        )
    )

    assert suppressed_result.disposition is DetectionDisposition.SUPPRESSED
    assert suppressed_result.reason == "cooldown_active"


def test_reset_session_clears_window_state() -> None:
    rule = DeauthenticationFloodRule(create_config(threshold=3))

    capture_session_id = uuid4()
    started_at = datetime.now(UTC)

    rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at,
            sequence_number=1,
        )
    )

    rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=1),
            sequence_number=2,
        )
    )

    rule.reset_session(capture_session_id)

    result = rule.evaluate(
        create_frame(
            capture_session_id=capture_session_id,
            observed_at=started_at + timedelta(seconds=2),
            sequence_number=3,
        )
    )

    assert result.disposition is DetectionDisposition.NOT_DETECTED
