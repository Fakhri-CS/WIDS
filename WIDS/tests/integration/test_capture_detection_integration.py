"""Integration tests between packet parsing and detection rules."""

from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tests.unit.capture.fakes import (
    DEFAULT_TIME,
    make_envelope,
    make_packet,
)
from wids.capture.frame_models import NormalizedWirelessFrame
from wids.capture.packet_parser import PacketParser
from wids.detection.bootstrap import build_detection_engine_from_yaml
from wids.detection.engine import DetectionEngine
from wids.detection.frame_protocols import (
    NormalizedWirelessFrameProtocol,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_DETECTION_CONFIG_PATH = (
    _PROJECT_ROOT
    / "config"
    / "detection_rules.dev.yaml"
)


def _build_engine() -> DetectionEngine[
    NormalizedWirelessFrameProtocol
]:
    """Build the standard five-rule development engine."""
    return build_detection_engine_from_yaml(
        _DETECTION_CONFIG_PATH
    )


def _parse_management_frame(
    *,
    parser: PacketParser,
    subtype: int,
    capture_session_id: UUID,
    packet_number: int,
    sequence_number: int,
) -> NormalizedWirelessFrame:
    """Create and parse one realistic management frame."""

    ssid_raw: bytes | None = b"WIDS-Lab"
    advertised_channel: int | None = 6
    include_security = True

    if subtype == 4:
        # Probe request with a wildcard SSID.
        ssid_raw = b""
        advertised_channel = None
        include_security = False
    elif subtype in {10, 11, 12}:
        # Disassociation, authentication, and
        # deauthentication frames do not require an SSID.
        ssid_raw = None
        advertised_channel = None
        include_security = False

    packet = make_packet(
        subtype=subtype,
        observed_at=DEFAULT_TIME
        + timedelta(seconds=packet_number - 1),
        ssid_raw=ssid_raw,
        advertised_channel=advertised_channel,
        include_security=include_security,
        sequence_number=sequence_number,
        fragment_number=0,
    )

    parse_result = parser.parse(
        make_envelope(
            packet,
            capture_session_id=capture_session_id,
            packet_number=packet_number,
            pcap_reference=(
                "pcap_samples/integration_management_frames.pcap"
            ),
        )
    )

    assert parse_result.frame is not None

    return parse_result.frame


@pytest.mark.parametrize(
    (
        "subtype",
        "expected_rule_code",
        "expected_event_type",
    ),
    [
        (
            12,
            "WIDS-R001",
            "deauthentication_flood",
        ),
        (
            10,
            "WIDS-R002",
            "disassociation_flood",
        ),
        (
            11,
            "WIDS-R003",
            "authentication_flood",
        ),
        (
            4,
            "WIDS-R004",
            "probe_request_flood",
        ),
        (
            8,
            "WIDS-R005",
            "beacon_flood",
        ),
    ],
)
def test_real_parser_frames_trigger_each_detection_rule(
    subtype: int,
    expected_rule_code: str,
    expected_event_type: str,
) -> None:
    """Verify all five rules accept real parser output."""

    parser = PacketParser()
    engine = _build_engine()
    capture_session_id = uuid4()

    emitted_events = []

    for index in range(3):
        frame = _parse_management_frame(
            parser=parser,
            subtype=subtype,
            capture_session_id=capture_session_id,
            packet_number=index + 1,
            sequence_number=900 + index,
        )

        emitted_events.extend(
            engine.evaluate(frame)
        )

    assert len(emitted_events) == 1

    event = emitted_events[0]

    assert event.rule_code == expected_rule_code
    assert event.event_type == expected_event_type
    assert event.capture_session_id == capture_session_id

    assert event.metrics["observed_count"] == 3
    assert event.metrics["threshold"] == 3
    assert event.metrics["window_seconds"] == 10

    assert len(event.correlation_key) == 64
    assert len(event.evidence) == 3

    assert all(
        evidence.capture_session_id
        == capture_session_id
        for evidence in event.evidence
    )


def test_session_reset_discards_partial_detection_window() -> None:
    """Ensure frames from a reset session do not remain counted."""

    parser = PacketParser()
    engine = _build_engine()
    capture_session_id = uuid4()

    for index in range(2):
        frame = _parse_management_frame(
            parser=parser,
            subtype=12,
            capture_session_id=capture_session_id,
            packet_number=index + 1,
            sequence_number=1000 + index,
        )

        assert engine.evaluate(frame) == ()

    engine.reset_session(capture_session_id)

    frame_after_reset = _parse_management_frame(
        parser=parser,
        subtype=12,
        capture_session_id=capture_session_id,
        packet_number=3,
        sequence_number=1002,
    )

    assert engine.evaluate(frame_after_reset) == ()
