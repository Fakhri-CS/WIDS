"""Runtime integration between capture worker and detection engine."""

from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

from tests.unit.capture.fakes import (
    DEFAULT_TIME,
    make_packet,
)
from wids.capture.frame_models import (
    CaptureSource,
    CaptureState,
)
from wids.capture.packet_source import (
    InMemoryPacketSource,
)
from wids.contracts.detection_event import DetectionEvent
from wids.workers.capture_worker import (
    CaptureWorker,
    WorkerConfig,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_DETECTION_CONFIG_PATH = _PROJECT_ROOT / "config" / "detection_rules.dev.yaml"


def _build_worker(
    events: list[DetectionEvent],
) -> CaptureWorker:
    return CaptureWorker(
        WorkerConfig(
            source_mode=CaptureSource.PCAP,
            feature_window_seconds=(10.0,),
            runtime_pcap_directory=Path("runtime/pcap"),
            heartbeat_interval_seconds=60.0,
            pcap_path=Path("unused-injected-source.pcap"),
            detection_config_path=(_DETECTION_CONFIG_PATH),
        ),
        detection_event_sink=events.append,
    )


def _deauthentication_packets(
    *,
    start_sequence: int,
    count: int,
    start_second: int = 0,
) -> list[object]:
    return [
        make_packet(
            subtype=12,
            observed_at=(DEFAULT_TIME + timedelta(seconds=start_second + index)),
            ssid_raw=None,
            advertised_channel=None,
            include_security=False,
            sequence_number=(start_sequence + index),
            fragment_number=0,
        )
        for index in range(count)
    ]


def test_worker_emits_detection_event() -> None:
    """Three parser frames must trigger R001 at runtime."""

    events: list[DetectionEvent] = []

    worker = _build_worker(events)

    source = InMemoryPacketSource(
        _deauthentication_packets(
            start_sequence=900,
            count=3,
        )
    )

    status = worker.run_source(source)

    assert status.state is CaptureState.STOPPED
    assert status.packets_seen == 3
    assert status.packets_parsed == 3
    assert status.packets_skipped == 0

    assert len(events) == 1

    event = events[0]

    assert event.rule_code == "WIDS-R001"

    assert event.event_type == "deauthentication_flood"

    assert event.capture_session_id == source.capture_session_id

    assert event.metrics["observed_count"] == 3

    assert len(event.evidence) == 3


def test_worker_resets_detection_session() -> None:
    """A completed run must clear partial detection state."""

    events: list[DetectionEvent] = []

    worker = _build_worker(events)

    capture_session_id: UUID = uuid4()

    first_source = InMemoryPacketSource(
        _deauthentication_packets(
            start_sequence=1000,
            count=2,
        ),
        capture_session_id=capture_session_id,
    )

    first_status = worker.run_source(first_source)

    assert first_status.state is CaptureState.STOPPED

    assert events == []

    second_source = InMemoryPacketSource(
        _deauthentication_packets(
            start_sequence=1002,
            count=1,
            start_second=2,
        ),
        capture_session_id=capture_session_id,
    )

    second_status = worker.run_source(second_source)

    assert second_status.state is CaptureState.STOPPED

    assert events == []
