from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("pyshark")

from wids.capture.frame_models import (  # noqa: E402
    CaptureSource,
    CaptureState,
    FrameSubtype,
    ParseStatus,
    SecurityClassification,
    SsidState,
)
from wids.capture.packet_parser import PacketParser  # noqa: E402
from wids.capture.packet_source import PcapPacketSource  # noqa: E402
from wids.workers.capture_worker import CaptureWorker, WorkerConfig  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURE = PROJECT_ROOT / "pcap_samples" / "lab_management_frames.pcap"
pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None,
    reason="TShark is required for PyShark PCAP integration tests.",
)


def test_lab_management_fixture_matches_the_frame_contract() -> None:
    parser = PacketParser()
    source = PcapPacketSource(
        FIXTURE,
        pcap_reference="pcap_samples/lab_management_frames.pcap",
    )

    results = [parser.parse(envelope) for envelope in source.packets()]
    frames = [result.frame for result in results if result.frame is not None]

    failures = [
        {
            "disposition": result.disposition.value,
            "reason": result.reason.value if result.reason else None,
            "detail": result.detail,
        }
        for result in results
        if result.frame is None
    ]
    assert len(frames) == 5, failures
    assert [frame.frame_subtype for frame in frames] == [
        FrameSubtype.BEACON,
        FrameSubtype.PROBE_REQUEST,
        FrameSubtype.AUTHENTICATION,
        FrameSubtype.DEAUTHENTICATION,
        FrameSubtype.DISASSOCIATION,
    ]

    beacon, probe, authentication, deauthentication, disassociation = frames

    assert beacon.management.ssid == "WIDS-Lab"
    assert beacon.management.ssid_hex == "574944532d4c6162"
    assert beacon.management.advertised_channel == 6
    assert beacon.management.beacon_interval_tu == 100
    assert beacon.management.capability_privacy is True
    assert beacon.parse_status is ParseStatus.COMPLETE
    assert beacon.management.security is not None
    assert beacon.management.security.classification is SecurityClassification.WPA2
    assert beacon.management.security.group_cipher == "ccmp_128"
    assert beacon.management.security.pairwise_ciphers == ("ccmp_128",)
    assert beacon.management.security.akm_suites == ("psk",)

    assert probe.management.ssid_state is SsidState.WILDCARD
    assert probe.management.ssid_hex == ""
    assert authentication.management.authentication_algorithm == 0
    assert authentication.management.authentication_sequence == 1
    assert deauthentication.management.reason_code == 7
    assert disassociation.management.reason_code == 8
    assert all(
        frame.evidence.pcap_reference == "pcap_samples/lab_management_frames.pcap"
        for frame in frames
    )


def test_capture_worker_replays_the_fixture_end_to_end(tmp_path: Path) -> None:
    worker = CaptureWorker(
        WorkerConfig(
            source_mode=CaptureSource.PCAP,
            feature_window_seconds=(10.0, 30.0),
            runtime_pcap_directory=tmp_path,
            heartbeat_interval_seconds=60.0,
            pcap_path=FIXTURE,
            pcap_reference="pcap_samples/lab_management_frames.pcap",
        )
    )

    status = worker.run()

    assert status.state is CaptureState.STOPPED
    assert status.packets_seen == 5
    assert status.packets_parsed == 5
    assert status.packets_skipped == 0
    assert status.parse_errors == 0
