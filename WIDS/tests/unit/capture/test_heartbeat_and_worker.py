from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from wids.capture.frame_models import CaptureSource, CaptureState
from wids.capture.packet_source import InMemoryPacketSource
from wids.workers.capture_worker import CaptureWorker, WorkerConfig
from wids.workers.heartbeat import (
    HeartbeatService,
    InMemoryHeartbeatPublisher,
    heartbeat_is_stale,
)

from tests.unit.capture.fakes import make_packet


class HeartbeatAndWorkerTests(unittest.TestCase):
    def test_worker_publishes_heartbeat_and_finishes_replay(self) -> None:
        publisher = InMemoryHeartbeatPublisher()
        worker = CaptureWorker(
            WorkerConfig(
                source_mode=CaptureSource.PCAP,
                feature_window_seconds=(10.0,),
                runtime_pcap_directory=Path("runtime/pcap"),
                heartbeat_interval_seconds=60.0,
                pcap_path=Path("unused-by-injected-source.pcap"),
            ),
            heartbeat_publisher=publisher,
        )
        source = InMemoryPacketSource([make_packet()])

        status = worker.run_source(source)

        self.assertEqual(status.state, CaptureState.STOPPED)
        self.assertEqual(status.packets_parsed, 1)
        self.assertGreaterEqual(len(publisher.records), 2)
        self.assertEqual(
            publisher.records[-1].status.state,
            CaptureState.STOPPED,
        )

    def test_publish_once_is_storage_neutral(self) -> None:
        publisher = InMemoryHeartbeatPublisher()
        worker = CaptureWorker(
            WorkerConfig(
                source_mode=CaptureSource.PCAP,
                feature_window_seconds=(10.0,),
                runtime_pcap_directory=Path("runtime/pcap"),
                heartbeat_interval_seconds=5.0,
                pcap_path=Path("unused.pcap"),
            )
        )
        service = HeartbeatService(
            worker_id="capture-worker-test",
            interval_seconds=5.0,
            status_provider=worker.status,
            publisher=publisher,
        )

        record = service.publish_once()

        self.assertIsNotNone(record)
        self.assertEqual(len(publisher.records), 1)
        self.assertEqual(
            publisher.records[0].status.state,
            CaptureState.IDLE,
        )

    def test_stale_heartbeat_detection(self) -> None:
        now = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
        self.assertTrue(
            heartbeat_is_stale(
                now - timedelta(seconds=31),
                now=now,
                stale_after_seconds=30,
            )
        )
        self.assertFalse(
            heartbeat_is_stale(
                now - timedelta(seconds=30),
                now=now,
                stale_after_seconds=30,
            )
        )
        self.assertTrue(
            heartbeat_is_stale(
                None,
                now=now,
                stale_after_seconds=30,
            )
        )


if __name__ == "__main__":
    unittest.main()
