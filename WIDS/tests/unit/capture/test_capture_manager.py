from __future__ import annotations

import unittest

from tests.unit.capture.fakes import make_packet
from wids.capture.capture_manager import CaptureManager
from wids.capture.feature_extractor import FeatureExtractor
from wids.capture.frame_models import CaptureState
from wids.capture.packet_parser import PacketParser
from wids.capture.packet_source import InMemoryPacketSource


class CaptureManagerTests(unittest.TestCase):
    def test_pipeline_counts_accepted_ignored_and_rejected_packets(self) -> None:
        accepted_frames = []
        feature_updates = []
        manager = CaptureManager(
            PacketParser(),
            FeatureExtractor((10.0,)),
            frame_sink=accepted_frames.append,
            feature_sink=lambda frame, update: feature_updates.append(
                (frame, update)
            ),
        )
        source = InMemoryPacketSource(
            [
                make_packet(),
                make_packet(include_wlan=False),
                make_packet(invalid_fcs=True),
            ]
        )

        status = manager.run(source)

        self.assertEqual(status.state, CaptureState.STOPPED)
        self.assertEqual(status.packets_seen, 3)
        self.assertEqual(status.packets_parsed, 1)
        self.assertEqual(status.packets_skipped, 2)
        self.assertEqual(status.parse_errors, 1)
        self.assertEqual(status.reason_counts["not_ieee80211"], 1)
        self.assertEqual(status.reason_counts["invalid_fcs"], 1)
        self.assertEqual(len(accepted_frames), 1)
        self.assertEqual(len(feature_updates), 1)
        self.assertTrue(source.closed)

    def test_processing_error_skips_one_packet_without_stopping_loop(self) -> None:
        calls = 0

        def failing_sink(frame) -> None:
            nonlocal calls
            del frame
            calls += 1
            if calls == 1:
                raise RuntimeError("database unavailable")

        manager = CaptureManager(
            PacketParser(),
            FeatureExtractor((10.0,)),
            frame_sink=failing_sink,
        )
        source = InMemoryPacketSource(
            [
                make_packet(sequence_number=1),
                make_packet(sequence_number=2),
            ]
        )

        status = manager.run(source)

        self.assertEqual(status.state, CaptureState.STOPPED)
        self.assertEqual(status.packets_seen, 2)
        self.assertEqual(status.packets_parsed, 1)
        self.assertEqual(status.reason_counts["processing_error"], 1)


if __name__ == "__main__":
    unittest.main()
