from __future__ import annotations

import unittest
from datetime import timedelta
from uuid import uuid4

from tests.unit.capture.fakes import (
    AP,
    DEFAULT_TIME,
    make_envelope,
    make_packet,
)
from wids.capture.feature_extractor import FeatureExtractor
from wids.capture.packet_parser import PacketParser


class FeatureExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = PacketParser()
        self.session_id = uuid4()

    def frame(
        self,
        *,
        seconds: float,
        subtype: int = 12,
        retry: bool = False,
        sequence: int = 1,
    ):
        packet = make_packet(
            subtype=subtype,
            observed_at=DEFAULT_TIME + timedelta(seconds=seconds),
            ssid_raw=None if subtype in {10, 12} else b"WIDS-Lab",
            advertised_channel=None if subtype in {10, 12} else 6,
            include_security=subtype in {5, 8},
            retry=retry,
            sequence_number=sequence,
        )
        result = self.parser.parse(
            make_envelope(
                packet,
                capture_session_id=self.session_id,
                packet_number=int(seconds * 10) + 1,
            )
        )
        assert result.frame is not None
        return result.frame

    def test_retry_deduplication_prevents_rate_inflation(self) -> None:
        extractor = FeatureExtractor((10.0,))
        first = extractor.ingest(self.frame(seconds=0, sequence=55))
        retry = extractor.ingest(
            self.frame(seconds=1, retry=True, sequence=55)
        )

        self.assertFalse(first.retry_deduplicated)
        self.assertTrue(retry.retry_deduplicated)
        snapshot = retry.snapshots[10.0]
        self.assertEqual(snapshot.frame_count, 1)
        self.assertEqual(snapshot.subtype_count("deauthentication"), 1)
        self.assertEqual(snapshot.transmitter_counts[AP], 1)

    def test_expired_groups_leave_the_window(self) -> None:
        extractor = FeatureExtractor((10.0,))
        extractor.ingest(self.frame(seconds=0, sequence=1))
        extractor.ingest(self.frame(seconds=1, retry=True, sequence=1))
        update = extractor.ingest(self.frame(seconds=12, sequence=2))

        snapshot = update.snapshots[10.0]
        self.assertEqual(snapshot.frame_count, 1)
        self.assertEqual(snapshot.subtype_count("deauthentication"), 1)

    def test_relationship_features_are_available(self) -> None:
        extractor = FeatureExtractor((5.0, 30.0))
        update = extractor.ingest(
            self.frame(seconds=0, subtype=8, sequence=10)
        )

        snapshot = update.snapshots[5.0]
        self.assertEqual(
            snapshot.ssid_bssid_counts[("574944532d4c6162", AP)],
            1,
        )
        self.assertEqual(snapshot.channels_by_bssid[AP], (6,))
        self.assertEqual(
            len(snapshot.security_fingerprints_by_bssid[AP]),
            1,
        )
        self.assertIn("access_point", snapshot.role_hints_by_transmitter[AP])

    def test_out_of_order_frames_are_rejected(self) -> None:
        extractor = FeatureExtractor((10.0,))
        extractor.ingest(self.frame(seconds=5, sequence=1))

        with self.assertRaises(ValueError):
            extractor.ingest(self.frame(seconds=4, sequence=2))

    def test_windows_must_be_supplied_by_configuration(self) -> None:
        with self.assertRaises(ValueError):
            FeatureExtractor(())
        with self.assertRaises(ValueError):
            FeatureExtractor((0,))


if __name__ == "__main__":
    unittest.main()
