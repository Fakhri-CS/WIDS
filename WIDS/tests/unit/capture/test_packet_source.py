from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from wids.capture.frame_models import CaptureSource
from wids.capture.packet_source import LivePacketSource, PcapPacketSource

from tests.unit.capture.fakes import make_packet


class FakeFileCapture:
    def __init__(self, packets) -> None:
        self.packets = packets
        self.closed = False

    def __iter__(self):
        return iter(self.packets)

    def close(self) -> None:
        self.closed = True


class FakeLiveCapture(FakeFileCapture):
    def sniff_continuously(self):
        return iter(self.packets)


class PacketSourceTests(unittest.TestCase):
    def test_pcap_source_wraps_packets_with_deterministic_metadata(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            path.write_bytes(b"fixture")
            capture = FakeFileCapture([make_packet(), make_packet()])
            received_kwargs = {}

            def factory(input_path: str, **kwargs):
                received_kwargs.update(kwargs)
                self.assertEqual(input_path, str(path))
                return capture

            source = PcapPacketSource(
                path,
                pcap_reference="pcap_samples/sample.pcap",
                capture_factory=factory,
            )
            envelopes = list(source.packets())

        self.assertEqual([item.packet_number for item in envelopes], [1, 2])
        self.assertTrue(
            all(item.capture_source is CaptureSource.PCAP for item in envelopes)
        )
        self.assertEqual(
            envelopes[0].pcap_reference,
            "pcap_samples/sample.pcap",
        )
        self.assertNotIn("include_raw", received_kwargs)
        self.assertNotIn("use_json", received_kwargs)
        self.assertTrue(capture.closed)

    def test_live_source_uses_output_file_and_interface(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "capture.pcapng"
            capture = FakeLiveCapture([make_packet()])
            received_kwargs = {}

            def factory(**kwargs):
                received_kwargs.update(kwargs)
                return capture

            source = LivePacketSource(
                "wlan0mon",
                output_file=output,
                pcap_reference="runtime/pcap/capture.pcapng",
                capture_factory=factory,
            )
            envelopes = list(source.packets())

        self.assertEqual(len(envelopes), 1)
        self.assertEqual(envelopes[0].interface_name, "wlan0mon")
        self.assertEqual(received_kwargs["interface"], "wlan0mon")
        self.assertEqual(received_kwargs["output_file"], str(output))
        self.assertTrue(capture.closed)

    def test_reference_rejects_parent_traversal(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            path.write_bytes(b"fixture")
            with self.assertRaises(ValueError):
                PcapPacketSource(
                    path,
                    pcap_reference="../private.pcap",
                )


if __name__ == "__main__":
    unittest.main()
