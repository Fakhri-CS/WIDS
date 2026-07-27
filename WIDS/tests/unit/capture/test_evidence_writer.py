from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

from wids.capture.evidence_writer import (
    EvidenceTarget,
    EvidenceWriter,
    EvidenceWriterError,
)


class EvidenceWriterTests(unittest.TestCase):
    def test_live_target_uses_runtime_relative_reference(self) -> None:
        with TemporaryDirectory() as directory:
            writer = EvidenceWriter(Path(directory))
            target = writer.prepare_live_capture(uuid4())
            target.storage_path.write_bytes(b"pcap-bytes")

            metadata = writer.finalize(target)

        self.assertTrue(target.pcap_reference.startswith("runtime/pcap/"))
        self.assertFalse(target.pcap_reference.startswith("/"))
        self.assertEqual(metadata.size_bytes, 10)
        self.assertEqual(len(metadata.file_sha256), 64)

    def test_replay_copy_is_persisted_atomically(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "fixture.pcap"
            source.write_bytes(b"fixture")
            writer = EvidenceWriter(root / "runtime")

            target = writer.copy_replay_evidence(source, uuid4())

            self.assertEqual(target.storage_path.read_bytes(), b"fixture")
            self.assertFalse(
                target.storage_path.with_suffix(".pcap.part").exists()
            )

    def test_finalize_rejects_path_outside_runtime_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            writer = EvidenceWriter(root / "runtime")
            outside = root / "outside.pcap"
            outside.write_bytes(b"x")
            target = EvidenceTarget(
                storage_path=outside,
                pcap_reference="runtime/pcap/outside.pcap",
                capture_session_id=uuid4(),
                created_at=writer.prepare_live_capture(uuid4()).created_at,
            )

            with self.assertRaises(EvidenceWriterError):
                writer.finalize(target)


if __name__ == "__main__":
    unittest.main()
