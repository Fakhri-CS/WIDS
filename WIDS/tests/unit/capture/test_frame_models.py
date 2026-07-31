from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from tests.unit.capture.fakes import make_envelope
from wids.capture.frame_models import (
    NormalizedWirelessFrame,
    SecurityClassification,
    SecurityProfile,
    SecurityProtocol,
    normalize_mac,
)
from wids.capture.packet_parser import PacketParser


class FrameModelTests(unittest.TestCase):
    def test_security_profile_is_canonical_and_deterministic(self) -> None:
        first = SecurityProfile(
            classification=SecurityClassification.WPA2,
            protocols=(SecurityProtocol.WPA2, SecurityProtocol.WPA2),
            group_cipher="CCMP_128",
            pairwise_ciphers=("tkip", "ccmp_128", "CCMP_128"),
            akm_suites=("psk", "ieee8021x", "psk"),
            pmf_capable=True,
            pmf_required=False,
        )
        second = SecurityProfile(
            classification=SecurityClassification.WPA2,
            protocols=(SecurityProtocol.WPA2,),
            group_cipher="ccmp_128",
            pairwise_ciphers=("ccmp_128", "tkip"),
            akm_suites=("ieee8021x", "psk"),
            pmf_capable=True,
            pmf_required=False,
        )

        self.assertEqual(first.fingerprint_sha256, second.fingerprint_sha256)
        self.assertEqual(first.pairwise_ciphers, ("ccmp_128", "tkip"))
        self.assertEqual(first.akm_suites, ("ieee8021x", "psk"))

    def test_json_round_trip_preserves_contract_values(self) -> None:
        result = PacketParser().parse(make_envelope())
        self.assertIsNotNone(result.frame)
        assert result.frame is not None

        restored = NormalizedWirelessFrame.from_json(result.frame.to_json())

        self.assertEqual(restored.to_dict(), result.frame.to_dict())

    def test_frame_is_immutable(self) -> None:
        result = PacketParser().parse(make_envelope())
        assert result.frame is not None
        with self.assertRaises(FrozenInstanceError):
            result.frame.packet_number = 99  # type: ignore[misc]

    def test_mac_normalization_accepts_common_notation(self) -> None:
        self.assertEqual(
            normalize_mac("aa-bb-cc-dd-ee-ff"),
            "AA:BB:CC:DD:EE:FF",
        )
        self.assertEqual(
            normalize_mac("aabb.ccdd.eeff"),
            "AA:BB:CC:DD:EE:FF",
        )
        with self.assertRaises(ValueError):
            normalize_mac("not-a-mac")


if __name__ == "__main__":
    unittest.main()
