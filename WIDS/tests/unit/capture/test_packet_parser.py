from __future__ import annotations

from datetime import timedelta
import unittest
from uuid import uuid4

from wids.capture.frame_models import (
    CaptureSource,
    FcsStatus,
    FrameSubtype,
    ParseStatus,
    ParserDisposition,
    ParserReason,
    SecurityClassification,
    SsidState,
)
from wids.capture.packet_parser import PacketParser

from tests.unit.capture.fakes import (
    AP,
    BROADCAST,
    DEFAULT_TIME,
    STATION,
    make_envelope,
    make_packet,
)


class PacketParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = PacketParser()

    def test_beacon_normalizes_identity_radio_and_security(self) -> None:
        result = self.parser.parse(make_envelope())

        self.assertEqual(result.disposition, ParserDisposition.ACCEPTED)
        assert result.frame is not None
        frame = result.frame
        self.assertEqual(frame.frame_subtype, FrameSubtype.BEACON)
        self.assertEqual(frame.addresses.bssid, AP)
        self.assertEqual(frame.addresses.receiver_mac, BROADCAST)
        self.assertEqual(frame.management.ssid, "WIDS-Lab")
        self.assertEqual(frame.management.ssid_hex, "574944532d4c6162")
        self.assertEqual(frame.radio.channel, 6)
        self.assertEqual(frame.radio.signal_dbm, -47)
        self.assertEqual(frame.radio.fcs_status, FcsStatus.UNKNOWN)
        self.assertEqual(frame.parse_status, ParseStatus.COMPLETE)
        self.assertIsNotNone(frame.management.security)
        assert frame.management.security is not None
        self.assertEqual(
            frame.management.security.classification,
            SecurityClassification.WPA2,
        )
        self.assertEqual(
            frame.management.security.pairwise_ciphers,
            ("ccmp_128",),
        )
        self.assertEqual(frame.management.security.akm_suites, ("psk",))
        self.assertIsNotNone(frame.evidence.frame_sha256)

    def test_deauthentication_normalizes_reason_sequence_and_evidence(self) -> None:
        packet = make_packet(
            subtype=12,
            ssid_raw=None,
            advertised_channel=None,
            include_security=False,
        )
        result = self.parser.parse(
            make_envelope(
                packet,
                packet_number=1901,
                pcap_reference="pcap_samples/deauth_flood.pcap",
            )
        )

        assert result.frame is not None
        frame = result.frame
        self.assertEqual(frame.frame_subtype, FrameSubtype.DEAUTHENTICATION)
        self.assertEqual(frame.addresses.receiver_mac, STATION)
        self.assertEqual(frame.addresses.transmitter_mac, AP)
        self.assertEqual(frame.management.reason_code, 7)
        self.assertEqual(frame.sequence.sequence_number, 931)
        self.assertEqual(frame.evidence.pcap_reference, "pcap_samples/deauth_flood.pcap")
        self.assertEqual(frame.parse_status, ParseStatus.COMPLETE)

    def test_wildcard_probe_and_hidden_beacon_are_distinct(self) -> None:
        wildcard = self.parser.parse(
            make_envelope(
                make_packet(
                    subtype=4,
                    ssid_raw=b"",
                    advertised_channel=None,
                    include_security=False,
                )
            )
        )
        hidden = self.parser.parse(
            make_envelope(make_packet(subtype=8, ssid_raw=b""))
        )

        assert wildcard.frame is not None
        assert hidden.frame is not None
        self.assertEqual(
            wildcard.frame.management.ssid_state,
            SsidState.WILDCARD,
        )
        self.assertEqual(
            hidden.frame.management.ssid_state,
            SsidState.HIDDEN,
        )
        self.assertEqual(wildcard.frame.management.ssid_hex, "")
        self.assertEqual(hidden.frame.management.ssid_hex, "")

    def test_invalid_utf8_ssid_preserves_exact_hex(self) -> None:
        result = self.parser.parse(
            make_envelope(make_packet(ssid_raw=b"\xff\xfe"))
        )

        assert result.frame is not None
        self.assertIsNone(result.frame.management.ssid)
        self.assertEqual(result.frame.management.ssid_hex, "fffe")
        self.assertEqual(
            result.frame.management.ssid_state,
            SsidState.INVALID_UTF8,
        )

    def test_missing_optional_radiotap_fields_do_not_crash(self) -> None:
        result = self.parser.parse(
            make_envelope(make_packet(radio=False))
        )

        assert result.frame is not None
        self.assertIsNone(result.frame.radio.signal_dbm)
        self.assertIsNone(result.frame.radio.frequency_mhz)
        self.assertEqual(result.frame.parse_status, ParseStatus.COMPLETE)

    def test_truncated_header_is_rejected(self) -> None:
        result = self.parser.parse(
            make_envelope(make_packet(truncated=True))
        )

        self.assertEqual(result.disposition, ParserDisposition.REJECTED)
        self.assertEqual(
            result.reason,
            ParserReason.TRUNCATED_MANAGEMENT_HEADER,
        )

    def test_explicitly_invalid_fcs_is_rejected(self) -> None:
        result = self.parser.parse(
            make_envelope(make_packet(invalid_fcs=True))
        )

        self.assertEqual(result.disposition, ParserDisposition.REJECTED)
        self.assertEqual(result.reason, ParserReason.INVALID_FCS)

    def test_malformed_rsn_yields_partial_frame_and_warning(self) -> None:
        result = self.parser.parse(
            make_envelope(make_packet(malformed_rsn=True))
        )

        assert result.frame is not None
        self.assertEqual(result.frame.parse_status, ParseStatus.PARTIAL)
        self.assertIn("malformed_rsn_ie", result.frame.parse_warnings)
        self.assertIsNone(result.frame.management.security)

    def test_non_wireless_and_data_frames_are_ignored(self) -> None:
        no_wlan = self.parser.parse(
            make_envelope(make_packet(include_wlan=False))
        )
        data = self.parser.parse(
            make_envelope(make_packet(frame_type=2))
        )

        self.assertEqual(no_wlan.reason, ParserReason.NOT_IEEE80211)
        self.assertEqual(data.reason, ParserReason.OUT_OF_SCOPE_FRAME_TYPE)

    def test_live_and_replay_are_semantically_equivalent(self) -> None:
        session_id = uuid4()
        packet = make_packet(observed_at=DEFAULT_TIME + timedelta(seconds=1))
        replay = self.parser.parse(
            make_envelope(
                packet,
                capture_session_id=session_id,
                capture_source=CaptureSource.PCAP,
                pcap_reference="evidence/same.pcap",
            )
        )
        live = self.parser.parse(
            make_envelope(
                packet,
                capture_session_id=session_id,
                capture_source=CaptureSource.LIVE,
                interface_name="wlan0mon",
                pcap_reference="evidence/same.pcap",
            )
        )

        assert replay.frame is not None
        assert live.frame is not None
        self.assertEqual(
            replay.frame.semantic_dict(),
            live.frame.semantic_dict(),
        )


if __name__ == "__main__":
    unittest.main()
