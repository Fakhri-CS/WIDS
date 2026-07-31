from dataclasses import dataclass
from typing import Any
from uuid import UUID

from wids.detection.correlation import CorrelationValue
from wids.detection.frame_protocols import (
    NormalizedWirelessFrameProtocol,
)
from wids.detection.rules.management_flood_base import (
    ManagementFloodObservation,
    ManagementFrameFloodRule,
)


@dataclass(frozen=True, slots=True)
class BeaconWindowKey:
    capture_session_id: UUID
    transmitter_mac: str
    bssid: str


class BeaconFloodRule(ManagementFrameFloodRule):
    expected_rule_code = "WIDS-R005"
    expected_event_type = "beacon_flood"
    expected_frame_subtype = "beacon"

    event_title = "Beacon Flood Detected"
    event_label = "beacon"

    additional_required_fields = (
        "addresses.bssid",
        "management.ssid_state",
    )

    def _build_window_key(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> BeaconWindowKey:
        bssid = frame.addresses.bssid
        assert bssid is not None

        return BeaconWindowKey(
            capture_session_id=frame.capture_session_id,
            transmitter_mac=(frame.addresses.transmitter_mac),
            bssid=bssid,
        )

    def _build_correlation_components(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> dict[str, CorrelationValue]:
        return {
            "transmitter_mac": (frame.addresses.transmitter_mac),
            "bssid": frame.addresses.bssid,
        }

    def _build_rule_metrics(
        self,
        observations: tuple[
            ManagementFloodObservation,
            ...,
        ],
    ) -> dict[str, Any]:
        unique_ssids = {
            observation.ssid_hex for observation in observations if observation.ssid_hex is not None
        }

        hidden_ssid_count = sum(observation.ssid_state == "hidden" for observation in observations)

        return {
            "unique_ssid_count": len(unique_ssids),
            "hidden_ssid_count": hidden_ssid_count,
        }
