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
class ProbeRequestWindowKey:
    capture_session_id: UUID
    transmitter_mac: str


class ProbeRequestFloodRule(ManagementFrameFloodRule):
    expected_rule_code = "WIDS-R004"
    expected_event_type = "probe_request_flood"
    expected_frame_subtype = "probe_request"

    event_title = "Probe Request Flood Detected"
    event_label = "probe-request"

    additional_required_fields = ("management.ssid_state",)

    def _build_window_key(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> ProbeRequestWindowKey:
        return ProbeRequestWindowKey(
            capture_session_id=frame.capture_session_id,
            transmitter_mac=(frame.addresses.transmitter_mac),
        )

    def _build_correlation_components(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> dict[str, CorrelationValue]:
        return {
            "transmitter_mac": (frame.addresses.transmitter_mac),
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

        wildcard_count = sum(observation.ssid_state == "wildcard" for observation in observations)

        directed_count = sum(observation.ssid_state == "present" for observation in observations)

        return {
            "unique_ssid_count": len(unique_ssids),
            "wildcard_probe_count": wildcard_count,
            "directed_probe_count": directed_count,
        }
