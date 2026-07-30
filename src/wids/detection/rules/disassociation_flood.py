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
class DisassociationWindowKey:
    capture_session_id: UUID
    transmitter_mac: str
    bssid: str


class DisassociationFloodRule(ManagementFrameFloodRule):
    expected_rule_code = "WIDS-R002"
    expected_event_type = "disassociation_flood"
    expected_frame_subtype = "disassociation"

    event_title = "Disassociation Flood Detected"
    event_label = "disassociation"

    additional_required_fields = ("addresses.bssid",)

    def _build_window_key(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> DisassociationWindowKey:
        bssid = frame.addresses.bssid
        assert bssid is not None

        return DisassociationWindowKey(
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
        reason_codes = sorted(
            {
                observation.reason_code
                for observation in observations
                if observation.reason_code is not None
            }
        )

        unique_receivers = {observation.receiver_mac for observation in observations}

        return {
            "unique_receiver_count": len(unique_receivers),
            "reason_codes": reason_codes,
        }
