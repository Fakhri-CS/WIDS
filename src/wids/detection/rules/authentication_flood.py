from dataclasses import dataclass
from typing import Any
from uuid import UUID

from wids.detection.correlation import CorrelationValue
from wids.detection.frame_protocols import (
    NormalizedWirelessFrameProtocol,
)
from wids.detection.result import RuleEvaluationResult
from wids.detection.rules.management_flood_base import (
    ManagementFloodObservation,
    ManagementFrameFloodRule,
)


@dataclass(frozen=True, slots=True)
class AuthenticationWindowKey:
    capture_session_id: UUID
    transmitter_mac: str
    bssid: str


class AuthenticationFloodRule(ManagementFrameFloodRule):
    expected_rule_code = "WIDS-R003"
    expected_event_type = "authentication_flood"
    expected_frame_subtype = "authentication"

    event_title = "Authentication Flood Detected"
    event_label = "authentication-request"

    additional_required_fields = (
        "addresses.bssid",
        "management.authentication_sequence",
    )

    def _prefilter(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> RuleEvaluationResult | None:
        if frame.management.authentication_sequence != 1:
            return RuleEvaluationResult.not_detected()

        return None

    def _build_window_key(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> AuthenticationWindowKey:
        bssid = frame.addresses.bssid
        assert bssid is not None

        return AuthenticationWindowKey(
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
        unique_receivers = {observation.receiver_mac for observation in observations}

        return {
            "authentication_sequence": 1,
            "unique_receiver_count": len(unique_receivers),
        }
