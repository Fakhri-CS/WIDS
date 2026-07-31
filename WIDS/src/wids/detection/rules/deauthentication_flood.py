from dataclasses import dataclass
from uuid import UUID, uuid4

from wids.contracts.detection_event import (
    DetectionEvent,
    EvidenceReference,
)
from wids.detection.config import RuleConfig
from wids.detection.correlation import build_correlation_key
from wids.detection.frame_protocols import (
    NormalizedWirelessFrameProtocol,
)
from wids.detection.required_fields import find_missing_fields
from wids.detection.result import RuleEvaluationResult
from wids.detection.rules.base import DetectionRule
from wids.detection.state import (
    CooldownTracker,
    RetryDeduplicator,
    RetryFrameKey,
    SlidingWindowStore,
)

DEAUTHENTICATION_RULE_CODE = "WIDS-R001"
DEAUTHENTICATION_EVENT_TYPE = "deauthentication_flood"

_REQUIRED_FIELDS = (
    "contract_version",
    "frame_id",
    "capture_session_id",
    "packet_number",
    "observed_at",
    "addresses.receiver_mac",
    "addresses.transmitter_mac",
    "addresses.bssid",
    "sequence.sequence_number",
    "sequence.fragment_number",
    "flags.retry",
    "evidence.pcap_reference",
)


@dataclass(frozen=True, slots=True)
class DeauthenticationWindowKey:
    """Aggregation identity for a deauthentication flood."""

    capture_session_id: UUID
    transmitter_mac: str
    bssid: str


@dataclass(frozen=True, slots=True)
class DeauthenticationObservation:
    """Small immutable record stored inside the active window."""

    evidence: EvidenceReference
    receiver_mac: str
    reason_code: int | None


class DeauthenticationFloodRule(DetectionRule[NormalizedWirelessFrameProtocol]):
    """Detect excessive deauthentication management frames."""

    def __init__(
        self,
        config: RuleConfig,
    ) -> None:
        super().__init__(config)

        if config.code != DEAUTHENTICATION_RULE_CODE:
            raise ValueError("DeauthenticationFloodRule requires WIDS-R001")

        if config.event_type != DEAUTHENTICATION_EVENT_TYPE:
            raise ValueError("DeauthenticationFloodRule requires deauthentication_flood event type")

        if config.threshold is None or config.window_seconds is None:
            raise ValueError("DeauthenticationFloodRule requires threshold and window_seconds")

        self._threshold = config.threshold
        self._window_seconds = config.window_seconds

        self._windows = SlidingWindowStore[
            DeauthenticationWindowKey,
            DeauthenticationObservation,
        ]()

        self._retry_deduplicator = RetryDeduplicator()
        self._cooldown_tracker = CooldownTracker()

        self._window_keys_by_session: dict[
            UUID,
            set[DeauthenticationWindowKey],
        ] = {}

        self._correlation_keys_by_session: dict[
            UUID,
            set[str],
        ] = {}

    def evaluate(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> RuleEvaluationResult:
        if not self.config.enabled:
            return RuleEvaluationResult.skipped("rule_disabled")

        if frame.frame_subtype != "deauthentication":
            return RuleEvaluationResult.not_detected()

        missing_fields = find_missing_fields(
            frame,
            _REQUIRED_FIELDS,
        )

        if missing_fields:
            return RuleEvaluationResult.skipped(
                "missing required fields: " + ", ".join(missing_fields)
            )

        transmitter_mac = frame.addresses.transmitter_mac
        receiver_mac = frame.addresses.receiver_mac
        bssid = frame.addresses.bssid
        sequence_number = frame.sequence.sequence_number
        fragment_number = frame.sequence.fragment_number

        if bssid is None:
            return RuleEvaluationResult.skipped("missing required fields: addresses.bssid")

        if sequence_number is None:
            return RuleEvaluationResult.skipped("missing required fields: sequence.sequence_number")

        if fragment_number is None:
            return RuleEvaluationResult.skipped("missing required fields: sequence.fragment_number")

        retry_key = RetryFrameKey(
            capture_session_id=frame.capture_session_id,
            transmitter_mac=transmitter_mac,
            frame_subtype=frame.frame_subtype,
            sequence_number=sequence_number,
            fragment_number=fragment_number,
        )

        is_duplicate_retry = self._retry_deduplicator.check_and_record(
            key=retry_key,
            observed_at=frame.observed_at,
            is_retry=frame.flags.retry,
        )

        if is_duplicate_retry:
            return RuleEvaluationResult.suppressed("duplicate_retry")

        evidence = EvidenceReference(
            frame_id=frame.frame_id,
            capture_session_id=frame.capture_session_id,
            packet_number=frame.packet_number,
            observed_at=frame.observed_at,
            pcap_reference=frame.evidence.pcap_reference,
            frame_sha256=frame.evidence.frame_sha256,
        )

        observation = DeauthenticationObservation(
            evidence=evidence,
            receiver_mac=receiver_mac,
            reason_code=frame.management.reason_code,
        )

        window_key = DeauthenticationWindowKey(
            capture_session_id=frame.capture_session_id,
            transmitter_mac=transmitter_mac,
            bssid=bssid,
        )

        self._window_keys_by_session.setdefault(
            frame.capture_session_id,
            set(),
        ).add(window_key)

        observed_count = self._windows.add(
            key=window_key,
            observed_at=frame.observed_at,
            value=observation,
            window_seconds=self._window_seconds,
        )

        if observed_count < self._threshold:
            return RuleEvaluationResult.not_detected()

        correlation_key = build_correlation_key(
            rule_code=self.rule_code,
            capture_session_id=frame.capture_session_id,
            components={
                "transmitter_mac": transmitter_mac,
                "bssid": bssid,
            },
        )

        self._correlation_keys_by_session.setdefault(
            frame.capture_session_id,
            set(),
        ).add(correlation_key)

        should_emit = self._cooldown_tracker.should_emit_and_record(
            correlation_key=correlation_key,
            detected_at=frame.observed_at,
            cooldown_seconds=self.config.cooldown_seconds,
        )

        if not should_emit:
            return RuleEvaluationResult.suppressed("cooldown_active")

        observations = self._windows.values(window_key)

        reason_codes = sorted(
            {item.reason_code for item in observations if item.reason_code is not None}
        )

        unique_receiver_count = len({item.receiver_mac for item in observations})

        evidence_references = self._sample_evidence(observations)

        event = DetectionEvent(
            event_id=uuid4(),
            frame_contract_version=frame.contract_version,
            rule_code=self.rule_code,
            event_type=self.event_type,
            capture_session_id=frame.capture_session_id,
            detected_at=frame.observed_at,
            severity=self.config.severity,
            correlation_key=correlation_key,
            correlation_window_seconds=(self.config.correlation_window_seconds),
            transmitter_mac=transmitter_mac,
            receiver_mac=receiver_mac,
            source_mac=frame.addresses.source_mac,
            destination_mac=(frame.addresses.destination_mac),
            bssid=bssid,
            ssid=None,
            ssid_hex=None,
            channel=frame.radio.channel,
            title="Deauthentication Flood Detected",
            description=(
                f"Observed {observed_count} deauthentication "
                f"frames from {transmitter_mac} toward BSSID "
                f"{bssid} within {self._window_seconds} seconds."
            ),
            metrics={
                "observed_count": observed_count,
                "threshold": self._threshold,
                "window_seconds": self._window_seconds,
                "unique_receiver_count": (unique_receiver_count),
                "reason_codes": reason_codes,
            },
            evidence=evidence_references,
        )

        return RuleEvaluationResult.detected(event)

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        window_keys = self._window_keys_by_session.pop(
            capture_session_id,
            set(),
        )

        for window_key in window_keys:
            self._windows.clear_key(window_key)

        correlation_keys = self._correlation_keys_by_session.pop(
            capture_session_id,
            set(),
        )

        for correlation_key in correlation_keys:
            self._cooldown_tracker.clear_key(correlation_key)

        self._retry_deduplicator.clear_session(capture_session_id)

    @staticmethod
    def _sample_evidence(
        observations: tuple[
            DeauthenticationObservation,
            ...,
        ],
        maximum_items: int = 20,
    ) -> tuple[EvidenceReference, ...]:
        if len(observations) <= maximum_items:
            return tuple(item.evidence for item in observations)

        half = maximum_items // 2

        selected_observations = observations[:half] + observations[-half:]

        return tuple(item.evidence for item in selected_observations)
