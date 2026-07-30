from abc import abstractmethod
from collections.abc import Hashable
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from wids.contracts.detection_event import (
    DetectionEvent,
    EvidenceReference,
)
from wids.detection.config import RuleConfig
from wids.detection.correlation import (
    CorrelationValue,
    build_correlation_key,
)
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

_BASE_REQUIRED_FIELDS = (
    "contract_version",
    "frame_id",
    "capture_session_id",
    "packet_number",
    "observed_at",
    "addresses.receiver_mac",
    "addresses.transmitter_mac",
    "sequence.sequence_number",
    "sequence.fragment_number",
    "flags.retry",
    "evidence.pcap_reference",
)


@dataclass(frozen=True, slots=True)
class ManagementFloodObservation:
    """Small frame record retained in a rate-based window."""

    evidence: EvidenceReference
    receiver_mac: str
    reason_code: int | None
    authentication_sequence: int | None
    ssid_hex: str | None
    ssid_state: str


class ManagementFrameFloodRule(DetectionRule[NormalizedWirelessFrameProtocol]):
    """Shared implementation for management-frame flood rules."""

    expected_rule_code: str
    expected_event_type: str
    expected_frame_subtype: str

    event_title: str
    event_label: str

    additional_required_fields: tuple[str, ...] = ()

    def __init__(
        self,
        config: RuleConfig,
    ) -> None:
        super().__init__(config)

        if config.code != self.expected_rule_code:
            raise ValueError(f"{type(self).__name__} requires {self.expected_rule_code}")

        if config.event_type != self.expected_event_type:
            raise ValueError(f"{type(self).__name__} requires {self.expected_event_type}")

        if config.threshold is None or config.window_seconds is None:
            raise ValueError(f"{type(self).__name__} requires threshold and window_seconds")

        self._threshold = config.threshold
        self._window_seconds = config.window_seconds

        self._windows = SlidingWindowStore[
            Hashable,
            ManagementFloodObservation,
        ]()

        self._retry_deduplicator = RetryDeduplicator()
        self._cooldown_tracker = CooldownTracker()

        self._window_keys_by_session: dict[
            UUID,
            set[Hashable],
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

        if frame.frame_subtype != self.expected_frame_subtype:
            return RuleEvaluationResult.not_detected()

        required_fields = _BASE_REQUIRED_FIELDS + self.additional_required_fields

        missing_fields = find_missing_fields(
            frame,
            required_fields,
        )

        if missing_fields:
            return RuleEvaluationResult.skipped(
                "missing required fields: " + ", ".join(missing_fields)
            )

        prefilter_result = self._prefilter(frame)

        if prefilter_result is not None:
            return prefilter_result

        sequence_number = frame.sequence.sequence_number
        fragment_number = frame.sequence.fragment_number

        if sequence_number is None:
            return RuleEvaluationResult.skipped("missing required fields: sequence.sequence_number")

        if fragment_number is None:
            return RuleEvaluationResult.skipped("missing required fields: sequence.fragment_number")

        retry_key = RetryFrameKey(
            capture_session_id=frame.capture_session_id,
            transmitter_mac=(frame.addresses.transmitter_mac),
            frame_subtype=frame.frame_subtype,
            sequence_number=sequence_number,
            fragment_number=fragment_number,
        )

        duplicate_retry = self._retry_deduplicator.check_and_record(
            key=retry_key,
            observed_at=frame.observed_at,
            is_retry=frame.flags.retry,
        )

        if duplicate_retry:
            return RuleEvaluationResult.suppressed("duplicate_retry")

        evidence = EvidenceReference(
            frame_id=frame.frame_id,
            capture_session_id=frame.capture_session_id,
            packet_number=frame.packet_number,
            observed_at=frame.observed_at,
            pcap_reference=frame.evidence.pcap_reference,
            frame_sha256=frame.evidence.frame_sha256,
        )

        observation = ManagementFloodObservation(
            evidence=evidence,
            receiver_mac=frame.addresses.receiver_mac,
            reason_code=frame.management.reason_code,
            authentication_sequence=(frame.management.authentication_sequence),
            ssid_hex=frame.management.ssid_hex,
            ssid_state=frame.management.ssid_state,
        )

        window_key = self._build_window_key(frame)

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
            components=(self._build_correlation_components(frame)),
        )

        self._correlation_keys_by_session.setdefault(
            frame.capture_session_id,
            set(),
        ).add(correlation_key)

        should_emit = self._cooldown_tracker.should_emit_and_record(
            correlation_key=correlation_key,
            detected_at=frame.observed_at,
            cooldown_seconds=(self.config.cooldown_seconds),
        )

        if not should_emit:
            return RuleEvaluationResult.suppressed("cooldown_active")

        observations = self._windows.values(window_key)

        metrics: dict[str, Any] = {
            "observed_count": observed_count,
            "threshold": self._threshold,
            "window_seconds": self._window_seconds,
        }

        metrics.update(self._build_rule_metrics(observations))

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
            transmitter_mac=(frame.addresses.transmitter_mac),
            receiver_mac=frame.addresses.receiver_mac,
            source_mac=frame.addresses.source_mac,
            destination_mac=(frame.addresses.destination_mac),
            bssid=frame.addresses.bssid,
            ssid=frame.management.ssid,
            ssid_hex=frame.management.ssid_hex,
            channel=frame.radio.channel,
            title=self.event_title,
            description=self._build_description(
                frame=frame,
                observed_count=observed_count,
            ),
            metrics=metrics,
            evidence=self._sample_evidence(observations),
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

    def _prefilter(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> RuleEvaluationResult | None:
        del frame
        return None

    @abstractmethod
    def _build_window_key(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> Hashable:
        """Build the state-window aggregation identity."""

    @abstractmethod
    def _build_correlation_components(
        self,
        frame: NormalizedWirelessFrameProtocol,
    ) -> dict[str, CorrelationValue]:
        """Build rule-specific correlation components."""

    @abstractmethod
    def _build_rule_metrics(
        self,
        observations: tuple[
            ManagementFloodObservation,
            ...,
        ],
    ) -> dict[str, Any]:
        """Build metrics specific to the rule."""

    def _build_description(
        self,
        *,
        frame: NormalizedWirelessFrameProtocol,
        observed_count: int,
    ) -> str:
        return (
            f"Observed {observed_count} "
            f"{self.event_label} frames from "
            f"{frame.addresses.transmitter_mac} "
            f"within {self._window_seconds} seconds."
        )

    @staticmethod
    def _sample_evidence(
        observations: tuple[
            ManagementFloodObservation,
            ...,
        ],
        maximum_items: int = 20,
    ) -> tuple[EvidenceReference, ...]:
        if len(observations) <= maximum_items:
            return tuple(item.evidence for item in observations)

        first_half = maximum_items // 2
        last_half = maximum_items - first_half

        selected = observations[:first_half] + observations[-last_half:]

        return tuple(item.evidence for item in selected)
