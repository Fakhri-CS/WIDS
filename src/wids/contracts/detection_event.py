import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from wids.common.enums import AlertSeverity

DETECTION_EVENT_CONTRACT_VERSION = "1.0"

_RULE_CODE_PATTERN = re.compile(r"^WIDS-R\d{3}$")
_EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _validate_utc_datetime(
    value: datetime,
    field_name: str,
) -> None:
    """Ensure a datetime is timezone-aware and normalized to UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC")


def _serialize_datetime(value: datetime) -> str:
    """Serialize a UTC datetime using RFC 3339 with microseconds."""

    return (
        value.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Reference to one normalized wireless frame used as evidence."""

    frame_id: UUID
    capture_session_id: UUID
    packet_number: int
    observed_at: datetime
    pcap_reference: str
    frame_sha256: str | None = None

    def __post_init__(self) -> None:
        _validate_utc_datetime(
            self.observed_at,
            "observed_at",
        )

        if self.packet_number < 1:
            raise ValueError("packet_number must be at least 1")

        if not self.pcap_reference.strip():
            raise ValueError("pcap_reference must not be empty")

        if (
            self.frame_sha256 is not None
            and _SHA256_PATTERN.fullmatch(self.frame_sha256) is None
        ):
            raise ValueError(
                "frame_sha256 must be a lowercase SHA-256 hexadecimal value"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert the evidence reference to a JSON-compatible dictionary."""

        return {
            "frame_id": str(self.frame_id),
            "capture_session_id": str(self.capture_session_id),
            "packet_number": self.packet_number,
            "observed_at": _serialize_datetime(self.observed_at),
            "pcap_reference": self.pcap_reference,
            "frame_sha256": self.frame_sha256,
        }


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """Normalized event emitted by a WIDS detection rule."""

    event_id: UUID
    frame_contract_version: str

    rule_code: str
    event_type: str
    capture_session_id: UUID

    detected_at: datetime
    severity: AlertSeverity

    correlation_key: str
    correlation_window_seconds: int

    transmitter_mac: str | None
    receiver_mac: str | None
    source_mac: str | None
    destination_mac: str | None
    bssid: str | None

    ssid: str | None
    ssid_hex: str | None
    channel: int | None

    title: str
    description: str

    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[EvidenceReference, ...] = ()
    event_contract_version: str = DETECTION_EVENT_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _validate_utc_datetime(
            self.detected_at,
            "detected_at",
        )

        if self.event_contract_version != DETECTION_EVENT_CONTRACT_VERSION:
            raise ValueError(
                "Unsupported detection-event contract version"
            )

        if not self.frame_contract_version.strip():
            raise ValueError(
                "frame_contract_version must not be empty"
            )

        if _RULE_CODE_PATTERN.fullmatch(self.rule_code) is None:
            raise ValueError(
                "rule_code must use the WIDS-R000 format"
            )

        if _EVENT_TYPE_PATTERN.fullmatch(self.event_type) is None:
            raise ValueError(
                "event_type must use lowercase snake_case"
            )

        if _SHA256_PATTERN.fullmatch(self.correlation_key) is None:
            raise ValueError(
                "correlation_key must be a lowercase SHA-256 value"
            )

        if self.correlation_window_seconds < 1:
            raise ValueError(
                "correlation_window_seconds must be positive"
            )

        if not self.title.strip():
            raise ValueError("title must not be empty")

        if not self.description.strip():
            raise ValueError("description must not be empty")

        for evidence_reference in self.evidence:
            if (
                evidence_reference.capture_session_id
                != self.capture_session_id
            ):
                raise ValueError(
                    "All evidence must belong to the event capture session"
                )

    def to_dict(self) -> dict[str, Any]:
        """Convert the event to a JSON-compatible dictionary."""

        return {
            "event_id": str(self.event_id),
            "event_contract_version": self.event_contract_version,
            "frame_contract_version": self.frame_contract_version,
            "rule_code": self.rule_code,
            "event_type": self.event_type,
            "capture_session_id": str(self.capture_session_id),
            "detected_at": _serialize_datetime(self.detected_at),
            "severity": self.severity.value,
            "correlation_key": self.correlation_key,
            "correlation_window_seconds": (
                self.correlation_window_seconds
            ),
            "transmitter_mac": self.transmitter_mac,
            "receiver_mac": self.receiver_mac,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "ssid_hex": self.ssid_hex,
            "channel": self.channel,
            "title": self.title,
            "description": self.description,
            "metrics": dict(self.metrics),
            "evidence": [
                evidence_reference.to_dict()
                for evidence_reference in self.evidence
            ],
        }
