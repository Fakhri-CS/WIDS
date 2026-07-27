from enum import StrEnum


class AlertSeverity(StrEnum):
    """Supported WIDS alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionDisposition(StrEnum):
    """Possible outcomes of evaluating a detection rule."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    SKIPPED = "skipped"
    SUPPRESSED = "suppressed"
