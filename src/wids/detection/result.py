from dataclasses import dataclass
from typing import Self

from wids.common.enums import DetectionDisposition
from wids.contracts.detection_event import DetectionEvent


@dataclass(frozen=True, slots=True)
class RuleEvaluationResult:
    """Result returned by one detection-rule evaluation."""

    disposition: DetectionDisposition
    event: DetectionEvent | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.disposition is DetectionDisposition.DETECTED and self.event is None:
            raise ValueError("A detected result must contain a DetectionEvent")

        if self.disposition is not DetectionDisposition.DETECTED and self.event is not None:
            raise ValueError("Only a detected result may contain a DetectionEvent")

        if self.disposition is DetectionDisposition.SKIPPED and not self.reason:
            raise ValueError("A skipped result must include a reason")

    @classmethod
    def detected(
        cls,
        event: DetectionEvent,
    ) -> Self:
        return cls(
            disposition=DetectionDisposition.DETECTED,
            event=event,
        )

    @classmethod
    def not_detected(cls) -> Self:
        return cls(
            disposition=DetectionDisposition.NOT_DETECTED,
        )

    @classmethod
    def skipped(
        cls,
        reason: str,
    ) -> Self:
        return cls(
            disposition=DetectionDisposition.SKIPPED,
            reason=reason,
        )
