import re
from dataclasses import dataclass

from wids.common.enums import AlertSeverity

_RULE_CODE_PATTERN = re.compile(r"^WIDS-R\d{3}$")
_EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """Validated runtime configuration for one detection rule."""

    code: str
    event_type: str
    enabled: bool
    severity: AlertSeverity

    correlation_window_seconds: int
    cooldown_seconds: int

    threshold: int | None = None
    window_seconds: int | None = None

    def __post_init__(self) -> None:
        if _RULE_CODE_PATTERN.fullmatch(self.code) is None:
            raise ValueError("code must use the WIDS-R000 format")

        if _EVENT_TYPE_PATTERN.fullmatch(self.event_type) is None:
            raise ValueError("event_type must use lowercase snake_case")

        if self.correlation_window_seconds < 1:
            raise ValueError("correlation_window_seconds must be positive")

        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")

        if self.threshold is not None and self.threshold < 1:
            raise ValueError("threshold must be positive")

        if self.window_seconds is not None and self.window_seconds < 1:
            raise ValueError("window_seconds must be positive")

        if (self.threshold is None) != (self.window_seconds is None):
            raise ValueError("threshold and window_seconds must be provided together")

    @property
    def is_rate_based(self) -> bool:
        """Return whether the rule uses a threshold and time window."""

        return self.threshold is not None and self.window_seconds is not None
