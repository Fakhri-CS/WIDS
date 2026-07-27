from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID


def _validate_datetime(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class RetryFrameKey:
    """Identity used to recognize a retried wireless frame."""

    capture_session_id: UUID
    transmitter_mac: str
    frame_subtype: str
    sequence_number: int
    fragment_number: int

    def __post_init__(self) -> None:
        if not self.transmitter_mac.strip():
            raise ValueError("transmitter_mac must not be empty")

        if not self.frame_subtype.strip():
            raise ValueError("frame_subtype must not be empty")

        if not 0 <= self.sequence_number <= 4095:
            raise ValueError("sequence_number must be between 0 and 4095")

        if not 0 <= self.fragment_number <= 15:
            raise ValueError("fragment_number must be between 0 and 15")


class RetryDeduplicator:
    """Prevent retransmitted frames from inflating rule counters."""

    def __init__(
        self,
        *,
        retention_seconds: int = 5,
    ) -> None:
        if retention_seconds < 1:
            raise ValueError("retention_seconds must be positive")

        self._retention_seconds = retention_seconds
        self._seen: dict[
            RetryFrameKey,
            datetime,
        ] = {}

        self._watermark: datetime | None = None

    @property
    def size(self) -> int:
        return len(self._seen)

    def check_and_record(
        self,
        *,
        key: RetryFrameKey,
        observed_at: datetime,
        is_retry: bool,
    ) -> bool:
        """Return True when the frame is a duplicate retry."""

        _validate_datetime(observed_at)

        if self._watermark is None:
            self._watermark = observed_at
        else:
            self._watermark = max(
                self._watermark,
                observed_at,
            )

        self._prune_expired()

        previous_observation = self._seen.get(key)
        is_duplicate = False

        if is_retry and previous_observation is not None:
            elapsed_seconds = abs((observed_at - previous_observation).total_seconds())

            is_duplicate = elapsed_seconds <= self._retention_seconds

        if previous_observation is None or observed_at > previous_observation:
            self._seen[key] = observed_at

        return is_duplicate

    def clear_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        matching_keys = [key for key in self._seen if key.capture_session_id == capture_session_id]

        for key in matching_keys:
            del self._seen[key]

    def clear(self) -> None:
        self._seen.clear()
        self._watermark = None

    def _prune_expired(self) -> None:
        if self._watermark is None:
            return

        cutoff = self._watermark - timedelta(seconds=self._retention_seconds)

        expired_keys = [key for key, observed_at in self._seen.items() if observed_at < cutoff]

        for key in expired_keys:
            del self._seen[key]
