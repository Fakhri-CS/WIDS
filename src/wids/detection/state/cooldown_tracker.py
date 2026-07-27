from datetime import datetime


def _validate_datetime(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("detected_at must be timezone-aware")


class CooldownTracker:
    """Control repeated event emission for one correlation key."""

    def __init__(self) -> None:
        self._last_emitted_at: dict[
            str,
            datetime,
        ] = {}

    @property
    def size(self) -> int:
        return len(self._last_emitted_at)

    def should_emit_and_record(
        self,
        *,
        correlation_key: str,
        detected_at: datetime,
        cooldown_seconds: int,
    ) -> bool:
        """Return whether an event may be emitted now."""

        _validate_datetime(detected_at)

        if not correlation_key.strip():
            raise ValueError("correlation_key must not be empty")

        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")

        previous_emission = self._last_emitted_at.get(correlation_key)

        if previous_emission is None:
            self._last_emitted_at[correlation_key] = detected_at

            return True

        elapsed_seconds = (detected_at - previous_emission).total_seconds()

        if elapsed_seconds < 0:
            return False

        if elapsed_seconds < cooldown_seconds:
            return False

        self._last_emitted_at[correlation_key] = detected_at

        return True

    def clear_key(
        self,
        correlation_key: str,
    ) -> None:
        self._last_emitted_at.pop(
            correlation_key,
            None,
        )

    def clear(self) -> None:
        self._last_emitted_at.clear()
