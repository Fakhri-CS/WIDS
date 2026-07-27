from bisect import bisect_right
from collections import deque
from collections.abc import Hashable
from dataclasses import dataclass
from datetime import datetime, timedelta


def _validate_datetime(
    value: datetime,
    field_name: str,
) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class WindowEntry[ValueT]:
    """One timestamped value stored inside a sliding window."""

    observed_at: datetime
    value: ValueT


class SlidingWindowStore[KeyT: Hashable, ValueT]:
    """Maintain timestamp-ordered values grouped by aggregation key."""

    def __init__(self) -> None:
        self._windows: dict[
            KeyT,
            deque[WindowEntry[ValueT]],
        ] = {}

        self._watermarks: dict[KeyT, datetime] = {}

    @property
    def active_key_count(self) -> int:
        return len(self._windows)

    def add(
        self,
        *,
        key: KeyT,
        observed_at: datetime,
        value: ValueT,
        window_seconds: int,
    ) -> int:
        """Add a value and return the current active-window count."""

        _validate_datetime(
            observed_at,
            "observed_at",
        )

        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")

        previous_watermark = self._watermarks.get(key)

        if previous_watermark is None:
            watermark = observed_at
        else:
            watermark = max(
                previous_watermark,
                observed_at,
            )

        self._watermarks[key] = watermark

        window = self._windows.setdefault(
            key,
            deque(),
        )

        entry = WindowEntry(
            observed_at=observed_at,
            value=value,
        )

        if not window or observed_at >= window[-1].observed_at:
            window.append(entry)
        else:
            entries = list(window)
            timestamps = [existing_entry.observed_at for existing_entry in entries]

            insertion_index = bisect_right(
                timestamps,
                observed_at,
            )

            entries.insert(
                insertion_index,
                entry,
            )

            window = deque(entries)
            self._windows[key] = window

        cutoff = watermark - timedelta(seconds=window_seconds)

        self._prune_before(
            key=key,
            cutoff=cutoff,
        )

        return self.count(key)

    def prune(
        self,
        *,
        key: KeyT,
        reference_time: datetime,
        window_seconds: int,
    ) -> int:
        """Remove values older than the active time window."""

        _validate_datetime(
            reference_time,
            "reference_time",
        )

        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")

        previous_watermark = self._watermarks.get(key)

        if previous_watermark is None:
            watermark = reference_time
        else:
            watermark = max(
                previous_watermark,
                reference_time,
            )

        self._watermarks[key] = watermark

        cutoff = watermark - timedelta(seconds=window_seconds)

        self._prune_before(
            key=key,
            cutoff=cutoff,
        )

        return self.count(key)

    def count(self, key: KeyT) -> int:
        return len(
            self._windows.get(
                key,
                (),
            )
        )

    def entries(
        self,
        key: KeyT,
    ) -> tuple[WindowEntry[ValueT], ...]:
        return tuple(
            self._windows.get(
                key,
                (),
            )
        )

    def values(
        self,
        key: KeyT,
    ) -> tuple[ValueT, ...]:
        return tuple(entry.value for entry in self.entries(key))

    def clear_key(self, key: KeyT) -> None:
        self._windows.pop(key, None)
        self._watermarks.pop(key, None)

    def clear(self) -> None:
        self._windows.clear()
        self._watermarks.clear()

    def _prune_before(
        self,
        *,
        key: KeyT,
        cutoff: datetime,
    ) -> None:
        window = self._windows.get(key)

        if window is None:
            return

        while window and window[0].observed_at < cutoff:
            window.popleft()

        if not window:
            self.clear_key(key)
