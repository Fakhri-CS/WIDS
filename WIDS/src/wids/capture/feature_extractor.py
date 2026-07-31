"""Configurable sliding-window features for all Version 1 rules."""

from __future__ import annotations

import math
from collections import Counter, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from types import MappingProxyType
from uuid import UUID

from wids.capture.frame_models import (
    NormalizedWirelessFrame,
    datetime_to_rfc3339,
    ensure_utc,
)

type RetryIdentity = tuple[UUID, str, str, int, int]
type GroupKey = RetryIdentity | tuple[str, UUID]
type SsidBssidKey = tuple[str, str]


@dataclass(frozen=True, slots=True)
class FeatureSnapshot:
    """Immutable features for one configured time window."""

    window_seconds: float
    observed_through: datetime
    frame_count: int
    subtype_counts: Mapping[str, int]
    transmitter_counts: Mapping[str, int]
    receiver_counts: Mapping[str, int]
    destination_counts: Mapping[str, int]
    bssid_counts: Mapping[str, int]
    ssid_bssid_counts: Mapping[SsidBssidKey, int]
    channels_by_bssid: Mapping[str, tuple[int, ...]]
    security_fingerprints_by_bssid: Mapping[str, tuple[str, ...]]
    role_hints_by_transmitter: Mapping[str, tuple[str, ...]]
    first_seen_by_transmitter: Mapping[str, datetime]
    last_seen_by_transmitter: Mapping[str, datetime]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "observed_through",
            ensure_utc(self.observed_through),
        )

        for name in (
            "subtype_counts",
            "transmitter_counts",
            "receiver_counts",
            "destination_counts",
            "bssid_counts",
            "ssid_bssid_counts",
            "channels_by_bssid",
            "security_fingerprints_by_bssid",
            "role_hints_by_transmitter",
            "first_seen_by_transmitter",
            "last_seen_by_transmitter",
        ):
            object.__setattr__(
                self,
                name,
                MappingProxyType(dict(getattr(self, name))),
            )

    def subtype_count(self, subtype: str) -> int:
        """Return a subtype count without inventing missing values."""
        return self.subtype_counts.get(subtype, 0)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible snapshot for diagnostics/persistence."""
        return {
            "window_seconds": self.window_seconds,
            "observed_through": datetime_to_rfc3339(self.observed_through),
            "frame_count": self.frame_count,
            "subtype_counts": dict(self.subtype_counts),
            "transmitter_counts": dict(self.transmitter_counts),
            "receiver_counts": dict(self.receiver_counts),
            "destination_counts": dict(self.destination_counts),
            "bssid_counts": dict(self.bssid_counts),
            "ssid_bssid_counts": [
                {
                    "ssid_hex": ssid_hex,
                    "bssid": bssid,
                    "count": count,
                }
                for (ssid_hex, bssid), count in sorted(self.ssid_bssid_counts.items())
            ],
            "channels_by_bssid": {
                key: list(value) for key, value in self.channels_by_bssid.items()
            },
            "security_fingerprints_by_bssid": {
                key: list(value) for key, value in (self.security_fingerprints_by_bssid.items())
            },
            "role_hints_by_transmitter": {
                key: list(value) for key, value in (self.role_hints_by_transmitter.items())
            },
            "first_seen_by_transmitter": {
                key: datetime_to_rfc3339(value)
                for key, value in (self.first_seen_by_transmitter.items())
            },
            "last_seen_by_transmitter": {
                key: datetime_to_rfc3339(value)
                for key, value in (self.last_seen_by_transmitter.items())
            },
        }


@dataclass(frozen=True, slots=True)
class FeatureUpdate:
    """Result of adding one frame to all configured windows."""

    frame_id: UUID
    retry_deduplicated: bool
    snapshots: Mapping[float, FeatureSnapshot]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "snapshots",
            MappingProxyType(dict(self.snapshots)),
        )


@dataclass(slots=True)
class _WindowEntry:
    observed_at: datetime
    group_key: GroupKey


@dataclass(slots=True)
class _FrameGroup:
    frame: NormalizedWirelessFrame
    occurrences: int = 1


@dataclass(slots=True)
class _WindowState:
    seconds: float

    entries: deque[_WindowEntry] = field(default_factory=deque)

    groups: dict[GroupKey, _FrameGroup] = field(default_factory=dict)

    subtype_counts: Counter[str] = field(default_factory=Counter)

    transmitter_counts: Counter[str] = field(default_factory=Counter)

    receiver_counts: Counter[str] = field(default_factory=Counter)

    destination_counts: Counter[str] = field(default_factory=Counter)

    bssid_counts: Counter[str] = field(default_factory=Counter)

    ssid_bssid_counts: Counter[SsidBssidKey] = field(default_factory=Counter)

    def add(self, frame: NormalizedWirelessFrame) -> bool:
        """Add one frame and report duplicate-retry suppression."""
        group_key = _group_key(frame)
        existing = self.groups.get(group_key)

        deduplicated = existing is not None

        if existing is None:
            self.groups[group_key] = _FrameGroup(frame=frame)
            self._increment(frame)
        else:
            existing.occurrences += 1

        self.entries.append(
            _WindowEntry(
                observed_at=frame.observed_at,
                group_key=group_key,
            )
        )

        return deduplicated and frame.flags.retry

    def expire(self, observed_through: datetime) -> None:
        """Remove entries older than this state's time window."""
        cutoff = observed_through - timedelta(seconds=self.seconds)

        while self.entries and self.entries[0].observed_at < cutoff:
            entry = self.entries.popleft()
            group = self.groups[entry.group_key]

            group.occurrences -= 1

            if group.occurrences == 0:
                self._decrement(group.frame)
                del self.groups[entry.group_key]

    def snapshot(
        self,
        observed_through: datetime,
    ) -> FeatureSnapshot:
        """Create an immutable snapshot of the current window."""
        channels: dict[str, set[int]] = {}
        security: dict[str, set[str]] = {}
        roles: dict[str, set[str]] = {}

        first_seen: dict[str, datetime] = {}
        last_seen: dict[str, datetime] = {}

        for group in self.groups.values():
            frame = group.frame

            transmitter = frame.addresses.transmitter_mac

            role = frame.addresses.transmitter_role_hint.value

            roles.setdefault(
                transmitter,
                set(),
            ).add(role)

            bssid = frame.addresses.bssid

            channel = (
                frame.management.advertised_channel
                if (frame.management.advertised_channel is not None)
                else frame.radio.channel
            )

            if bssid is not None and channel is not None:
                channels.setdefault(
                    bssid,
                    set(),
                ).add(channel)

            profile = frame.management.security

            if bssid is not None and profile is not None:
                security.setdefault(
                    bssid,
                    set(),
                ).add(profile.fingerprint_sha256)

        # Retries remain useful for observation timing even
        # though they do not inflate traffic-rate counters.
        for entry in self.entries:
            frame = self.groups[entry.group_key].frame

            transmitter = frame.addresses.transmitter_mac

            timestamp = entry.observed_at

            first_seen[transmitter] = min(
                first_seen.get(
                    transmitter,
                    timestamp,
                ),
                timestamp,
            )

            last_seen[transmitter] = max(
                last_seen.get(
                    transmitter,
                    timestamp,
                ),
                timestamp,
            )

        return FeatureSnapshot(
            window_seconds=self.seconds,
            observed_through=observed_through,
            frame_count=sum(self.subtype_counts.values()),
            subtype_counts=_positive_counts(self.subtype_counts),
            transmitter_counts=_positive_counts(self.transmitter_counts),
            receiver_counts=_positive_counts(self.receiver_counts),
            destination_counts=_positive_counts(self.destination_counts),
            bssid_counts=_positive_counts(self.bssid_counts),
            ssid_bssid_counts=_positive_counts(self.ssid_bssid_counts),
            channels_by_bssid={key: tuple(sorted(values)) for key, values in channels.items()},
            security_fingerprints_by_bssid={
                key: tuple(sorted(values)) for key, values in security.items()
            },
            role_hints_by_transmitter={key: tuple(sorted(values)) for key, values in roles.items()},
            first_seen_by_transmitter=first_seen,
            last_seen_by_transmitter=last_seen,
        )

    def _increment(
        self,
        frame: NormalizedWirelessFrame,
    ) -> None:
        """Increment counters for one unique frame group."""
        self.subtype_counts[frame.frame_subtype.value] += 1

        self.transmitter_counts[frame.addresses.transmitter_mac] += 1

        self.receiver_counts[frame.addresses.receiver_mac] += 1

        if frame.addresses.destination_mac is not None:
            self.destination_counts[frame.addresses.destination_mac] += 1

        if frame.addresses.bssid is not None:
            self.bssid_counts[frame.addresses.bssid] += 1

        if frame.management.ssid_hex is not None and frame.addresses.bssid is not None:
            self.ssid_bssid_counts[
                (
                    frame.management.ssid_hex,
                    frame.addresses.bssid,
                )
            ] += 1

    def _decrement(
        self,
        frame: NormalizedWirelessFrame,
    ) -> None:
        """Decrement counters when one frame group expires."""
        self.subtype_counts[frame.frame_subtype.value] -= 1

        self.transmitter_counts[frame.addresses.transmitter_mac] -= 1

        self.receiver_counts[frame.addresses.receiver_mac] -= 1

        if frame.addresses.destination_mac is not None:
            self.destination_counts[frame.addresses.destination_mac] -= 1

        if frame.addresses.bssid is not None:
            self.bssid_counts[frame.addresses.bssid] -= 1

        if frame.management.ssid_hex is not None and frame.addresses.bssid is not None:
            self.ssid_bssid_counts[
                (
                    frame.management.ssid_hex,
                    frame.addresses.bssid,
                )
            ] -= 1


class FeatureExtractor:
    """Maintain one or more caller-configured sliding windows."""

    def __init__(
        self,
        window_seconds: Iterable[float],
    ) -> None:
        windows = tuple(sorted({float(value) for value in window_seconds}))

        if not windows:
            raise ValueError("At least one feature window is required")

        if any(not math.isfinite(value) or value <= 0 for value in windows):
            raise ValueError("Feature windows must be finite and positive")

        self._states = {seconds: _WindowState(seconds=seconds) for seconds in windows}

        self._observed_through: datetime | None = None
        self._lock = RLock()

    @property
    def configured_windows(self) -> tuple[float, ...]:
        """Return configured window lengths."""
        return tuple(self._states)

    def ingest(
        self,
        frame: NormalizedWirelessFrame,
    ) -> FeatureUpdate:
        """Add a frame and return updated snapshots.

        Sources must emit chronological packets. Rejecting an
        out-of-order frame prevents a late packet from corrupting
        rate windows.
        """
        observed_at = ensure_utc(frame.observed_at)

        with self._lock:
            if self._observed_through is not None and observed_at < self._observed_through:
                raise ValueError("FeatureExtractor requires nondecreasing observed_at values")

            self._observed_through = observed_at

            retry_deduplicated = False
            snapshots: dict[
                float,
                FeatureSnapshot,
            ] = {}

            for seconds, state in self._states.items():
                state.expire(observed_at)

                retry_deduplicated = state.add(frame) or retry_deduplicated

                snapshots[seconds] = state.snapshot(observed_at)

            return FeatureUpdate(
                frame_id=frame.frame_id,
                retry_deduplicated=(retry_deduplicated),
                snapshots=snapshots,
            )

    def snapshots(
        self,
        *,
        observed_through: datetime | None = None,
    ) -> Mapping[float, FeatureSnapshot]:
        """Read features, optionally advancing expiry time."""
        with self._lock:
            current = observed_through or self._observed_through

            if current is None:
                return MappingProxyType({})

            current = ensure_utc(current)

            if self._observed_through is not None and current < self._observed_through:
                raise ValueError("observed_through cannot move backwards")

            self._observed_through = current

            snapshots: dict[
                float,
                FeatureSnapshot,
            ] = {}

            for seconds, state in self._states.items():
                state.expire(current)

                snapshots[seconds] = state.snapshot(current)

            return MappingProxyType(snapshots)

    def reset(self) -> None:
        """Clear every configured feature window."""
        with self._lock:
            self._states = {seconds: _WindowState(seconds=seconds) for seconds in self._states}

            self._observed_through = None


def _retry_identity(
    frame: NormalizedWirelessFrame,
) -> RetryIdentity | None:
    """Build the identity used to deduplicate retry frames."""
    sequence = frame.sequence.sequence_number
    fragment = frame.sequence.fragment_number

    if sequence is None or fragment is None:
        return None

    return (
        frame.capture_session_id,
        frame.addresses.transmitter_mac,
        frame.frame_subtype.value,
        sequence,
        fragment,
    )


def _group_key(
    frame: NormalizedWirelessFrame,
) -> GroupKey:
    """Build a stable key for one logical frame group."""
    retry_identity = _retry_identity(frame)

    if retry_identity is not None:
        return retry_identity

    return (
        "frame",
        frame.frame_id,
    )


def _positive_counts[CountKey](
    counter: Counter[CountKey],
) -> dict[CountKey, int]:
    """Return only counters whose values remain positive."""
    return {key: value for key, value in counter.items() if value > 0}
