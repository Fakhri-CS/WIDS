"""Stateful orchestration of source, parser, and feature extraction."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from threading import Event, RLock
from typing import Protocol
from uuid import UUID

from wids.capture.feature_extractor import FeatureExtractor, FeatureUpdate
from wids.capture.frame_models import (
    CaptureSource,
    CaptureState,
    CaptureStatus,
    NormalizedWirelessFrame,
    ParserDisposition,
    ensure_utc,
)
from wids.capture.packet_parser import PacketParser
from wids.capture.packet_source import PacketSource


class CaptureManagerError(RuntimeError):
    """Raised for invalid capture-manager lifecycle operations."""


class FrameSink(Protocol):
    """Consumes one validated normalized frame."""

    def __call__(self, frame: NormalizedWirelessFrame) -> None:
        """Persist or forward a normalized frame."""


class FeatureSink(Protocol):
    """Consumes feature snapshots calculated for one frame."""

    def __call__(
        self,
        frame: NormalizedWirelessFrame,
        update: FeatureUpdate,
    ) -> None:
        """Forward features to the Phase 3 detection engine."""


ProcessingErrorHandler = Callable[[Exception, int], None]


class CaptureManager:
    """Run the storage-neutral Phase 2 packet-processing pipeline."""

    def __init__(
        self,
        parser: PacketParser,
        feature_extractor: FeatureExtractor,
        *,
        frame_sink: FrameSink | None = None,
        feature_sink: FeatureSink | None = None,
        on_processing_error: ProcessingErrorHandler | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._parser = parser
        self._feature_extractor = feature_extractor
        self._frame_sink = frame_sink
        self._feature_sink = feature_sink
        self._on_processing_error = on_processing_error
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._stop_event = Event()
        self._lock = RLock()
        self._source: PacketSource | None = None
        self._state = CaptureState.IDLE
        self._source_mode: CaptureSource | None = None
        self._session_id: UUID | None = None
        self._interface: str | None = None
        self._current_channel: int | None = None
        self._started_at: datetime | None = None
        self._heartbeat_at: datetime | None = None
        self._completed_at: datetime | None = None
        self._packets_seen = 0
        self._packets_parsed = 0
        self._packets_skipped = 0
        self._parse_errors = 0
        self._dropped_packets = 0
        self._last_error: str | None = None
        self._reason_counts: Counter[str] = Counter()
        self._seen_packets: set[tuple[UUID, int]] = set()

    def run(self, source: PacketSource) -> CaptureStatus:
        """Process a source synchronously until exhaustion or ``stop``."""

        self._begin(source)
        try:
            with self._lock:
                self._state = CaptureState.RUNNING
            for envelope in source.packets(self._stop_event):
                if self._stop_event.is_set():
                    break
                self._touch_heartbeat()
                with self._lock:
                    self._packets_seen += 1

                packet_key = (
                    envelope.capture_session_id,
                    envelope.packet_number,
                )
                with self._lock:
                    duplicate = packet_key in self._seen_packets
                    self._seen_packets.add(packet_key)
                if duplicate:
                    self._record_skip("duplicate_packet_number", parse_error=True)
                    continue

                result = self._parser.parse(envelope)
                if result.disposition is ParserDisposition.IGNORED:
                    self._record_skip(
                        result.reason.value if result.reason else "ignored"
                    )
                    continue
                if result.disposition is ParserDisposition.REJECTED:
                    self._record_skip(
                        result.reason.value if result.reason else "rejected",
                        parse_error=True,
                    )
                    continue

                frame = result.frame
                if frame is None:
                    self._record_skip("parser_contract_error", parse_error=True)
                    continue
                try:
                    if self._frame_sink is not None:
                        self._frame_sink(frame)
                    update = self._feature_extractor.ingest(frame)
                    if self._feature_sink is not None:
                        self._feature_sink(frame, update)
                except Exception as error:  # noqa: BLE001 - packet boundary
                    self._record_skip("processing_error", parse_error=True)
                    with self._lock:
                        self._last_error = (
                            f"Packet {envelope.packet_number}: "
                            f"{type(error).__name__}"
                        )
                    if self._on_processing_error is not None:
                        self._on_processing_error(
                            error,
                            envelope.packet_number,
                        )
                    continue

                with self._lock:
                    self._packets_parsed += 1

            with self._lock:
                self._state = CaptureState.STOPPED
        except Exception as error:  # noqa: BLE001 - source/worker boundary
            if self._stop_event.is_set():
                with self._lock:
                    self._state = CaptureState.STOPPED
            else:
                with self._lock:
                    self._state = CaptureState.FAILED
                    self._last_error = f"{type(error).__name__}: {error}"
                raise
        finally:
            try:
                source.close()
            finally:
                with self._lock:
                    source_drops = getattr(source, "dropped_packets", 0)
                    if isinstance(source_drops, int) and source_drops >= 0:
                        self._dropped_packets = source_drops
                    self._completed_at = ensure_utc(self._clock())
                    self._heartbeat_at = self._completed_at
                    self._source = None
        return self.status()

    def stop(self) -> None:
        """Request capture termination and close a blocking live source."""

        with self._lock:
            if self._state not in {
                CaptureState.STARTING,
                CaptureState.RUNNING,
            }:
                return
            self._state = CaptureState.STOPPING
            source = self._source
            self._stop_event.set()
        if source is not None:
            source.close()

    def update_current_channel(self, channel: int | None) -> None:
        """Update actual channel state after a fixed/hopping operation."""

        if channel is not None and not 1 <= channel <= 233:
            raise ValueError("channel must be between 1 and 233")
        with self._lock:
            self._current_channel = channel

    def touch_heartbeat(self, at: datetime | None = None) -> CaptureStatus:
        """Update heartbeat time and return a consistent status snapshot."""

        self._touch_heartbeat(at)
        return self.status()

    def status(self) -> CaptureStatus:
        """Return a thread-safe immutable status snapshot."""

        with self._lock:
            return CaptureStatus(
                state=self._state,
                source_mode=self._source_mode,
                capture_session_id=self._session_id,
                interface=self._interface,
                current_channel=self._current_channel,
                started_at=self._started_at,
                heartbeat_at=self._heartbeat_at,
                completed_at=self._completed_at,
                packets_seen=self._packets_seen,
                packets_parsed=self._packets_parsed,
                packets_skipped=self._packets_skipped,
                parse_errors=self._parse_errors,
                dropped_packets=self._dropped_packets,
                last_error=self._last_error,
                reason_counts=dict(self._reason_counts),
            )

    def _begin(self, source: PacketSource) -> None:
        with self._lock:
            if self._state in {
                CaptureState.STARTING,
                CaptureState.RUNNING,
                CaptureState.STOPPING,
            }:
                raise CaptureManagerError("A capture session is already active")
            self._state = CaptureState.STARTING
            self._source = source
            self._source_mode = source.capture_source
            self._session_id = source.capture_session_id
            self._interface = source.interface_name
            self._started_at = ensure_utc(self._clock())
            self._heartbeat_at = self._started_at
            self._completed_at = None
            self._packets_seen = 0
            self._packets_parsed = 0
            self._packets_skipped = 0
            self._parse_errors = 0
            self._dropped_packets = 0
            self._last_error = None
            self._reason_counts.clear()
            self._seen_packets.clear()
            self._feature_extractor.reset()
            self._stop_event.clear()

    def _record_skip(self, reason: str, *, parse_error: bool = False) -> None:
        with self._lock:
            self._packets_skipped += 1
            if parse_error:
                self._parse_errors += 1
            self._reason_counts[reason] += 1

    def _touch_heartbeat(self, at: datetime | None = None) -> None:
        timestamp = ensure_utc(at or self._clock())
        with self._lock:
            self._heartbeat_at = timestamp
