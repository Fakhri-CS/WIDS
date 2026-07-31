"""Runtime bridge between capture processing and detection rules."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from wids.capture.feature_extractor import FeatureUpdate
from wids.capture.frame_models import NormalizedWirelessFrame
from wids.contracts.detection_event import DetectionEvent


class DetectionEngineRuntime(Protocol):
    """Minimum detection-engine interface required at runtime."""

    def evaluate(
        self,
        frame: NormalizedWirelessFrame,
    ) -> tuple[DetectionEvent, ...]:
        """Evaluate one normalized wireless frame."""
        ...

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Remove state associated with one capture session."""
        ...


class DetectionEventSink(Protocol):
    """Consumes one immutable detection event."""

    def __call__(
        self,
        event: DetectionEvent,
    ) -> None:
        """Persist, publish, or forward one event."""
        ...


class DetectionFeatureSink:
    """Connect CaptureManager feature output to DetectionEngine.

    CaptureManager supplies a normalized frame and a FeatureUpdate.
    The current five detection rules evaluate the normalized frame
    directly and maintain their own windows, retry deduplication, and
    cooldown state. Therefore FeatureUpdate is intentionally ignored.
    """

    def __init__(
        self,
        engine: DetectionEngineRuntime,
        event_sink: DetectionEventSink,
    ) -> None:
        self._engine = engine
        self._event_sink = event_sink

    def __call__(
        self,
        frame: NormalizedWirelessFrame,
        update: FeatureUpdate,
    ) -> None:
        """Evaluate one frame and forward every generated event."""

        del update

        events = self._engine.evaluate(frame)

        for event in events:
            self._event_sink(event)

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        """Reset detection state after a capture session ends."""

        self._engine.reset_session(capture_session_id)
