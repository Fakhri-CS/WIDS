"""Tests for capture-to-detection runtime integration."""

from __future__ import annotations

from typing import cast
from uuid import UUID, uuid4

import pytest

from wids.capture.feature_extractor import FeatureUpdate
from wids.capture.frame_models import NormalizedWirelessFrame
from wids.contracts.detection_event import DetectionEvent
from wids.detection.runtime import DetectionFeatureSink


class FakeDetectionEngine:
    """Runtime-compatible detection-engine fake."""

    def __init__(
        self,
        events: tuple[DetectionEvent, ...] = (),
    ) -> None:
        self.events = events

        self.evaluated_frames: list[NormalizedWirelessFrame] = []

        self.reset_sessions: list[UUID] = []

    def evaluate(
        self,
        frame: NormalizedWirelessFrame,
    ) -> tuple[DetectionEvent, ...]:
        self.evaluated_frames.append(frame)

        return self.events

    def reset_session(
        self,
        capture_session_id: UUID,
    ) -> None:
        self.reset_sessions.append(capture_session_id)


def test_runtime_sink_evaluates_frame() -> None:
    frame = cast(
        NormalizedWirelessFrame,
        object(),
    )

    update = cast(
        FeatureUpdate,
        object(),
    )

    engine = FakeDetectionEngine()

    received_events: list[DetectionEvent] = []

    runtime_sink = DetectionFeatureSink(
        engine,
        received_events.append,
    )

    runtime_sink(frame, update)

    assert engine.evaluated_frames == [frame]

    assert received_events == []


def test_runtime_sink_publishes_all_events() -> None:
    frame = cast(
        NormalizedWirelessFrame,
        object(),
    )

    update = cast(
        FeatureUpdate,
        object(),
    )

    first_event = cast(
        DetectionEvent,
        object(),
    )

    second_event = cast(
        DetectionEvent,
        object(),
    )

    engine = FakeDetectionEngine(
        (
            first_event,
            second_event,
        )
    )

    received_events: list[DetectionEvent] = []

    runtime_sink = DetectionFeatureSink(
        engine,
        received_events.append,
    )

    runtime_sink(frame, update)

    assert received_events == [
        first_event,
        second_event,
    ]


def test_runtime_sink_resets_session() -> None:
    engine = FakeDetectionEngine()

    runtime_sink = DetectionFeatureSink(
        engine,
        lambda event: None,
    )

    capture_session_id = uuid4()

    runtime_sink.reset_session(capture_session_id)

    assert engine.reset_sessions == [capture_session_id]


def test_event_sink_error_is_propagated() -> None:
    frame = cast(
        NormalizedWirelessFrame,
        object(),
    )

    update = cast(
        FeatureUpdate,
        object(),
    )

    event = cast(
        DetectionEvent,
        object(),
    )

    engine = FakeDetectionEngine((event,))

    def failing_sink(
        emitted_event: DetectionEvent,
    ) -> None:
        del emitted_event

        raise RuntimeError("event persistence failed")

    runtime_sink = DetectionFeatureSink(
        engine,
        failing_sink,
    )

    with pytest.raises(
        RuntimeError,
        match="event persistence failed",
    ):
        runtime_sink(frame, update)
