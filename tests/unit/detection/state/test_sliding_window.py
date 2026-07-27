from datetime import UTC, datetime, timedelta

import pytest

from wids.detection.state.sliding_window import (
    SlidingWindowStore,
)


def test_sliding_window_counts_active_values() -> None:
    store = SlidingWindowStore[str, str]()
    started_at = datetime(
        2026,
        7,
        27,
        12,
        0,
        tzinfo=UTC,
    )

    first_count = store.add(
        key="source-a",
        observed_at=started_at,
        value="frame-1",
        window_seconds=10,
    )

    second_count = store.add(
        key="source-a",
        observed_at=started_at + timedelta(seconds=5),
        value="frame-2",
        window_seconds=10,
    )

    assert first_count == 1
    assert second_count == 2
    assert store.values("source-a") == (
        "frame-1",
        "frame-2",
    )


def test_sliding_window_removes_expired_values() -> None:
    store = SlidingWindowStore[str, str]()
    started_at = datetime.now(UTC)

    store.add(
        key="source-a",
        observed_at=started_at,
        value="frame-1",
        window_seconds=10,
    )

    count = store.add(
        key="source-a",
        observed_at=started_at + timedelta(seconds=11),
        value="frame-2",
        window_seconds=10,
    )

    assert count == 1
    assert store.values("source-a") == ("frame-2",)


def test_sliding_window_keeps_different_keys_separate() -> None:
    store = SlidingWindowStore[str, str]()
    observed_at = datetime.now(UTC)

    store.add(
        key="source-a",
        observed_at=observed_at,
        value="frame-a",
        window_seconds=10,
    )

    store.add(
        key="source-b",
        observed_at=observed_at,
        value="frame-b",
        window_seconds=10,
    )

    assert store.count("source-a") == 1
    assert store.count("source-b") == 1
    assert store.active_key_count == 2


def test_sliding_window_orders_late_values_by_timestamp() -> None:
    store = SlidingWindowStore[str, str]()
    started_at = datetime.now(UTC)

    store.add(
        key="source-a",
        observed_at=started_at + timedelta(seconds=10),
        value="later-frame",
        window_seconds=20,
    )

    store.add(
        key="source-a",
        observed_at=started_at + timedelta(seconds=5),
        value="earlier-frame",
        window_seconds=20,
    )

    assert store.values("source-a") == (
        "earlier-frame",
        "later-frame",
    )


def test_sliding_window_rejects_naive_datetime() -> None:
    store = SlidingWindowStore[str, str]()

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        store.add(
            key="source-a",
            observed_at=datetime(2026, 7, 27, 12, 0),
            value="frame",
            window_seconds=10,
        )
