from datetime import UTC, datetime, timedelta
from uuid import uuid4

from wids.detection.state.retry_deduplicator import (
    RetryDeduplicator,
    RetryFrameKey,
)


def create_key(
    *,
    capture_session_id=None,
    fragment_number: int = 0,
) -> RetryFrameKey:
    return RetryFrameKey(
        capture_session_id=(capture_session_id if capture_session_id is not None else uuid4()),
        transmitter_mac="AA:BB:CC:DD:EE:FF",
        frame_subtype="deauthentication",
        sequence_number=100,
        fragment_number=fragment_number,
    )


def test_first_frame_is_not_duplicate() -> None:
    deduplicator = RetryDeduplicator()
    key = create_key()

    duplicate = deduplicator.check_and_record(
        key=key,
        observed_at=datetime.now(UTC),
        is_retry=False,
    )

    assert duplicate is False


def test_retry_of_seen_frame_is_duplicate() -> None:
    deduplicator = RetryDeduplicator()
    key = create_key()
    observed_at = datetime.now(UTC)

    deduplicator.check_and_record(
        key=key,
        observed_at=observed_at,
        is_retry=False,
    )

    duplicate = deduplicator.check_and_record(
        key=key,
        observed_at=observed_at + timedelta(seconds=1),
        is_retry=True,
    )

    assert duplicate is True


def test_different_fragment_is_not_duplicate() -> None:
    deduplicator = RetryDeduplicator()
    session_id = uuid4()
    observed_at = datetime.now(UTC)

    first_key = create_key(
        capture_session_id=session_id,
        fragment_number=0,
    )

    second_key = create_key(
        capture_session_id=session_id,
        fragment_number=1,
    )

    deduplicator.check_and_record(
        key=first_key,
        observed_at=observed_at,
        is_retry=False,
    )

    duplicate = deduplicator.check_and_record(
        key=second_key,
        observed_at=observed_at + timedelta(seconds=1),
        is_retry=True,
    )

    assert duplicate is False


def test_expired_retry_is_not_duplicate() -> None:
    deduplicator = RetryDeduplicator(
        retention_seconds=5,
    )

    key = create_key()
    observed_at = datetime.now(UTC)

    deduplicator.check_and_record(
        key=key,
        observed_at=observed_at,
        is_retry=False,
    )

    duplicate = deduplicator.check_and_record(
        key=key,
        observed_at=observed_at + timedelta(seconds=6),
        is_retry=True,
    )

    assert duplicate is False


def test_clear_session_removes_matching_entries() -> None:
    deduplicator = RetryDeduplicator()
    first_session_id = uuid4()
    second_session_id = uuid4()
    observed_at = datetime.now(UTC)

    deduplicator.check_and_record(
        key=create_key(capture_session_id=first_session_id),
        observed_at=observed_at,
        is_retry=False,
    )

    deduplicator.check_and_record(
        key=create_key(capture_session_id=second_session_id),
        observed_at=observed_at,
        is_retry=False,
    )

    deduplicator.clear_session(first_session_id)

    assert deduplicator.size == 1
