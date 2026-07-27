"""Periodic worker-heartbeat publication independent of packet arrival."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Event, Lock, Thread, current_thread
from typing import Protocol

from wids.capture.frame_models import (
    CaptureStatus,
    datetime_to_rfc3339,
    ensure_utc,
)


@dataclass(frozen=True, slots=True)
class HeartbeatRecord:
    """Storage-neutral heartbeat payload."""

    worker_id: str
    emitted_at: datetime
    status: CaptureStatus

    def __post_init__(self) -> None:
        if not self.worker_id.strip():
            raise ValueError("worker_id is required")
        object.__setattr__(self, "emitted_at", ensure_utc(self.emitted_at))

    def to_dict(self) -> dict[str, object]:
        return {
            "worker_id": self.worker_id,
            "emitted_at": datetime_to_rfc3339(self.emitted_at),
            "status": self.status.to_dict(),
        }


class HeartbeatPublisher(Protocol):
    """Persists a heartbeat, normally through a Phase 4 repository."""

    def __call__(self, record: HeartbeatRecord) -> None:
        """Publish one heartbeat record."""


HeartbeatErrorHandler = Callable[[Exception], None]


class HeartbeatService:
    """Publish actual worker state on a fixed background interval."""

    def __init__(
        self,
        *,
        worker_id: str,
        interval_seconds: float,
        status_provider: Callable[[], CaptureStatus],
        publisher: HeartbeatPublisher,
        on_error: HeartbeatErrorHandler | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.worker_id = worker_id.strip()
        self.interval_seconds = float(interval_seconds)
        self._status_provider = status_provider
        self._publisher = publisher
        self._on_error = on_error
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._lock = Lock()

    def start(self) -> None:
        """Start publication and immediately emit the first heartbeat."""

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("Heartbeat service is already running")
            self._stop_event.clear()
            self._thread = Thread(
                target=self._run,
                name="wids-heartbeat",
                daemon=True,
            )
            self._thread.start()

    def stop(
        self,
        *,
        timeout: float | None = None,
        publish_final: bool = True,
    ) -> None:
        """Stop the service and optionally publish final worker state."""

        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not current_thread():
            thread.join(timeout)
        if publish_final:
            self.publish_once()

    def publish_once(self) -> HeartbeatRecord | None:
        """Publish one heartbeat; callback failures never kill the worker."""

        try:
            record = HeartbeatRecord(
                worker_id=self.worker_id,
                emitted_at=ensure_utc(self._clock()),
                status=self._status_provider(),
            )
            self._publisher(record)
            return record
        except Exception as error:  # noqa: BLE001 - external sink boundary
            if self._on_error is not None:
                self._on_error(error)
            return None

    @property
    def running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        self.publish_once()
        while not self._stop_event.wait(self.interval_seconds):
            self.publish_once()


class InMemoryHeartbeatPublisher:
    """Thread-safe heartbeat collector for tests and local development."""

    def __init__(self) -> None:
        self._records: list[HeartbeatRecord] = []
        self._lock = Lock()

    def __call__(self, record: HeartbeatRecord) -> None:
        with self._lock:
            self._records.append(record)

    @property
    def records(self) -> tuple[HeartbeatRecord, ...]:
        with self._lock:
            return tuple(self._records)


def heartbeat_is_stale(
    heartbeat_at: datetime | None,
    *,
    now: datetime | None = None,
    stale_after_seconds: float,
) -> bool:
    """Return whether a heartbeat is absent or older than the limit."""

    if stale_after_seconds <= 0:
        raise ValueError("stale_after_seconds must be positive")
    if heartbeat_at is None:
        return True
    current = ensure_utc(now or datetime.now(timezone.utc))
    return current - ensure_utc(heartbeat_at) > timedelta(
        seconds=stale_after_seconds
    )
