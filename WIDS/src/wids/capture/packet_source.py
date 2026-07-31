"""Packet sources shared by live capture and deterministic PCAP replay."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock
from typing import Any, Protocol
from uuid import UUID, uuid4

from wids.capture.frame_models import CaptureSource


class PacketSourceError(RuntimeError):
    """Raised when a capture source cannot be opened or read."""


@dataclass(frozen=True, slots=True)
class PacketEnvelope:
    """A source packet plus stable metadata required by the parser."""

    packet: Any
    capture_session_id: UUID
    capture_source: CaptureSource
    interface_name: str | None
    packet_number: int
    pcap_reference: str

    def __post_init__(self) -> None:
        if self.packet_number < 1:
            raise ValueError("packet_number must be one-based")
        reference = _normalize_reference(self.pcap_reference)
        object.__setattr__(self, "pcap_reference", reference)


class PacketSource(Protocol):
    """Common interface implemented by every packet source."""

    @property
    def capture_session_id(self) -> UUID:
        """Return the stable capture-session identifier."""
        ...

    @property
    def capture_source(self) -> CaptureSource:
        """Return whether this is live capture or PCAP replay."""
        ...

    @property
    def interface_name(self) -> str | None:
        """Return the live interface, when applicable."""
        ...

    @property
    def pcap_reference(self) -> str:
        """Return the opaque evidence-PCAP reference."""
        ...

    def packets(
        self,
        stop_event: Event | None = None,
    ) -> Iterator[PacketEnvelope]:
        """Yield captured packets until exhausted or stopped."""
        ...

    def close(self) -> None:
        """Release TShark/PyShark resources."""
        ...


CaptureFactory = Callable[..., Any]


class PcapPacketSource:
    """Replay packets from an existing PCAP/PCAPNG file via PyShark."""

    capture_source = CaptureSource.PCAP
    interface_name = None

    def __init__(
        self,
        path: str | Path,
        *,
        pcap_reference: str | None = None,
        capture_session_id: UUID | None = None,
        display_filter: str | None = None,
        capture_factory: CaptureFactory | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        if not self.path.is_file():
            raise FileNotFoundError(f"PCAP file does not exist: {self.path}")
        self.pcap_reference = _normalize_reference(
            pcap_reference or _default_replay_reference(self.path)
        )
        self.capture_session_id = capture_session_id or uuid4()
        self.display_filter = display_filter
        self._capture_factory = capture_factory or _file_capture_factory
        self._capture: Any | None = None
        self._lock = Lock()

    def __iter__(self) -> Iterator[PacketEnvelope]:
        return self.packets()

    def packets(self, stop_event: Event | None = None) -> Iterator[PacketEnvelope]:
        capture: Any | None = None
        try:
            kwargs: dict[str, Any] = {"keep_packets": False}
            if self.display_filter:
                kwargs["display_filter"] = self.display_filter
            capture = self._capture_factory(str(self.path), **kwargs)
            with self._lock:
                self._capture = capture

            for packet_number, packet in enumerate(capture, start=1):
                if stop_event is not None and stop_event.is_set():
                    break
                yield PacketEnvelope(
                    packet=packet,
                    capture_session_id=self.capture_session_id,
                    capture_source=self.capture_source,
                    interface_name=None,
                    packet_number=packet_number,
                    pcap_reference=self.pcap_reference,
                )
        except (OSError, RuntimeError) as error:
            raise PacketSourceError(f"Unable to replay PCAP {self.path.name}: {error}") from error
        finally:
            self._close_capture(capture)

    def close(self) -> None:
        with self._lock:
            capture = self._capture
        self._close_capture(capture)

    def _close_capture(self, capture: Any | None) -> None:
        if capture is None:
            return
        try:
            capture.close()
        except (AttributeError, RuntimeError):
            pass
        finally:
            with self._lock:
                if self._capture is capture:
                    self._capture = None


class LivePacketSource:
    """Capture packets from a monitor-mode interface via PyShark."""

    capture_source = CaptureSource.LIVE

    def __init__(
        self,
        interface_name: str,
        *,
        output_file: str | Path,
        pcap_reference: str,
        capture_session_id: UUID | None = None,
        display_filter: str | None = None,
        bpf_filter: str | None = None,
        capture_factory: CaptureFactory | None = None,
    ) -> None:
        if not interface_name or not interface_name.strip():
            raise ValueError("interface_name is required for live capture")
        self.interface_name = interface_name.strip()
        self.output_file = Path(output_file)
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.pcap_reference = _normalize_reference(pcap_reference)
        self.capture_session_id = capture_session_id or uuid4()
        self.display_filter = display_filter
        self.bpf_filter = bpf_filter
        self._capture_factory = capture_factory or _live_capture_factory
        self._capture: Any | None = None
        self._lock = Lock()

    def __iter__(self) -> Iterator[PacketEnvelope]:
        return self.packets()

    def packets(self, stop_event: Event | None = None) -> Iterator[PacketEnvelope]:
        capture: Any | None = None
        try:
            kwargs: dict[str, Any] = {
                "interface": self.interface_name,
                "output_file": str(self.output_file),
            }
            if self.display_filter:
                kwargs["display_filter"] = self.display_filter
            if self.bpf_filter:
                kwargs["bpf_filter"] = self.bpf_filter
            capture = self._capture_factory(**kwargs)
            with self._lock:
                self._capture = capture

            packet_stream = capture.sniff_continuously()
            for packet_number, packet in enumerate(packet_stream, start=1):
                if stop_event is not None and stop_event.is_set():
                    break
                yield PacketEnvelope(
                    packet=packet,
                    capture_session_id=self.capture_session_id,
                    capture_source=self.capture_source,
                    interface_name=self.interface_name,
                    packet_number=packet_number,
                    pcap_reference=self.pcap_reference,
                )
        except (OSError, RuntimeError) as error:
            if stop_event is None or not stop_event.is_set():
                raise PacketSourceError(
                    f"Unable to capture from {self.interface_name}: {error}"
                ) from error
        finally:
            self._close_capture(capture)

    def close(self) -> None:
        with self._lock:
            capture = self._capture
        self._close_capture(capture)

    def _close_capture(self, capture: Any | None) -> None:
        if capture is None:
            return
        try:
            capture.close()
        except (AttributeError, RuntimeError):
            pass
        finally:
            with self._lock:
                if self._capture is capture:
                    self._capture = None


class InMemoryPacketSource:
    """Deterministic source used by unit tests and synthetic scenarios."""

    def __init__(
        self,
        packets: Iterable[Any],
        *,
        capture_source: CaptureSource = CaptureSource.PCAP,
        interface_name: str | None = None,
        pcap_reference: str = "pcap_samples/in_memory.pcap",
        capture_session_id: UUID | None = None,
    ) -> None:
        self._packets = packets
        self.capture_source = capture_source
        self.interface_name = interface_name
        self.pcap_reference = _normalize_reference(pcap_reference)
        self.capture_session_id = capture_session_id or uuid4()
        self.closed = False

    def __iter__(self) -> Iterator[PacketEnvelope]:
        return self.packets()

    def packets(self, stop_event: Event | None = None) -> Iterator[PacketEnvelope]:
        for packet_number, packet in enumerate(self._packets, start=1):
            if stop_event is not None and stop_event.is_set():
                break
            yield PacketEnvelope(
                packet=packet,
                capture_session_id=self.capture_session_id,
                capture_source=self.capture_source,
                interface_name=self.interface_name,
                packet_number=packet_number,
                pcap_reference=self.pcap_reference,
            )

    def close(self) -> None:
        self.closed = True


def _file_capture_factory(path: str, **kwargs: Any) -> Any:
    pyshark = _load_pyshark()
    return pyshark.FileCapture(path, **kwargs)


def _live_capture_factory(**kwargs: Any) -> Any:
    pyshark = _load_pyshark()
    return pyshark.LiveCapture(**kwargs)


def _load_pyshark() -> Any:
    try:
        return importlib.import_module("pyshark")
    except ModuleNotFoundError as error:
        raise PacketSourceError(
            "PyShark is not installed. Install the Python package and TShark."
        ) from error


def _default_replay_reference(path: Path) -> str:
    if not path.is_absolute():
        return path.as_posix()
    if path.parent.name == "pcap_samples":
        return f"pcap_samples/{path.name}"
    return f"pcap/{path.name}"


def _normalize_reference(reference: str) -> str:
    normalized = str(reference).strip().replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        raise ValueError("pcap_reference must be a non-empty relative reference")
    if any(part == ".." for part in normalized.split("/")):
        raise ValueError("pcap_reference cannot contain parent traversal")
    return normalized
