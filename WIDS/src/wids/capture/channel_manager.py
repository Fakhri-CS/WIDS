"""Fixed-channel and controlled channel-hopping support."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
import re
from threading import Event, Lock, Thread, current_thread

from wids.capture.interface_manager import (
    CommandRunner,
    InterfaceManagerError,
    SubprocessCommandRunner,
    validate_interface_name,
)


class ChannelManagerError(RuntimeError):
    """Raised when a channel operation fails."""


class ChannelMode(StrEnum):
    """Supported channel-selection strategies."""

    FIXED = "fixed"
    HOPPING = "hopping"


@dataclass(frozen=True, slots=True)
class ChannelPlan:
    """Validated channel configuration supplied by application settings."""

    channels: tuple[int, ...]
    dwell_seconds: float
    width: str | None = None

    def __post_init__(self) -> None:
        channels = tuple(dict.fromkeys(self.channels))
        if not channels:
            raise ValueError("At least one channel is required")
        for channel in channels:
            validate_channel(channel)
        if self.dwell_seconds <= 0:
            raise ValueError("dwell_seconds must be positive")
        if self.width is not None and self.width not in {
            "HT20",
            "HT40+",
            "HT40-",
            "80MHz",
            "160MHz",
        }:
            raise ValueError("Unsupported channel width")
        object.__setattr__(self, "channels", channels)

    @property
    def mode(self) -> ChannelMode:
        return (
            ChannelMode.FIXED
            if len(self.channels) == 1
            else ChannelMode.HOPPING
        )

    def cycle(self) -> Iterator[int]:
        while True:
            yield from self.channels


class ChannelManager:
    """Changes and reads the channel of one monitor-mode interface."""

    def __init__(
        self,
        interface_name: str,
        runner: CommandRunner | None = None,
    ) -> None:
        self.interface_name = validate_interface_name(interface_name)
        self._runner = runner or SubprocessCommandRunner()

    def set_channel(self, channel: int, width: str | None = None) -> None:
        validate_channel(channel)
        args = [
            "iw",
            "dev",
            self.interface_name,
            "set",
            "channel",
            str(channel),
        ]
        if width:
            args.append(width)
        try:
            self._runner.run(tuple(args))
        except InterfaceManagerError as error:
            raise ChannelManagerError(
                f"Unable to set {self.interface_name} to channel {channel}: {error}"
            ) from error

    def current_channel(self) -> int | None:
        try:
            result = self._runner.run(
                ("iw", "dev", self.interface_name, "info")
            )
        except InterfaceManagerError as error:
            raise ChannelManagerError(
                f"Unable to read channel for {self.interface_name}: {error}"
            ) from error
        match = re.search(r"\bchannel\s+(\d+)\b", result.stdout)
        return int(match.group(1)) if match else None


class ChannelHopper:
    """Background channel hopper controlled by a stop event."""

    def __init__(
        self,
        manager: ChannelManager,
        plan: ChannelPlan,
        *,
        on_channel_changed: Callable[[int], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self._manager = manager
        self._plan = plan
        self._on_channel_changed = on_channel_changed
        self._on_error = on_error
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._lock = Lock()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("Channel hopper is already running")
            self._stop_event.clear()
            self._thread = Thread(
                target=self._run,
                name="wids-channel-hopper",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float | None = None) -> None:
        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not current_thread():
            thread.join(timeout)

    @property
    def running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        try:
            for channel in self._plan.cycle():
                if self._stop_event.is_set():
                    return
                self._manager.set_channel(channel, self._plan.width)
                if self._on_channel_changed is not None:
                    self._on_channel_changed(channel)
                if self._stop_event.wait(self._plan.dwell_seconds):
                    return
        except Exception as error:  # noqa: BLE001 - background boundary
            self._stop_event.set()
            if self._on_error is not None:
                self._on_error(error)


def validate_channel(channel: int) -> int:
    """Validate the contract's channel range."""

    if isinstance(channel, bool) or not 1 <= int(channel) <= 233:
        raise ValueError("channel must be between 1 and 233")
    return int(channel)


def frequency_to_channel(frequency_mhz: int) -> int | None:
    """Convert standard 2.4, 4.9/5, and 6 GHz center frequencies."""

    frequency = int(frequency_mhz)
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
        return (frequency - 2407) // 5
    if 4910 <= frequency <= 4980 and (frequency - 4000) % 5 == 0:
        return (frequency - 4000) // 5
    if 5005 <= frequency <= 5895 and (frequency - 5000) % 5 == 0:
        return (frequency - 5000) // 5
    if frequency == 5935:
        return 2
    if 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
        channel = (frequency - 5950) // 5
        return channel if 1 <= channel <= 233 else None
    return None


def channel_to_frequency(
    channel: int,
    *,
    band: str | None = None,
) -> int:
    """Convert a channel to MHz.

    Because channel numbers overlap between bands, ``band`` is required for
    ambiguous 6 GHz channels. With no band, channels 1-14 use 2.4 GHz and
    higher channels use the conventional 5 GHz mapping.
    """

    channel = validate_channel(channel)
    selected_band = band or ("2.4" if channel <= 14 else "5")
    if selected_band == "2.4":
        if channel == 14:
            return 2484
        if 1 <= channel <= 13:
            return 2407 + (channel * 5)
    elif selected_band == "5":
        if 182 <= channel <= 196:
            return 4000 + (channel * 5)
        frequency = 5000 + (channel * 5)
        if 5005 <= frequency <= 5895:
            return frequency
    elif selected_band == "6":
        if channel == 2:
            return 5935
        return 5950 + (channel * 5)
    else:
        raise ValueError("band must be one of: '2.4', '5', or '6'")
    raise ValueError(f"Channel {channel} is not valid in the {selected_band} GHz band")
