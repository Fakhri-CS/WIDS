"""Safe wireless-interface discovery and monitor-mode management."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, TypedDict

_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")


class _InterfaceRecord(TypedDict, total=False):
    """Partially parsed fields for one wireless interface."""

    name: str
    phy: str | None
    interface_type: str
    mac_address: str
    channel: int
    frequency_mhz: int


class InterfaceManagerError(RuntimeError):
    """Raised when a wireless-interface operation fails."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Small command result abstraction that is easy to fake in tests."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """Runs an argument vector without invoking a shell."""

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
    ) -> CommandResult:
        """Execute a command and return captured text output."""


class SubprocessCommandRunner:
    """Production command runner."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                tuple(args),
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise InterfaceManagerError(f"Unable to execute {args[0]!r}: {error}") from error

        result = CommandResult(
            args=tuple(args),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise InterfaceManagerError(f"Command {args[0]!r} failed: {detail or 'unknown error'}")
        return result


@dataclass(frozen=True, slots=True)
class WirelessInterface:
    """Current information reported by ``iw`` and ``ip``."""

    name: str
    phy: str | None
    interface_type: str
    mac_address: str | None
    channel: int | None
    frequency_mhz: int | None
    is_up: bool

    @property
    def monitor_mode(self) -> bool:
        return self.interface_type == "monitor"


class InterfaceManager:
    """Discovers wireless interfaces and changes their operating type."""

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or SubprocessCommandRunner()

    def list_wireless_interfaces(self) -> tuple[WirelessInterface, ...]:
        """Return interfaces shown by ``iw dev``."""

        result = self._runner.run(("iw", "dev"))
        parsed = _parse_iw_dev(result.stdout)
        return tuple(
            WirelessInterface(
                name=item.name,
                phy=item.phy,
                interface_type=item.interface_type,
                mac_address=item.mac_address,
                channel=item.channel,
                frequency_mhz=item.frequency_mhz,
                is_up=self._is_up(item.name),
            )
            for item in parsed
        )

    def get_interface(self, interface_name: str) -> WirelessInterface:
        """Return one wireless interface or raise a clear error."""

        name = validate_interface_name(interface_name)
        for interface in self.list_wireless_interfaces():
            if interface.name == name:
                return interface
        raise InterfaceManagerError(f"Wireless interface not found: {name}")

    def is_monitor_mode(self, interface_name: str) -> bool:
        return self.get_interface(interface_name).monitor_mode

    def ensure_monitor_mode(self, interface_name: str) -> WirelessInterface:
        """Enable monitor mode only when it is not already active."""

        interface = self.get_interface(interface_name)
        if interface.monitor_mode and interface.is_up:
            return interface
        return self.set_interface_type(interface.name, "monitor")

    def restore_managed_mode(self, interface_name: str) -> WirelessInterface:
        """Return an interface to managed mode."""

        return self.set_interface_type(interface_name, "managed")

    def set_interface_type(
        self,
        interface_name: str,
        interface_type: str,
    ) -> WirelessInterface:
        """Set ``managed`` or ``monitor`` mode using ``ip`` and ``iw``."""

        name = validate_interface_name(interface_name)
        if interface_type not in {"managed", "monitor"}:
            raise ValueError("interface_type must be 'managed' or 'monitor'")

        self.get_interface(name)
        self._runner.run(("ip", "link", "set", "dev", name, "down"))
        try:
            self._runner.run(("iw", "dev", name, "set", "type", interface_type))
            self._runner.run(("ip", "link", "set", "dev", name, "up"))
        except InterfaceManagerError:
            # Best-effort recovery: do not leave the adapter down after a failed
            # type change.
            self._runner.run(
                ("ip", "link", "set", "dev", name, "up"),
                check=False,
            )
            raise

        updated = self.get_interface(name)
        if updated.interface_type != interface_type:
            raise InterfaceManagerError(f"{name} did not enter {interface_type} mode")
        return updated

    def _is_up(self, interface_name: str) -> bool:
        result = self._runner.run(
            ("ip", "-o", "link", "show", "dev", interface_name),
            check=False,
        )
        if result.returncode != 0:
            return False
        return bool(re.search(r"<[^>]*\bUP\b[^>]*>", result.stdout))


def validate_interface_name(interface_name: str) -> str:
    """Validate an interface name before passing it to operating-system tools."""

    name = str(interface_name).strip()
    if not _INTERFACE_PATTERN.fullmatch(name):
        raise ValueError(f"Invalid interface name: {interface_name!r}")
    return name


def _parse_iw_dev(output: str) -> list[WirelessInterface]:
    """Parse the stable fields reported by ``iw dev``."""

    interfaces: list[WirelessInterface] = []

    phy: str | None = None
    current: _InterfaceRecord | None = None

    def finish() -> None:
        nonlocal current

        if current is None:
            return

        name = current.get("name")

        if name is None:
            current = None
            return

        interfaces.append(
            WirelessInterface(
                name=name,
                phy=current.get("phy"),
                interface_type=current.get(
                    "interface_type",
                    "unknown",
                ),
                mac_address=current.get("mac_address"),
                channel=current.get("channel"),
                frequency_mhz=current.get("frequency_mhz"),
                is_up=False,
            )
        )

        current = None

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line.startswith("phy#"):
            phy = line

        elif line.startswith("Interface "):
            finish()

            current = {
                "name": line.removeprefix("Interface ").strip(),
                "phy": phy,
            }

        elif current is not None and line.startswith("type "):
            current["interface_type"] = line.removeprefix("type ").strip()

        elif current is not None and line.startswith("addr "):
            current["mac_address"] = line.removeprefix("addr ").strip().upper()

        elif current is not None and line.startswith("channel "):
            match = re.search(
                r"channel\s+(\d+)\s+\((\d+)\s+MHz\)",
                line,
            )

            if match is not None:
                current["channel"] = int(match.group(1))

                current["frequency_mhz"] = int(match.group(2))

    finish()

    return interfaces
