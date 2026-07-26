"""Application service for packet capture operations."""


class CaptureService:
    """Manage the current packet-capture state."""

    def __init__(self) -> None:
        self._is_running = False
        self._interface: str | None = None

    def start(self, interface: str) -> dict[str, str] | None:
        """Start a capture session.

        Return None when capture is already running.
        """
        if self._is_running:
            return None

        self._is_running = True
        self._interface = interface

        return {
            "status": "running",
            "interface": interface,
        }

    def stop(self) -> dict[str, str] | None:
        """Stop the current capture session.

        Return None when no capture session is running.
        """
        if not self._is_running:
            return None

        interface = self._interface or "unknown"

        self._is_running = False
        self._interface = None

        return {
            "status": "stopped",
            "interface": interface,
        }
