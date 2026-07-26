"""Application service for WIDS alerts."""


class AlertService:
    """Provide access to detected WIDS alerts."""

    def __init__(self) -> None:
        self._alerts: list[dict[str, object]] = []

    def get_all(self) -> list[dict[str, object]]:
        """Return all detected alerts."""
        return self._alerts.copy()
