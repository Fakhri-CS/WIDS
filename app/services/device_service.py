"""Application service for detected wireless devices."""


class DeviceService:
    """Provide access to devices observed by the WIDS sensor."""

    def __init__(self) -> None:
        self._devices: list[dict[str, object]] = []

    def get_all(self) -> list[dict[str, object]]:
        """Return all observed wireless devices."""
        return self._devices.copy()
