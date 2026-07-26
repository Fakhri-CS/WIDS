"""Application service for observed wireless access points."""


class AccessPointService:
    """Provide access to access points observed by the WIDS sensor."""

    def __init__(self) -> None:
        self._access_points: list[dict[str, object]] = []

    def get_all(self) -> list[dict[str, object]]:
        """Return all observed wireless access points."""
        return self._access_points.copy()
