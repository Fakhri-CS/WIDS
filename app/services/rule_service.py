"""Application service for WIDS detection rules."""


class RuleService:
    """Provide access to supported WIDS detection rules."""

    def __init__(self) -> None:
        self._rules: list[dict[str, object]] = [
            {
                "id": "deauthentication_flood",
                "name": "Deauthentication Flood",
                "enabled": True,
            },
            {
                "id": "disassociation_flood",
                "name": "Disassociation Flood",
                "enabled": True,
            },
            {
                "id": "probe_request_flood",
                "name": "Probe Request Flood",
                "enabled": True,
            },
            {
                "id": "authentication_request_flood",
                "name": "Authentication Request Flood",
                "enabled": True,
            },
            {
                "id": "unknown_access_point",
                "name": "Unknown Access Point",
                "enabled": True,
            },
            {
                "id": "unauthorized_bssid",
                "name": "Unauthorized BSSID",
                "enabled": True,
            },
            {
                "id": "evil_twin",
                "name": "Evil Twin",
                "enabled": True,
            },
            {
                "id": "unauthorized_channel",
                "name": "Unauthorized Channel",
                "enabled": True,
            },
            {
                "id": "security_configuration_change",
                "name": "Security Configuration Change",
                "enabled": True,
            },
            {
                "id": "beacon_flood",
                "name": "Beacon Flood",
                "enabled": True,
            },
            {
                "id": "mac_behavioral_conflict",
                "name": "MAC Behavioral Conflict",
                "enabled": True,
            },
        ]

    def get_all(self) -> list[dict[str, object]]:
        """Return all supported detection rules."""
        return [rule.copy() for rule in self._rules]
