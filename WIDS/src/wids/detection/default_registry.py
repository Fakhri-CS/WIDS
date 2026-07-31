"""Build the standard five-rule detection engine."""

from collections.abc import Mapping

from wids.detection.config import RuleConfig
from wids.detection.engine import DetectionEngine
from wids.detection.frame_protocols import NormalizedWirelessFrameProtocol
from wids.detection.registry import RegisteredRule, RuleRegistry
from wids.detection.rules.authentication_flood import (
    AuthenticationFloodRule,
)
from wids.detection.rules.beacon_flood import BeaconFloodRule
from wids.detection.rules.deauthentication_flood import (
    DeauthenticationFloodRule,
)
from wids.detection.rules.disassociation_flood import (
    DisassociationFloodRule,
)
from wids.detection.rules.probe_request_flood import ProbeRequestFloodRule

DEFAULT_RULE_CODES: tuple[str, ...] = (
    "WIDS-R001",
    "WIDS-R002",
    "WIDS-R003",
    "WIDS-R004",
    "WIDS-R005",
)


def build_default_rule_registry(
    configs: Mapping[str, RuleConfig],
) -> RuleRegistry[NormalizedWirelessFrameProtocol]:
    """Build the registry containing the five supported WIDS rules."""

    _validate_default_configs(configs)

    def create_r001() -> DeauthenticationFloodRule:
        return DeauthenticationFloodRule(configs["WIDS-R001"])

    def create_r002() -> DisassociationFloodRule:
        return DisassociationFloodRule(configs["WIDS-R002"])

    def create_r003() -> AuthenticationFloodRule:
        return AuthenticationFloodRule(configs["WIDS-R003"])

    def create_r004() -> ProbeRequestFloodRule:
        return ProbeRequestFloodRule(configs["WIDS-R004"])

    def create_r005() -> BeaconFloodRule:
        return BeaconFloodRule(configs["WIDS-R005"])

    return RuleRegistry(
        [
            RegisteredRule[NormalizedWirelessFrameProtocol](
                rule_code="WIDS-R001",
                factory=create_r001,
            ),
            RegisteredRule[NormalizedWirelessFrameProtocol](
                rule_code="WIDS-R002",
                factory=create_r002,
            ),
            RegisteredRule[NormalizedWirelessFrameProtocol](
                rule_code="WIDS-R003",
                factory=create_r003,
            ),
            RegisteredRule[NormalizedWirelessFrameProtocol](
                rule_code="WIDS-R004",
                factory=create_r004,
            ),
            RegisteredRule[NormalizedWirelessFrameProtocol](
                rule_code="WIDS-R005",
                factory=create_r005,
            ),
        ]
    )


def build_default_detection_engine(
    configs: Mapping[str, RuleConfig],
) -> DetectionEngine[NormalizedWirelessFrameProtocol]:
    """Build a detection engine containing the five supported rules."""

    registry = build_default_rule_registry(configs)
    return registry.build_engine()


def _validate_default_configs(
    configs: Mapping[str, RuleConfig],
) -> None:
    """Require configuration for exactly the five supported rules."""

    expected_codes = set(DEFAULT_RULE_CODES)
    provided_codes = set(configs)

    missing_codes = sorted(expected_codes - provided_codes)
    unexpected_codes = sorted(provided_codes - expected_codes)

    if not missing_codes and not unexpected_codes:
        return

    problems: list[str] = []

    if missing_codes:
        problems.append(
            "missing configurations: "
            + ", ".join(missing_codes)
        )

    if unexpected_codes:
        problems.append(
            "unexpected configurations: "
            + ", ".join(unexpected_codes)
        )

    raise ValueError(
        "Invalid default detection configuration: "
        + "; ".join(problems)
    )
