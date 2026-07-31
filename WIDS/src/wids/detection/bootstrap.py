"""Build the detection engine from external configuration."""

from pathlib import Path

from wids.detection.config_loader import load_rule_configs
from wids.detection.default_registry import (
    build_default_detection_engine,
)
from wids.detection.engine import DetectionEngine
from wids.detection.frame_protocols import (
    NormalizedWirelessFrameProtocol,
)


def build_detection_engine_from_yaml(
    path: str | Path,
) -> DetectionEngine[NormalizedWirelessFrameProtocol]:
    """Load validated rule configs and build the five-rule engine."""

    configs = load_rule_configs(path)

    return build_default_detection_engine(configs)
