"""Load validated detection-rule configuration from YAML."""

from pathlib import Path
from typing import Any

import yaml

from wids.common.enums import AlertSeverity
from wids.detection.config import RuleConfig

_ALLOWED_RULE_FIELDS = frozenset(
    {
        "event_type",
        "enabled",
        "severity",
        "correlation_window_seconds",
        "cooldown_seconds",
        "threshold",
        "window_seconds",
    }
)


def load_rule_configs(
    path: str | Path,
) -> dict[str, RuleConfig]:
    """Load and validate detection-rule configurations from YAML."""

    config_path = Path(path)

    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(
            f"Unable to read detection configuration: {config_path}"
        ) from exc

    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Invalid YAML detection configuration: {config_path}"
        ) from exc

    root = _require_mapping(
        document,
        field_name="configuration root",
    )

    raw_rules = _require_mapping(
        root.get("rules"),
        field_name="rules",
    )

    if not raw_rules:
        raise ValueError(
            "Detection configuration must contain at least one rule"
        )

    configs: dict[str, RuleConfig] = {}

    for raw_rule_code, raw_rule_data in raw_rules.items():
        if not isinstance(raw_rule_code, str):
            raise ValueError(
                "Every detection rule code must be a string"
            )

        rule_data = _require_mapping(
            raw_rule_data,
            field_name=f"rules.{raw_rule_code}",
        )

        _reject_unknown_fields(
            rule_code=raw_rule_code,
            rule_data=rule_data,
        )

        try:
            config = RuleConfig(
                code=raw_rule_code,
                event_type=_require_string(
                    rule_data,
                    field_name="event_type",
                    rule_code=raw_rule_code,
                ),
                enabled=_require_boolean(
                    rule_data,
                    field_name="enabled",
                    rule_code=raw_rule_code,
                ),
                severity=AlertSeverity(
                    _require_string(
                        rule_data,
                        field_name="severity",
                        rule_code=raw_rule_code,
                    )
                ),
                correlation_window_seconds=_require_integer(
                    rule_data,
                    field_name="correlation_window_seconds",
                    rule_code=raw_rule_code,
                ),
                cooldown_seconds=_require_integer(
                    rule_data,
                    field_name="cooldown_seconds",
                    rule_code=raw_rule_code,
                ),
                threshold=_optional_integer(
                    rule_data,
                    field_name="threshold",
                    rule_code=raw_rule_code,
                ),
                window_seconds=_optional_integer(
                    rule_data,
                    field_name="window_seconds",
                    rule_code=raw_rule_code,
                ),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid configuration for {raw_rule_code}: {exc}"
            ) from exc

        configs[raw_rule_code] = config

    return configs


def _require_mapping(
    value: object,
    *,
    field_name: str,
) -> dict[str, Any]:
    """Require a YAML object to be a mapping."""

    if not isinstance(value, dict):
        raise ValueError(
            f"{field_name} must be a YAML mapping"
        )

    return value


def _require_string(
    data: dict[str, Any],
    *,
    field_name: str,
    rule_code: str,
) -> str:
    """Read one required string field."""

    value = data.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{rule_code}.{field_name} must be a non-empty string"
        )

    return value


def _require_boolean(
    data: dict[str, Any],
    *,
    field_name: str,
    rule_code: str,
) -> bool:
    """Read one required boolean field."""

    value = data.get(field_name)

    if not isinstance(value, bool):
        raise ValueError(
            f"{rule_code}.{field_name} must be a boolean"
        )

    return value


def _require_integer(
    data: dict[str, Any],
    *,
    field_name: str,
    rule_code: str,
) -> int:
    """Read one required integer field."""

    value = data.get(field_name)

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{rule_code}.{field_name} must be an integer"
        )

    return value


def _optional_integer(
    data: dict[str, Any],
    *,
    field_name: str,
    rule_code: str,
) -> int | None:
    """Read one optional integer field."""

    if field_name not in data or data[field_name] is None:
        return None

    return _require_integer(
        data,
        field_name=field_name,
        rule_code=rule_code,
    )


def _reject_unknown_fields(
    *,
    rule_code: str,
    rule_data: dict[str, Any],
) -> None:
    """Reject misspelled or unsupported configuration fields."""

    unknown_fields = sorted(
        set(rule_data) - _ALLOWED_RULE_FIELDS
    )

    if not unknown_fields:
        return

    raise ValueError(
        f"Unknown fields for {rule_code}: "
        + ", ".join(unknown_fields)
    )
