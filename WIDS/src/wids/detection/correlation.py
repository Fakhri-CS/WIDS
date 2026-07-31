import hashlib
import json
import re
from collections.abc import Mapping
from uuid import UUID

type CorrelationValue = str | int | bool | None

_RULE_CODE_PATTERN = re.compile(r"^WIDS-R\d{3}$")
_COMPONENT_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


def build_correlation_key(
    *,
    rule_code: str,
    capture_session_id: UUID,
    components: Mapping[str, CorrelationValue],
) -> str:
    """Build a deterministic SHA-256 alert-correlation key."""

    if _RULE_CODE_PATTERN.fullmatch(rule_code) is None:
        raise ValueError("rule_code must use the WIDS-R000 format")

    if not components:
        raise ValueError("correlation components must not be empty")

    normalized_components: dict[str, CorrelationValue] = {}

    for name, value in components.items():
        if _COMPONENT_NAME_PATTERN.fullmatch(name) is None:
            raise ValueError("correlation component names must use lowercase snake_case")

        normalized_components[name] = value

    payload = {
        "version": "1",
        "rule_code": rule_code,
        "capture_session_id": str(capture_session_id),
        "components": normalized_components,
    }

    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
