import re
from uuid import uuid4

import pytest

from wids.detection.correlation import build_correlation_key


def test_correlation_key_is_deterministic() -> None:
    capture_session_id = uuid4()

    first_key = build_correlation_key(
        rule_code="WIDS-R001",
        capture_session_id=capture_session_id,
        components={
            "transmitter_mac": "AA:BB:CC:DD:EE:FF",
            "bssid": "11:22:33:44:55:66",
        },
    )

    second_key = build_correlation_key(
        rule_code="WIDS-R001",
        capture_session_id=capture_session_id,
        components={
            "bssid": "11:22:33:44:55:66",
            "transmitter_mac": "AA:BB:CC:DD:EE:FF",
        },
    )

    assert first_key == second_key


def test_correlation_key_changes_with_components() -> None:
    capture_session_id = uuid4()

    first_key = build_correlation_key(
        rule_code="WIDS-R001",
        capture_session_id=capture_session_id,
        components={
            "transmitter_mac": "AA:BB:CC:DD:EE:FF",
            "bssid": "11:22:33:44:55:66",
        },
    )

    second_key = build_correlation_key(
        rule_code="WIDS-R001",
        capture_session_id=capture_session_id,
        components={
            "transmitter_mac": "AA:BB:CC:DD:EE:FF",
            "bssid": "22:33:44:55:66:77",
        },
    )

    assert first_key != second_key


def test_correlation_key_has_sha256_format() -> None:
    key = build_correlation_key(
        rule_code="WIDS-R004",
        capture_session_id=uuid4(),
        components={
            "transmitter_mac": "AA:BB:CC:DD:EE:FF",
        },
    )

    assert re.fullmatch(r"[0-9a-f]{64}", key) is not None


def test_correlation_key_rejects_empty_components() -> None:
    with pytest.raises(
        ValueError,
        match="components must not be empty",
    ):
        build_correlation_key(
            rule_code="WIDS-R001",
            capture_session_id=uuid4(),
            components={},
        )
