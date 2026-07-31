from dataclasses import dataclass

import pytest

from wids.detection.required_fields import (
    find_missing_fields,
    has_required_fields,
)


@dataclass(frozen=True, slots=True)
class Addresses:
    transmitter_mac: str | None
    bssid: str | None


@dataclass(frozen=True, slots=True)
class FrameStub:
    addresses: Addresses
    retry: bool
    sequence_number: int


def test_required_fields_accept_available_nested_values() -> None:
    frame = FrameStub(
        addresses=Addresses(
            transmitter_mac="AA:BB:CC:DD:EE:FF",
            bssid="11:22:33:44:55:66",
        ),
        retry=False,
        sequence_number=0,
    )

    assert has_required_fields(
        frame,
        (
            "addresses.transmitter_mac",
            "addresses.bssid",
            "retry",
            "sequence_number",
        ),
    )


def test_required_fields_report_nested_none_value() -> None:
    frame = FrameStub(
        addresses=Addresses(
            transmitter_mac="AA:BB:CC:DD:EE:FF",
            bssid=None,
        ),
        retry=False,
        sequence_number=0,
    )

    missing = find_missing_fields(
        frame,
        (
            "addresses.transmitter_mac",
            "addresses.bssid",
        ),
    )

    assert missing == ("addresses.bssid",)


def test_required_fields_report_absent_attribute() -> None:
    frame = FrameStub(
        addresses=Addresses(
            transmitter_mac="AA:BB:CC:DD:EE:FF",
            bssid="11:22:33:44:55:66",
        ),
        retry=False,
        sequence_number=0,
    )

    missing = find_missing_fields(
        frame,
        ("management.reason_code",),
    )

    assert missing == ("management.reason_code",)


def test_required_fields_do_not_treat_false_or_zero_as_missing() -> None:
    frame = FrameStub(
        addresses=Addresses(
            transmitter_mac="AA:BB:CC:DD:EE:FF",
            bssid="11:22:33:44:55:66",
        ),
        retry=False,
        sequence_number=0,
    )

    assert (
        find_missing_fields(
            frame,
            ("retry", "sequence_number"),
        )
        == ()
    )


def test_required_fields_reject_invalid_path() -> None:
    frame = FrameStub(
        addresses=Addresses(
            transmitter_mac=None,
            bssid=None,
        ),
        retry=False,
        sequence_number=0,
    )

    with pytest.raises(
        ValueError,
        match="non-empty dotted segments",
    ):
        find_missing_fields(
            frame,
            ("addresses..bssid",),
        )
