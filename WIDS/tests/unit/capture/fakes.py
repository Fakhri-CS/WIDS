"""Packet-like and command-runner fakes used by capture unit tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

from wids.capture.frame_models import CaptureSource
from wids.capture.interface_manager import CommandResult
from wids.capture.packet_source import PacketEnvelope

DEFAULT_TIME = datetime(2026, 7, 27, 6, 31, 44, tzinfo=UTC)
AP = "AA:BB:CC:DD:EE:FF"
STATION = "11:22:33:44:55:66"
BROADCAST = "FF:FF:FF:FF:FF:FF"


def make_packet(
    *,
    subtype: int = 8,
    observed_at: datetime = DEFAULT_TIME,
    ssid_raw: bytes | None = b"WIDS-Lab",
    advertised_channel: int | None = 6,
    radio: bool = True,
    invalid_fcs: bool = False,
    malformed_rsn: bool = False,
    truncated: bool = False,
    retry: bool = False,
    sequence_number: int | None = 931,
    fragment_number: int | None = 0,
    frame_type: int = 0,
    include_security: bool = True,
    include_wlan: bool = True,
    bssid: str | None = AP,
) -> Any:
    if not include_wlan:
        return SimpleNamespace(
            sniff_time=observed_at,
            frame_info=SimpleNamespace(len=60, cap_len=60),
        )

    receiver = (
        STATION
        if subtype in {10, 12}
        else BROADCAST
    )
    transmitter = STATION if subtype == 4 else AP
    wlan_values: dict[str, Any] = {
        "fc_type": frame_type,
        "fc_subtype": subtype,
        "ra": receiver,
        "ta": transmitter,
        "da": receiver,
        "sa": transmitter,
        "seq": sequence_number,
        "frag": fragment_number,
        "fc_to_ds": False,
        "fc_from_ds": False,
        "fc_more_frag": False,
        "fc_retry": retry,
        "fc_pwrmgt": False,
        "fc_moredata": False,
        "fc_protected": False,
        "fc_order": False,
    }
    if bssid is not None:
        wlan_values["bssid"] = bssid

    management_values: dict[str, Any] = {}
    if ssid_raw is not None:
        management_values["ssid_raw"] = ssid_raw
    if advertised_channel is not None:
        management_values["ds_current_channel"] = advertised_channel
    if subtype == 8:
        management_values["fixed_beacon"] = 100
        management_values["fixed_capabilities_privacy"] = include_security
    if subtype in {10, 12}:
        management_values["fixed_reason_code"] = 7
    if subtype == 11:
        management_values["fixed_auth_alg"] = 0
        management_values["fixed_auth_seq"] = 1
    if include_security and subtype in {5, 8}:
        management_values.update(
            {
                "rsn_version": 1,
                "rsn_group_cipher": 4,
                "rsn_pairwise_cipher": [4],
                "rsn_akm": [2],
                "pmf_capable": True,
                "pmf_required": False,
            }
        )
    if malformed_rsn:
        management_values["malformed_rsn"] = True
    management_values["stable_information_elements"] = (
        b"\x00\x08WIDS-Lab\x03\x01\x06"
    )

    packet_values: dict[str, Any] = {
        "wlan": SimpleNamespace(**wlan_values),
        "wlan_mgt": SimpleNamespace(**management_values),
        "sniff_time": observed_at,
        "frame_info": SimpleNamespace(
            **{
                "len": 100,
                "cap_len": 20 if truncated else 100,
            }
        ),
    }
    if radio:
        packet_values["radiotap"] = SimpleNamespace(
            channel_freq=2437,
            dbm_antsignal=-47,
            dbm_antnoise=-92,
            datarate=1.0,
            antenna=0,
            flags_badfcs=invalid_fcs,
        )
    raw = b"\x00\x00\x08\x00\x00\x00\x00\x00" + bytes(range(32))
    packet_values["get_raw_packet"] = lambda: raw
    return SimpleNamespace(**packet_values)


def make_envelope(
    packet: Any | None = None,
    *,
    capture_source: CaptureSource = CaptureSource.PCAP,
    interface_name: str | None = None,
    packet_number: int = 1,
    capture_session_id: UUID | None = None,
    pcap_reference: str = "pcap_samples/lab_management_frames.pcap",
) -> PacketEnvelope:
    return PacketEnvelope(
        packet=packet or make_packet(),
        capture_session_id=capture_session_id or uuid4(),
        capture_source=capture_source,
        interface_name=interface_name,
        packet_number=packet_number,
        pcap_reference=pcap_reference,
    )


@dataclass
class FakeRunner:
    """Configurable argument-vector command runner."""

    responses: dict[tuple[str, ...], CommandResult]

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        args: tuple[str, ...],
        *,
        check: bool = True,
    ) -> CommandResult:
        del check
        command = tuple(args)
        self.calls.append(command)
        return self.responses.get(
            command,
            CommandResult(command, 0, "", ""),
        )
