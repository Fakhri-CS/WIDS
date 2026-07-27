from datetime import datetime
from typing import Protocol
from uuid import UUID


class FrameAddresses(Protocol):
    receiver_mac: str
    transmitter_mac: str
    destination_mac: str | None
    source_mac: str | None
    bssid: str | None


class FrameSequence(Protocol):
    sequence_number: int | None
    fragment_number: int | None


class FrameFlags(Protocol):
    retry: bool


class FrameRadio(Protocol):
    channel: int | None


class FrameManagement(Protocol):
    reason_code: int | None


class FrameEvidence(Protocol):
    pcap_reference: str
    frame_sha256: str | None


class NormalizedWirelessFrameProtocol(Protocol):
    """Fields used by Version 1 wireless detection rules."""

    contract_version: str
    frame_id: UUID
    capture_session_id: UUID
    packet_number: int
    observed_at: datetime

    frame_subtype: str

    addresses: FrameAddresses
    sequence: FrameSequence
    flags: FrameFlags
    radio: FrameRadio
    management: FrameManagement
    evidence: FrameEvidence
