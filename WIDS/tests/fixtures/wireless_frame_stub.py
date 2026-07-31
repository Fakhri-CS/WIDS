from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class AddressesStub:
    receiver_mac: str
    transmitter_mac: str
    destination_mac: str | None
    source_mac: str | None
    bssid: str | None


@dataclass(frozen=True, slots=True)
class SequenceStub:
    sequence_number: int | None
    fragment_number: int | None


@dataclass(frozen=True, slots=True)
class FlagsStub:
    retry: bool


@dataclass(frozen=True, slots=True)
class RadioStub:
    channel: int | None


@dataclass(frozen=True, slots=True)
class ManagementStub:
    ssid: str | None
    ssid_hex: str | None
    ssid_state: str
    reason_code: int | None
    authentication_sequence: int | None


@dataclass(frozen=True, slots=True)
class EvidenceStub:
    pcap_reference: str
    frame_sha256: str | None


@dataclass(frozen=True, slots=True)
class WirelessFrameStub:
    contract_version: str
    frame_id: UUID
    capture_session_id: UUID
    packet_number: int
    observed_at: datetime
    frame_subtype: str
    addresses: AddressesStub
    sequence: SequenceStub
    flags: FlagsStub
    radio: RadioStub
    management: ManagementStub
    evidence: EvidenceStub


def create_wireless_frame(
    *,
    capture_session_id: UUID,
    observed_at: datetime,
    sequence_number: int,
    frame_subtype: str,
    transmitter_mac: str = "77:88:99:AA:BB:CC",
    receiver_mac: str = "11:22:33:44:55:66",
    bssid: str | None = "AA:BB:CC:DD:EE:FF",
    retry: bool = False,
    reason_code: int | None = None,
    authentication_sequence: int | None = None,
    ssid: str | None = "WIDS-Lab",
    ssid_hex: str | None = "574944532D4C6162",
    ssid_state: str = "present",
) -> WirelessFrameStub:
    return WirelessFrameStub(
        contract_version="1.0",
        frame_id=uuid4(),
        capture_session_id=capture_session_id,
        packet_number=sequence_number + 1,
        observed_at=observed_at,
        frame_subtype=frame_subtype,
        addresses=AddressesStub(
            receiver_mac=receiver_mac,
            transmitter_mac=transmitter_mac,
            destination_mac=receiver_mac,
            source_mac=transmitter_mac,
            bssid=bssid,
        ),
        sequence=SequenceStub(
            sequence_number=sequence_number,
            fragment_number=0,
        ),
        flags=FlagsStub(
            retry=retry,
        ),
        radio=RadioStub(
            channel=6,
        ),
        management=ManagementStub(
            ssid=ssid,
            ssid_hex=ssid_hex,
            ssid_state=ssid_state,
            reason_code=reason_code,
            authentication_sequence=(authentication_sequence),
        ),
        evidence=EvidenceStub(
            pcap_reference="pcap_samples/test.pcap",
            frame_sha256=None,
        ),
    )
