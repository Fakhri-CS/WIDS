"""Immutable models for the WIDS wireless-frame contract.

Only this normalized representation may cross the packet-parser boundary.
Downstream code must never depend on PyShark or Wireshark field names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping
from uuid import UUID, uuid4


CONTRACT_VERSION = "1.0"
_MAC_PATTERN = re.compile(r"^[0-9A-F]{12}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class CaptureSource(StrEnum):
    """Origin of a captured packet."""

    LIVE = "live"
    PCAP = "pcap"


class FrameType(StrEnum):
    """Frame types supported by contract version 1."""

    MANAGEMENT = "management"


class FrameSubtype(StrEnum):
    """Stable management-frame subtype vocabulary."""

    ASSOCIATION_REQUEST = "association_request"
    ASSOCIATION_RESPONSE = "association_response"
    REASSOCIATION_REQUEST = "reassociation_request"
    REASSOCIATION_RESPONSE = "reassociation_response"
    PROBE_REQUEST = "probe_request"
    PROBE_RESPONSE = "probe_response"
    RESERVED_6 = "reserved_6"
    RESERVED_7 = "reserved_7"
    BEACON = "beacon"
    ATIM = "atim"
    DISASSOCIATION = "disassociation"
    AUTHENTICATION = "authentication"
    DEAUTHENTICATION = "deauthentication"
    ACTION = "action"
    ACTION_NO_ACK = "action_no_ack"
    RESERVED_15 = "reserved_15"


SUBTYPE_BY_CODE: Mapping[int, FrameSubtype] = MappingProxyType(
    {
        0: FrameSubtype.ASSOCIATION_REQUEST,
        1: FrameSubtype.ASSOCIATION_RESPONSE,
        2: FrameSubtype.REASSOCIATION_REQUEST,
        3: FrameSubtype.REASSOCIATION_RESPONSE,
        4: FrameSubtype.PROBE_REQUEST,
        5: FrameSubtype.PROBE_RESPONSE,
        6: FrameSubtype.RESERVED_6,
        7: FrameSubtype.RESERVED_7,
        8: FrameSubtype.BEACON,
        9: FrameSubtype.ATIM,
        10: FrameSubtype.DISASSOCIATION,
        11: FrameSubtype.AUTHENTICATION,
        12: FrameSubtype.DEAUTHENTICATION,
        13: FrameSubtype.ACTION,
        14: FrameSubtype.ACTION_NO_ACK,
        15: FrameSubtype.RESERVED_15,
    }
)
SUBTYPE_CODE: Mapping[FrameSubtype, int] = MappingProxyType(
    {subtype: code for code, subtype in SUBTYPE_BY_CODE.items()}
)


class TransmitterRoleHint(StrEnum):
    """Conservative role hint derived only from frame semantics."""

    ACCESS_POINT = "access_point"
    STATION = "station"
    UNKNOWN = "unknown"


class FcsStatus(StrEnum):
    """Frame-check-sequence status supplied by the capture adapter."""

    VALID = "valid"
    INVALID = "invalid"
    NOT_PRESENT = "not_present"
    UNKNOWN = "unknown"


class SsidState(StrEnum):
    """Meaning of the normalized SSID element."""

    PRESENT = "present"
    HIDDEN = "hidden"
    WILDCARD = "wildcard"
    INVALID_UTF8 = "invalid_utf8"
    ABSENT = "absent"


class ParseStatus(StrEnum):
    """Whether all subtype-specific values were available."""

    COMPLETE = "complete"
    PARTIAL = "partial"


class SecurityClassification(StrEnum):
    """Normalized access-point security classification."""

    OPEN = "open"
    WEP_OR_LEGACY = "wep_or_legacy"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class SecurityProtocol(StrEnum):
    """Advertised security protocol."""

    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"


class ParserDisposition(StrEnum):
    """Outcome of parsing one packet."""

    ACCEPTED = "accepted"
    IGNORED = "ignored"
    REJECTED = "rejected"


class ParserReason(StrEnum):
    """Stable ignored/rejected reason codes."""

    NOT_IEEE80211 = "not_ieee80211"
    OUT_OF_SCOPE_FRAME_TYPE = "out_of_scope_frame_type"
    UNSUPPORTED_SUBTYPE = "unsupported_subtype"
    TRUNCATED_MANAGEMENT_HEADER = "truncated_management_header"
    MISSING_RECEIVER_ADDRESS = "missing_receiver_address"
    MISSING_TRANSMITTER_ADDRESS = "missing_transmitter_address"
    INVALID_MAC_ADDRESS = "invalid_mac_address"
    INVALID_FCS = "invalid_fcs"
    MALFORMED_REQUIRED_FIELD = "malformed_required_field"
    PARSER_ERROR = "parser_error"


class CaptureState(StrEnum):
    """Actual state of the capture pipeline."""

    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


def normalize_mac(value: str) -> str:
    """Return an uppercase, colon-delimited MAC address.

    Hyphen-delimited and Cisco dotted input are accepted, but placeholder or
    incomplete values are rejected.
    """

    compact = re.sub(r"[:.\-\s]", "", str(value)).upper()
    if not _MAC_PATTERN.fullmatch(compact):
        raise ValueError(f"Invalid MAC address: {value!r}")
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def ensure_utc(value: datetime) -> datetime:
    """Normalize a datetime to timezone-aware UTC."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def datetime_to_rfc3339(value: datetime) -> str:
    """Serialize a datetime using the contract's UTC microsecond format."""

    return ensure_utc(value).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )


def datetime_from_rfc3339(value: str) -> datetime:
    """Parse an RFC 3339 timestamp and normalize it to UTC."""

    return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def sha256_hex(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def _validate_optional_int(
    name: str,
    value: int | None,
    minimum: int,
    maximum: int,
) -> None:
    if value is not None and not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")


def _validate_optional_finite_number(
    name: str,
    value: float | None,
    *,
    positive: bool = False,
) -> None:
    if value is None:
        return
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    if positive and value <= 0:
        raise ValueError(f"{name} must be positive")


def _canonical_names(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = {str(value).strip().lower() for value in values if str(value).strip()}
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class MacAddresses:
    """Normalized IEEE 802.11 address fields."""

    receiver_mac: str
    transmitter_mac: str
    destination_mac: str | None
    source_mac: str | None
    bssid: str | None
    transmitter_role_hint: TransmitterRoleHint

    def __post_init__(self) -> None:
        for name in ("receiver_mac", "transmitter_mac"):
            object.__setattr__(self, name, normalize_mac(getattr(self, name)))
        for name in ("destination_mac", "source_mac", "bssid"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, normalize_mac(value))


@dataclass(frozen=True, slots=True)
class SequenceInfo:
    """Sequence-control values used by retry deduplication."""

    sequence_number: int | None
    fragment_number: int | None

    def __post_init__(self) -> None:
        _validate_optional_int("sequence_number", self.sequence_number, 0, 4095)
        _validate_optional_int("fragment_number", self.fragment_number, 0, 15)


@dataclass(frozen=True, slots=True)
class FrameFlags:
    """Normalized frame-control flags."""

    to_ds: bool = False
    from_ds: bool = False
    more_fragments: bool = False
    retry: bool = False
    power_management: bool = False
    more_data: bool = False
    protected: bool = False
    order: bool = False


@dataclass(frozen=True, slots=True)
class RadioMetadata:
    """Optional capture-radio metadata."""

    channel: int | None
    frequency_mhz: int | None
    signal_dbm: int | None
    noise_dbm: int | None
    data_rate_mbps: float | None
    antenna_index: int | None
    fcs_status: FcsStatus

    def __post_init__(self) -> None:
        _validate_optional_int("channel", self.channel, 1, 233)
        if self.frequency_mhz is not None and self.frequency_mhz <= 0:
            raise ValueError("frequency_mhz must be positive")
        _validate_optional_int("signal_dbm", self.signal_dbm, -127, 0)
        _validate_optional_int("noise_dbm", self.noise_dbm, -127, 0)
        _validate_optional_finite_number(
            "data_rate_mbps",
            self.data_rate_mbps,
            positive=True,
        )
        if self.antenna_index is not None and self.antenna_index < 0:
            raise ValueError("antenna_index cannot be negative")


@dataclass(frozen=True, slots=True)
class SecurityProfile:
    """Canonical security profile and its deterministic fingerprint."""

    classification: SecurityClassification
    protocols: tuple[SecurityProtocol, ...]
    group_cipher: str | None
    pairwise_ciphers: tuple[str, ...]
    akm_suites: tuple[str, ...]
    pmf_capable: bool | None
    pmf_required: bool | None
    fingerprint_sha256: str = ""

    def __post_init__(self) -> None:
        protocols = tuple(
            sorted(
                set(self.protocols),
                key=lambda protocol: protocol.value,
            )
        )
        pairwise = _canonical_names(self.pairwise_ciphers)
        akm = _canonical_names(self.akm_suites)
        group = (
            self.group_cipher.strip().lower()
            if self.group_cipher and self.group_cipher.strip()
            else None
        )

        object.__setattr__(self, "protocols", protocols)
        object.__setattr__(self, "pairwise_ciphers", pairwise)
        object.__setattr__(self, "akm_suites", akm)
        object.__setattr__(self, "group_cipher", group)

        expected = sha256_hex(
            json.dumps(
                self.canonical_payload(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        )
        if self.fingerprint_sha256 and self.fingerprint_sha256 != expected:
            raise ValueError("security fingerprint does not match the profile")
        object.__setattr__(self, "fingerprint_sha256", expected)

    def canonical_payload(self) -> dict[str, Any]:
        """Return exactly the values included in the security fingerprint."""

        return {
            "akm_suites": list(self.akm_suites),
            "classification": self.classification.value,
            "group_cipher": self.group_cipher,
            "pairwise_ciphers": list(self.pairwise_ciphers),
            "pmf_capable": self.pmf_capable,
            "pmf_required": self.pmf_required,
            "protocols": [protocol.value for protocol in self.protocols],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.canonical_payload()
        payload["fingerprint_sha256"] = self.fingerprint_sha256
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SecurityProfile:
        return cls(
            classification=SecurityClassification(str(value["classification"])),
            protocols=tuple(
                SecurityProtocol(str(protocol))
                for protocol in value.get("protocols", ())
            ),
            group_cipher=_optional_str(value.get("group_cipher")),
            pairwise_ciphers=tuple(
                str(cipher) for cipher in value.get("pairwise_ciphers", ())
            ),
            akm_suites=tuple(
                str(suite) for suite in value.get("akm_suites", ())
            ),
            pmf_capable=_optional_bool(value.get("pmf_capable")),
            pmf_required=_optional_bool(value.get("pmf_required")),
            fingerprint_sha256=str(value.get("fingerprint_sha256", "")),
        )


@dataclass(frozen=True, slots=True)
class ManagementFields:
    """Normalized management-frame information."""

    ssid: str | None
    ssid_hex: str | None
    ssid_state: SsidState
    advertised_channel: int | None
    reason_code: int | None
    status_code: int | None
    authentication_algorithm: int | None
    authentication_sequence: int | None
    beacon_interval_tu: int | None
    capability_privacy: bool | None
    information_elements_sha256: str | None
    security: SecurityProfile | None

    def __post_init__(self) -> None:
        if self.ssid_hex is not None:
            if len(self.ssid_hex) > 64 or len(self.ssid_hex) % 2:
                raise ValueError("ssid_hex must contain at most 32 bytes")
            try:
                bytes.fromhex(self.ssid_hex)
            except ValueError as error:
                raise ValueError("ssid_hex must be lowercase hexadecimal") from error
            if self.ssid_hex != self.ssid_hex.lower():
                raise ValueError("ssid_hex must be lowercase hexadecimal")
        if self.ssid_state is SsidState.PRESENT:
            if self.ssid is None or not self.ssid_hex:
                raise ValueError("present SSIDs require text and non-empty bytes")
        elif self.ssid_state in {SsidState.HIDDEN, SsidState.WILDCARD}:
            if self.ssid is not None or self.ssid_hex != "":
                raise ValueError(
                    "hidden/wildcard SSIDs require an empty byte value"
                )
        elif self.ssid_state is SsidState.INVALID_UTF8:
            if self.ssid is not None or not self.ssid_hex:
                raise ValueError(
                    "invalid UTF-8 SSIDs require preserved non-empty bytes"
                )
        elif self.ssid_state is SsidState.ABSENT:
            if self.ssid is not None or self.ssid_hex is not None:
                raise ValueError("absent SSIDs cannot contain text or bytes")
        _validate_optional_int(
            "advertised_channel",
            self.advertised_channel,
            1,
            233,
        )
        for name in (
            "reason_code",
            "status_code",
            "authentication_algorithm",
            "authentication_sequence",
            "beacon_interval_tu",
        ):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} cannot be negative")
        if (
            self.information_elements_sha256 is not None
            and not _SHA256_PATTERN.fullmatch(
                self.information_elements_sha256,
            )
        ):
            raise ValueError(
                "information_elements_sha256 must be a lowercase SHA-256 digest"
            )


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Opaque link from a normalized frame to its source packet."""

    pcap_reference: str
    frame_sha256: str | None

    def __post_init__(self) -> None:
        reference = self.pcap_reference.strip().replace("\\", "/")
        if not reference or reference.startswith("/"):
            raise ValueError("pcap_reference must be a non-empty opaque reference")
        if any(part == ".." for part in reference.split("/")):
            raise ValueError("pcap_reference cannot contain parent traversal")
        object.__setattr__(self, "pcap_reference", reference)
        if (
            self.frame_sha256 is not None
            and not _SHA256_PATTERN.fullmatch(self.frame_sha256)
        ):
            raise ValueError("frame_sha256 must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class NormalizedWirelessFrame:
    """Validated immutable representation of one management frame."""

    capture_session_id: UUID
    capture_source: CaptureSource
    interface_name: str | None
    packet_number: int
    observed_at: datetime
    original_length: int
    captured_length: int
    frame_subtype: FrameSubtype
    frame_subtype_code: int
    addresses: MacAddresses
    sequence: SequenceInfo
    flags: FrameFlags
    radio: RadioMetadata
    management: ManagementFields
    evidence: EvidenceReference
    parse_status: ParseStatus
    parse_warnings: tuple[str, ...] = ()
    frame_id: UUID = field(default_factory=uuid4)
    ingested_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    contract_version: str = CONTRACT_VERSION
    frame_type: FrameType = FrameType.MANAGEMENT
    frame_type_code: int = 0

    def __post_init__(self) -> None:
        if self.contract_version != CONTRACT_VERSION:
            raise ValueError(f"Unsupported contract version: {self.contract_version}")
        if self.frame_type is not FrameType.MANAGEMENT or self.frame_type_code != 0:
            raise ValueError("Version 1 accepts management frames only")
        if self.packet_number < 1:
            raise ValueError("packet_number must be one-based")
        if self.original_length < 0 or self.captured_length < 0:
            raise ValueError("frame lengths cannot be negative")
        if self.captured_length > self.original_length:
            raise ValueError("captured_length cannot exceed original_length")
        expected_subtype = SUBTYPE_BY_CODE.get(self.frame_subtype_code)
        if expected_subtype is not self.frame_subtype:
            raise ValueError("frame subtype name and code do not match")
        object.__setattr__(self, "observed_at", ensure_utc(self.observed_at))
        object.__setattr__(self, "ingested_at", ensure_utc(self.ingested_at))
        object.__setattr__(
            self,
            "parse_warnings",
            tuple(dict.fromkeys(self.parse_warnings)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize every contract key using JSON-compatible values."""

        return {
            "contract_version": self.contract_version,
            "frame_id": str(self.frame_id),
            "capture_session_id": str(self.capture_session_id),
            "capture_source": self.capture_source.value,
            "interface_name": self.interface_name,
            "packet_number": self.packet_number,
            "observed_at": datetime_to_rfc3339(self.observed_at),
            "ingested_at": datetime_to_rfc3339(self.ingested_at),
            "original_length": self.original_length,
            "captured_length": self.captured_length,
            "frame_type": self.frame_type.value,
            "frame_type_code": self.frame_type_code,
            "frame_subtype": self.frame_subtype.value,
            "frame_subtype_code": self.frame_subtype_code,
            "addresses": {
                "receiver_mac": self.addresses.receiver_mac,
                "transmitter_mac": self.addresses.transmitter_mac,
                "destination_mac": self.addresses.destination_mac,
                "source_mac": self.addresses.source_mac,
                "bssid": self.addresses.bssid,
                "transmitter_role_hint": (
                    self.addresses.transmitter_role_hint.value
                ),
            },
            "sequence": {
                "sequence_number": self.sequence.sequence_number,
                "fragment_number": self.sequence.fragment_number,
            },
            "flags": {
                "to_ds": self.flags.to_ds,
                "from_ds": self.flags.from_ds,
                "more_fragments": self.flags.more_fragments,
                "retry": self.flags.retry,
                "power_management": self.flags.power_management,
                "more_data": self.flags.more_data,
                "protected": self.flags.protected,
                "order": self.flags.order,
            },
            "radio": {
                "channel": self.radio.channel,
                "frequency_mhz": self.radio.frequency_mhz,
                "signal_dbm": self.radio.signal_dbm,
                "noise_dbm": self.radio.noise_dbm,
                "data_rate_mbps": self.radio.data_rate_mbps,
                "antenna_index": self.radio.antenna_index,
                "fcs_status": self.radio.fcs_status.value,
            },
            "management": {
                "ssid": self.management.ssid,
                "ssid_hex": self.management.ssid_hex,
                "ssid_state": self.management.ssid_state.value,
                "advertised_channel": self.management.advertised_channel,
                "reason_code": self.management.reason_code,
                "status_code": self.management.status_code,
                "authentication_algorithm": (
                    self.management.authentication_algorithm
                ),
                "authentication_sequence": (
                    self.management.authentication_sequence
                ),
                "beacon_interval_tu": self.management.beacon_interval_tu,
                "capability_privacy": self.management.capability_privacy,
                "information_elements_sha256": (
                    self.management.information_elements_sha256
                ),
                "security": (
                    self.management.security.to_dict()
                    if self.management.security
                    else None
                ),
            },
            "evidence": {
                "pcap_reference": self.evidence.pcap_reference,
                "frame_sha256": self.evidence.frame_sha256,
            },
            "parse_status": self.parse_status.value,
            "parse_warnings": list(self.parse_warnings),
        }

    def to_json(self) -> str:
        """Serialize the frame deterministically."""

        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

    def semantic_dict(self) -> dict[str, Any]:
        """Return values suitable for replay/live semantic comparison."""

        value = self.to_dict()
        value.pop("frame_id")
        value.pop("ingested_at")
        value.pop("capture_source")
        value.pop("interface_name")
        return value

    @classmethod
    def from_json(cls, value: str) -> NormalizedWirelessFrame:
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise ValueError("A normalized frame must be a JSON object")
        return cls.from_dict(parsed)

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
    ) -> NormalizedWirelessFrame:
        addresses = _mapping(value["addresses"], "addresses")
        sequence = _mapping(value["sequence"], "sequence")
        flags = _mapping(value["flags"], "flags")
        radio = _mapping(value["radio"], "radio")
        management = _mapping(value["management"], "management")
        evidence = _mapping(value["evidence"], "evidence")
        security_value = management.get("security")

        return cls(
            contract_version=str(value["contract_version"]),
            frame_id=UUID(str(value["frame_id"])),
            capture_session_id=UUID(str(value["capture_session_id"])),
            capture_source=CaptureSource(str(value["capture_source"])),
            interface_name=_optional_str(value.get("interface_name")),
            packet_number=int(value["packet_number"]),
            observed_at=datetime_from_rfc3339(str(value["observed_at"])),
            ingested_at=datetime_from_rfc3339(str(value["ingested_at"])),
            original_length=int(value["original_length"]),
            captured_length=int(value["captured_length"]),
            frame_type=FrameType(str(value["frame_type"])),
            frame_type_code=int(value["frame_type_code"]),
            frame_subtype=FrameSubtype(str(value["frame_subtype"])),
            frame_subtype_code=int(value["frame_subtype_code"]),
            addresses=MacAddresses(
                receiver_mac=str(addresses["receiver_mac"]),
                transmitter_mac=str(addresses["transmitter_mac"]),
                destination_mac=_optional_str(
                    addresses.get("destination_mac")
                ),
                source_mac=_optional_str(addresses.get("source_mac")),
                bssid=_optional_str(addresses.get("bssid")),
                transmitter_role_hint=TransmitterRoleHint(
                    str(addresses["transmitter_role_hint"])
                ),
            ),
            sequence=SequenceInfo(
                sequence_number=_optional_int(
                    sequence.get("sequence_number")
                ),
                fragment_number=_optional_int(
                    sequence.get("fragment_number")
                ),
            ),
            flags=FrameFlags(
                to_ds=bool(flags["to_ds"]),
                from_ds=bool(flags["from_ds"]),
                more_fragments=bool(flags["more_fragments"]),
                retry=bool(flags["retry"]),
                power_management=bool(flags["power_management"]),
                more_data=bool(flags["more_data"]),
                protected=bool(flags["protected"]),
                order=bool(flags["order"]),
            ),
            radio=RadioMetadata(
                channel=_optional_int(radio.get("channel")),
                frequency_mhz=_optional_int(radio.get("frequency_mhz")),
                signal_dbm=_optional_int(radio.get("signal_dbm")),
                noise_dbm=_optional_int(radio.get("noise_dbm")),
                data_rate_mbps=_optional_float(
                    radio.get("data_rate_mbps")
                ),
                antenna_index=_optional_int(radio.get("antenna_index")),
                fcs_status=FcsStatus(str(radio["fcs_status"])),
            ),
            management=ManagementFields(
                ssid=_optional_str(management.get("ssid")),
                ssid_hex=_optional_str(management.get("ssid_hex")),
                ssid_state=SsidState(str(management["ssid_state"])),
                advertised_channel=_optional_int(
                    management.get("advertised_channel")
                ),
                reason_code=_optional_int(management.get("reason_code")),
                status_code=_optional_int(management.get("status_code")),
                authentication_algorithm=_optional_int(
                    management.get("authentication_algorithm")
                ),
                authentication_sequence=_optional_int(
                    management.get("authentication_sequence")
                ),
                beacon_interval_tu=_optional_int(
                    management.get("beacon_interval_tu")
                ),
                capability_privacy=_optional_bool(
                    management.get("capability_privacy")
                ),
                information_elements_sha256=_optional_str(
                    management.get("information_elements_sha256")
                ),
                security=(
                    SecurityProfile.from_dict(
                        _mapping(security_value, "management.security")
                    )
                    if security_value is not None
                    else None
                ),
            ),
            evidence=EvidenceReference(
                pcap_reference=str(evidence["pcap_reference"]),
                frame_sha256=_optional_str(evidence.get("frame_sha256")),
            ),
            parse_status=ParseStatus(str(value["parse_status"])),
            parse_warnings=tuple(
                str(warning) for warning in value.get("parse_warnings", ())
            ),
        )


@dataclass(frozen=True, slots=True)
class ParserResult:
    """Categorized parser result for one packet."""

    disposition: ParserDisposition
    frame: NormalizedWirelessFrame | None
    reason: ParserReason | None
    detail: str

    def __post_init__(self) -> None:
        if self.disposition is ParserDisposition.ACCEPTED:
            if self.frame is None or self.reason is not None:
                raise ValueError("accepted results require only a frame")
        elif self.frame is not None or self.reason is None:
            raise ValueError("ignored/rejected results require only a reason")

    @classmethod
    def accepted(cls, frame: NormalizedWirelessFrame) -> ParserResult:
        return cls(ParserDisposition.ACCEPTED, frame, None, "")

    @classmethod
    def ignored(
        cls,
        reason: ParserReason,
        detail: str,
    ) -> ParserResult:
        return cls(ParserDisposition.IGNORED, None, reason, detail)

    @classmethod
    def rejected(
        cls,
        reason: ParserReason,
        detail: str,
    ) -> ParserResult:
        return cls(ParserDisposition.REJECTED, None, reason, detail)


@dataclass(frozen=True, slots=True)
class CaptureStatus:
    """Read-only snapshot of actual capture-worker state."""

    state: CaptureState
    source_mode: CaptureSource | None
    capture_session_id: UUID | None
    interface: str | None
    current_channel: int | None
    started_at: datetime | None
    heartbeat_at: datetime | None
    completed_at: datetime | None
    packets_seen: int
    packets_parsed: int
    packets_skipped: int
    parse_errors: int
    dropped_packets: int
    last_error: str | None
    reason_counts: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "packets_seen",
            "packets_parsed",
            "packets_skipped",
            "parse_errors",
            "dropped_packets",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        for name in ("started_at", "heartbeat_at", "completed_at"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, ensure_utc(value))
        object.__setattr__(
            self,
            "reason_counts",
            MappingProxyType(dict(self.reason_counts)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "source_mode": (
                self.source_mode.value if self.source_mode is not None else None
            ),
            "capture_session_id": (
                str(self.capture_session_id)
                if self.capture_session_id is not None
                else None
            ),
            "interface": self.interface,
            "current_channel": self.current_channel,
            "started_at": (
                datetime_to_rfc3339(self.started_at)
                if self.started_at is not None
                else None
            ),
            "heartbeat_at": (
                datetime_to_rfc3339(self.heartbeat_at)
                if self.heartbeat_at is not None
                else None
            ),
            "completed_at": (
                datetime_to_rfc3339(self.completed_at)
                if self.completed_at is not None
                else None
            ),
            "packets_seen": self.packets_seen,
            "packets_parsed": self.packets_parsed,
            "packets_skipped": self.packets_skipped,
            "parse_errors": self.parse_errors,
            "dropped_packets": self.dropped_packets,
            "last_error": self.last_error,
            "reason_counts": dict(self.reason_counts),
        }


def role_hint_for_subtype(subtype: FrameSubtype) -> TransmitterRoleHint:
    """Derive the contract-defined transmitter role hint."""

    if subtype in (FrameSubtype.BEACON, FrameSubtype.PROBE_RESPONSE):
        return TransmitterRoleHint.ACCESS_POINT
    if subtype is FrameSubtype.PROBE_REQUEST:
        return TransmitterRoleHint.STATION
    return TransmitterRoleHint.UNKNOWN


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


def _optional_bool(value: Any) -> bool | None:
    return None if value is None else bool(value)
