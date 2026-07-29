"""Defensive IEEE 802.11 management-frame normalization.

This is the only module allowed to access PyShark/Wireshark fields. The parser
also accepts packet-like test objects, which keeps contract tests deterministic
without requiring TShark.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from wids.capture.channel_manager import frequency_to_channel
from wids.capture.frame_models import (
    SUBTYPE_BY_CODE,
    EvidenceReference,
    FcsStatus,
    FrameFlags,
    FrameSubtype,
    MacAddresses,
    ManagementFields,
    NormalizedWirelessFrame,
    ParserReason,
    ParserResult,
    ParseStatus,
    RadioMetadata,
    SecurityClassification,
    SecurityProfile,
    SecurityProtocol,
    SequenceInfo,
    SsidState,
    ensure_utc,
    normalize_mac,
    role_hint_for_subtype,
    sha256_hex,
)
from wids.capture.packet_source import PacketEnvelope

_MISSING = object()
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_INT_RE = re.compile(r"-?\d+")
_FLOAT_RE = re.compile(r"-?(?:\d+(?:\.\d*)?|\.\d+)")

_CIPHER_TYPES: dict[int, str] = {
    0: "use_group",
    1: "wep_40",
    2: "tkip",
    4: "ccmp_128",
    5: "wep_104",
    6: "bip_cmac_128",
    8: "gcmp_128",
    9: "gcmp_256",
    10: "ccmp_256",
    11: "bip_gmac_128",
    12: "bip_gmac_256",
    13: "bip_cmac_256",
}
_AKM_TYPES: dict[int, str] = {
    1: "ieee8021x",
    2: "psk",
    3: "ft_ieee8021x",
    4: "ft_psk",
    5: "ieee8021x_sha256",
    6: "psk_sha256",
    8: "sae",
    9: "ft_sae",
    11: "ieee8021x_suite_b",
    12: "ieee8021x_suite_b_192",
    18: "owe",
}


class _ParserFailure(Exception):
    def __init__(self, reason: ParserReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class PacketParser:
    """Convert one packet envelope into the version 1 frame contract."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def parse(self, envelope: PacketEnvelope) -> ParserResult:
        """Parse safely; no per-packet exception escapes this boundary."""

        try:
            return self._parse(envelope)
        except _ParserFailure as error:
            return ParserResult.rejected(error.reason, error.detail)
        except Exception as error:  # noqa: BLE001 - per-packet safety boundary
            return ParserResult.rejected(
                ParserReason.PARSER_ERROR,
                f"Unexpected parser error: {type(error).__name__}",
            )

    def _parse(self, envelope: PacketEnvelope) -> ParserResult:
        packet = envelope.packet
        wlan = _layer(packet, "wlan")
        if wlan is None:
            return ParserResult.ignored(
                ParserReason.NOT_IEEE80211,
                "Packet has no IEEE 802.11 layer.",
            )

        frame_type = _parse_int(
            _field(wlan, "fc_type", "type", "wlan_fc_type")
        )
        if frame_type is None:
            raise _ParserFailure(
                ParserReason.MALFORMED_REQUIRED_FIELD,
                "IEEE 802.11 frame type is missing or malformed.",
            )
        if frame_type != 0:
            return ParserResult.ignored(
                ParserReason.OUT_OF_SCOPE_FRAME_TYPE,
                "Contract version 1 accepts management frames only.",
            )

        subtype_code = _parse_int(
            _field(wlan, "fc_subtype", "subtype", "wlan_fc_subtype")
        )
        if subtype_code is None:
            raise _ParserFailure(
                ParserReason.MALFORMED_REQUIRED_FIELD,
                "Management-frame subtype is missing or malformed.",
            )
        subtype = SUBTYPE_BY_CODE.get(subtype_code)
        if subtype is None:
            return ParserResult.ignored(
                ParserReason.UNSUPPORTED_SUBTYPE,
                f"Unsupported management-frame subtype code {subtype_code}.",
            )

        original_length, captured_length = _frame_lengths(packet)
        if _is_explicitly_truncated(packet) or (
            captured_length > 0 and captured_length < 24
        ):
            raise _ParserFailure(
                ParserReason.TRUNCATED_MANAGEMENT_HEADER,
                "The management header is truncated.",
            )

        radio = _radio_metadata(packet)
        if radio.fcs_status is FcsStatus.INVALID:
            raise _ParserFailure(
                ParserReason.INVALID_FCS,
                "The capture adapter explicitly reported an invalid FCS.",
            )

        warnings: list[str] = []
        partial = False
        receiver_raw = _field(wlan, "ra", "receiver", "addr1")
        transmitter_raw = _field(wlan, "ta", "transmitter", "addr2")
        if _is_missing(receiver_raw):
            raise _ParserFailure(
                ParserReason.MISSING_RECEIVER_ADDRESS,
                "Receiver address is unavailable.",
            )
        if _is_missing(transmitter_raw):
            raise _ParserFailure(
                ParserReason.MISSING_TRANSMITTER_ADDRESS,
                "Transmitter address is unavailable.",
            )

        try:
            receiver = normalize_mac(_text(receiver_raw))
            transmitter = normalize_mac(_text(transmitter_raw))
        except ValueError as error:
            raise _ParserFailure(
                ParserReason.INVALID_MAC_ADDRESS,
                "A required management-frame address is invalid.",
            ) from error

        destination, invalid = _optional_mac(
            _field(wlan, "da", "destination", "addr1"),
            fallback=receiver,
        )
        if invalid:
            warnings.append("invalid_destination_address")
            partial = True
        source, invalid = _optional_mac(
            _field(wlan, "sa", "source", "addr2"),
            fallback=transmitter,
        )
        if invalid:
            warnings.append("invalid_source_address")
            partial = True
        bssid, invalid = _optional_mac(_field(wlan, "bssid", "addr3"))
        if invalid:
            warnings.append("invalid_bssid")
            partial = True

        sequence_number = _parse_int(
            _field(wlan, "seq", "sequence_number", "wlan_seq")
        )
        fragment_number = _parse_int(
            _field(wlan, "frag", "fragment_number", "wlan_frag")
        )
        if sequence_number is None or fragment_number is None:
            sequence_number = None
            fragment_number = None
            warnings.append("missing_sequence_control")
            partial = True

        flags = FrameFlags(
            to_ds=_parse_bool(_field(wlan, "fc_to_ds", "to_ds")) or False,
            from_ds=_parse_bool(_field(wlan, "fc_from_ds", "from_ds")) or False,
            more_fragments=(
                _parse_bool(_field(wlan, "fc_more_frag", "more_fragments"))
                or False
            ),
            retry=_parse_bool(_field(wlan, "fc_retry", "retry")) or False,
            power_management=(
                _parse_bool(_field(wlan, "fc_pwrmgt", "power_management"))
                or False
            ),
            more_data=(
                _parse_bool(_field(wlan, "fc_moredata", "more_data")) or False
            ),
            protected=(
                _parse_bool(_field(wlan, "fc_protected", "protected")) or False
            ),
            order=_parse_bool(_field(wlan, "fc_order", "order")) or False,
        )

        management_layer = _layer(packet, "wlan_mgt")
        if management_layer is None:
            management_layer = wlan
        management, management_warnings = _management_fields(
            management_layer,
            wlan,
            subtype,
            radio,
        )
        warnings.extend(management_warnings)
        if management_warnings:
            partial = True

        required_warnings = _missing_subtype_values(
            subtype,
            bssid=bssid,
            radio=radio,
            management=management,
        )
        warnings.extend(required_warnings)
        if required_warnings:
            partial = True

        if (
            radio.channel is not None
            and management.advertised_channel is not None
            and radio.channel != management.advertised_channel
        ):
            warnings.append("channel_mismatch")

        observed_at = _observed_at(packet)
        raw_frame = _ieee80211_bytes(packet)
        frame = NormalizedWirelessFrame(
            capture_session_id=envelope.capture_session_id,
            capture_source=envelope.capture_source,
            interface_name=envelope.interface_name,
            packet_number=envelope.packet_number,
            observed_at=observed_at,
            ingested_at=ensure_utc(self._clock()),
            original_length=original_length,
            captured_length=captured_length,
            frame_subtype=subtype,
            frame_subtype_code=subtype_code,
            addresses=MacAddresses(
                receiver_mac=receiver,
                transmitter_mac=transmitter,
                destination_mac=destination,
                source_mac=source,
                bssid=bssid,
                transmitter_role_hint=role_hint_for_subtype(subtype),
            ),
            sequence=SequenceInfo(
                sequence_number=sequence_number,
                fragment_number=fragment_number,
            ),
            flags=flags,
            radio=radio,
            management=management,
            evidence=EvidenceReference(
                pcap_reference=envelope.pcap_reference,
                frame_sha256=sha256_hex(raw_frame) if raw_frame else None,
            ),
            parse_status=(
                ParseStatus.PARTIAL if partial else ParseStatus.COMPLETE
            ),
            parse_warnings=tuple(warnings),
        )
        return ParserResult.accepted(frame)


def _management_fields(
    management_layer: Any,
    wlan: Any,
    subtype: FrameSubtype,
    radio: RadioMetadata,
) -> tuple[ManagementFields, list[str]]:
    warnings: list[str] = []
    sources = (management_layer, wlan)
    def management_value(*names: str) -> Any:
        return _first_field(sources, names)
        
    ssid, ssid_hex, ssid_state, ssid_warning = _ssid_fields(
        management_layer,
        wlan,
        subtype,
    )
    if ssid_warning:
        warnings.append(ssid_warning)

    advertised_channel = _parse_int(
        _field(
            management_layer,
            "ds_current_channel",
            "current_channel",
            "advertised_channel",
            "tagged_current_channel",
        )
    )
    reason_code = _parse_int(
        _field(management_layer, "fixed_reason_code", "reason_code")
    )
    status_code = _parse_int(
        _field(management_layer, "fixed_status_code", "status_code")
    )
    auth_algorithm = _parse_int(
        _field(
            management_layer,
            "fixed_auth_alg",
            "authentication_algorithm",
            "auth_alg",
        )
    )
    auth_sequence = _parse_int(
        _field(
            management_layer,
            "fixed_auth_seq",
            "authentication_sequence",
            "auth_seq",
        )
    )
    beacon_interval = _parse_int(
        _field(
            management_layer,
            "fixed_beacon",
            "beacon_interval",
            "beacon_interval_tu",
        )
    )
    privacy = _parse_bool(
        _field(
            management_layer,
            "fixed_capabilities_privacy",
            "capabilities_privacy",
            "capability_privacy",
        )
    )

    malformed_rsn = _parse_bool(
        _field(
            management_layer,
            "malformed_rsn",
            "rsn_malformed",
            "_ws_malformed",
        )
    )
    security: SecurityProfile | None = None
    if subtype in (FrameSubtype.BEACON, FrameSubtype.PROBE_RESPONSE):
        if malformed_rsn:
            warnings.append("malformed_rsn_ie")
        else:
            try:
                security = _security_profile(management_layer, privacy)

                if security is None and management_layer is not wlan:
                    security = _security_profile(wlan, privacy)

            except (TypeError, ValueError):
                warnings.append("malformed_rsn_ie")

    ie_fingerprint = _information_elements_fingerprint(
        management_layer,
        ssid_hex=ssid_hex,
        advertised_channel=advertised_channel,
        beacon_interval=beacon_interval,
        privacy=privacy,
        security=security,
    )

    return (
        ManagementFields(
            ssid=ssid,
            ssid_hex=ssid_hex,
            ssid_state=ssid_state,
            advertised_channel=advertised_channel,
            reason_code=reason_code,
            status_code=status_code,
            authentication_algorithm=auth_algorithm,
            authentication_sequence=auth_sequence,
            beacon_interval_tu=beacon_interval,
            capability_privacy=privacy,
            information_elements_sha256=ie_fingerprint,
            security=security,
        ),
        warnings,
    )


def _ssid_fields(
    management_layer: Any,
    wlan: Any,
    subtype: FrameSubtype,
) -> tuple[str | None, str | None, SsidState, str | None]:
    sources = (management_layer, wlan)

    raw_field = _first_field(
        sources,
        (
            "ssid_raw",
            "tag_ssid_raw",
            "wlan_ssid_raw",
        ),
    )

    display_field = _first_field(
        sources,
        (
            "ssid",
            "tag_ssid",
            "wlan_ssid",
            "wlan.ssid",
        ),
    )

    if _is_missing(raw_field) and _is_missing(display_field):
        return None, None, SsidState.ABSENT, None

    ssid_bytes = (
        _field_bytes(raw_field, raw_is_hex=True)
        if not _is_missing(raw_field)
        else _field_bytes(display_field, raw_is_hex=False)
    )

    if ssid_bytes is None:
        return None, None, SsidState.ABSENT, "malformed_ssid_ie"

    ssid_hex = ssid_bytes.hex()

    if not ssid_bytes:
        state = (
            SsidState.WILDCARD
            if subtype is FrameSubtype.PROBE_REQUEST
            else SsidState.HIDDEN
        )
        return None, "", state, None

    if len(ssid_bytes) > 32:
        return None, None, SsidState.ABSENT, "invalid_ssid_length"

    try:
        return (
            ssid_bytes.decode("utf-8"),
            ssid_hex,
            SsidState.PRESENT,
            None,
        )
    except UnicodeDecodeError:
        return None, ssid_hex, SsidState.INVALID_UTF8, None


def _security_profile(
    layer: Any,
    privacy: bool | None,
) -> SecurityProfile | None:
    direct_protocol_values = _field_values(
        _field(layer, "security_protocols", "protocols")
    )
    direct_classification = _optional_text(
        _field(layer, "security_classification", "classification")
    )

    rsn_present = _has_any_field(
        layer,
        (
            "wlan.rsn.version",
            "wlan_rsn_version",
            "rsn_version",
            "rsn_group_cipher",
            "rsn_pairwise_cipher",
            "rsn_akm",
            "rsn_akms_type",
        ),
    )
    wpa_present = _has_any_field(
        layer,
        (
            "wpa_version",
            "wpa_group_cipher",
            "wpa_pairwise_cipher",
            "wpa_akm",
        ),
    )

    pairwise_values = _field_values(
        _field(
            layer,
            "wlan.rsn.pcs.type",
            "wlan_rsn_pcs_type",
            "pairwise_ciphers",
            "rsn_pairwise_cipher",
            "rsn_pcs_type",
            "wpa_pairwise_cipher",
        )
    )
    akm_values = _field_values(
        _field(
            layer,
            "wlan.rsn.akms.type",
            "wlan_rsn_akms_type",
            "akm_suites",
            "rsn_akm",
            "rsn_akms_type",
            "wpa_akm",
        )
    )
    group_values = _field_values(
        _field(
            layer,
            "wlan.rsn.gcs.type",
            "wlan_rsn_gcs_type",
            "group_cipher",
            "rsn_group_cipher",
            "rsn_gcs_type",
            "wpa_group_cipher",
        )
    )

    pairwise = tuple(
        dict.fromkeys(_canonical_suite(value, _CIPHER_TYPES) for value in pairwise_values)
    )
    akms = tuple(
        dict.fromkeys(_canonical_suite(value, _AKM_TYPES) for value in akm_values)
    )
    group = (
        _canonical_suite(group_values[0], _CIPHER_TYPES)
        if group_values
        else None
    )

    protocols: set[SecurityProtocol] = set()
    for value in direct_protocol_values:
        normalized = _canonical_token(value)
        if normalized in {"wpa", "wpa2", "wpa3"}:
            protocols.add(SecurityProtocol(normalized))
    if wpa_present:
        protocols.add(SecurityProtocol.WPA)
    if rsn_present:
        if any(akm in {"sae", "ft_sae", "owe"} for akm in akms):
            protocols.add(SecurityProtocol.WPA3)
        if not akms or any(
            akm
            not in {
                "sae",
                "ft_sae",
                "owe",
            }
            for akm in akms
        ):
            protocols.add(SecurityProtocol.WPA2)

    if direct_classification:
        classification = SecurityClassification(
            _canonical_token(direct_classification)
        )
    elif len(protocols) > 1:
        classification = SecurityClassification.MIXED
    elif SecurityProtocol.WPA3 in protocols:
        classification = SecurityClassification.WPA3
    elif SecurityProtocol.WPA2 in protocols:
        classification = SecurityClassification.WPA2
    elif SecurityProtocol.WPA in protocols:
        classification = SecurityClassification.WPA
    elif privacy is False:
        classification = SecurityClassification.OPEN
    elif privacy is True:
        classification = SecurityClassification.WEP_OR_LEGACY
    else:
        return None

    pmf_capable = _parse_bool(
        _field(
            layer,
            "wlan.rsn.capabilities.mfpc",
            "wlan_rsn_capabilities_mfpc",
            "pmf_capable",
            "rsn_capabilities_mfpc",
            "rsn_mfpc",
        )
    )
    pmf_required = _parse_bool(
        _field(
            layer,
            "wlan.rsn.capabilities.mfpr",
            "wlan_rsn_capabilities_mfpr",
            "pmf_required",
            "rsn_capabilities_mfpr",
            "rsn_mfpr",
        )
    )
    return SecurityProfile(
        classification=classification,
        protocols=tuple(protocols),
        group_cipher=group,
        pairwise_ciphers=pairwise,
        akm_suites=akms,
        pmf_capable=pmf_capable,
        pmf_required=pmf_required,
    )


def _information_elements_fingerprint(
    layer: Any,
    *,
    ssid_hex: str | None,
    advertised_channel: int | None,
    beacon_interval: int | None,
    privacy: bool | None,
    security: SecurityProfile | None,
) -> str | None:
    """Fingerprint a documented stable IE sequence.

    If the dissector exposes a pre-canonicalized stable IE byte sequence, it is
    hashed directly. Otherwise the stable semantic sequence is canonical JSON:
    SSID bytes, advertised channel, beacon interval, privacy capability, and
    the normalized security fingerprint. Volatile timestamp/TIM values are
    intentionally absent.
    """

    stable_raw = _field(
        layer,
        "stable_information_elements",
        "stable_information_elements_raw",
    )
    if not _is_missing(stable_raw):
        raw_bytes = _field_bytes(stable_raw, raw_is_hex=True)
        if raw_bytes is not None:
            return sha256_hex(raw_bytes)

    payload = {
        "advertised_channel": advertised_channel,
        "beacon_interval_tu": beacon_interval,
        "capability_privacy": privacy,
        "security_fingerprint": (
            security.fingerprint_sha256 if security is not None else None
        ),
        "ssid_hex": ssid_hex,
    }
    if all(value is None for value in payload.values()):
        return None
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256_hex(serialized)


def _radio_metadata(packet: Any) -> RadioMetadata:
    radiotap = _layer(packet, "radiotap")
    radio = _layer(packet, "wlan_radio")
    source = radio if radio is not None else radiotap

    frequency = _parse_int(
        _first_field(
            (radio, radiotap),
            (
                "frequency",
                "frequency_mhz",
                "channel_freq",
                "channel_frequency",
            ),
        )
    )
    channel = _parse_int(
        _first_field(
            (radio, radiotap),
            ("channel", "channel_number"),
        )
    )
    if channel is None and frequency is not None:
        channel = frequency_to_channel(frequency)
    signal = _parse_int(
        _first_field(
            (source, radiotap),
            ("signal_dbm", "dbm_antsignal", "signal"),
        )
    )
    noise = _parse_int(
        _first_field(
            (source, radiotap),
            ("noise_dbm", "dbm_antnoise", "noise"),
        )
    )
    data_rate = _parse_float(
        _first_field(
            (source, radiotap),
            ("data_rate", "data_rate_mbps", "datarate"),
        )
    )
    antenna = _parse_int(
        _first_field((source, radiotap), ("antenna", "antenna_index"))
    )

    fcs_status = FcsStatus.UNKNOWN
    explicit_status = _optional_text(
        _first_field(
            (radiotap, _layer(packet, "wlan")),
            ("fcs_status", "fcs.status"),
        )
    )
    bad_fcs = _parse_bool(
        _first_field(
            (radiotap, _layer(packet, "wlan")),
            ("flags_badfcs", "bad_fcs", "fcs_bad"),
        )
    )
    if bad_fcs is True:
        fcs_status = FcsStatus.INVALID
    elif explicit_status:
        normalized = explicit_status.lower()
        if any(word in normalized for word in ("bad", "invalid", "failed")):
            fcs_status = FcsStatus.INVALID
        elif any(word in normalized for word in ("good", "valid", "passed")):
            fcs_status = FcsStatus.VALID
        elif "not" in normalized and "present" in normalized:
            fcs_status = FcsStatus.NOT_PRESENT

    return RadioMetadata(
        channel=_bounded(channel, 1, 233),
        frequency_mhz=frequency if frequency and frequency > 0 else None,
        signal_dbm=_bounded(signal, -127, 0),
        noise_dbm=_bounded(noise, -127, 0),
        data_rate_mbps=(
            data_rate
            if data_rate is not None
            and math.isfinite(data_rate)
            and data_rate > 0
            else None
        ),
        antenna_index=antenna if antenna is not None and antenna >= 0 else None,
        fcs_status=fcs_status,
    )


def _missing_subtype_values(
    subtype: FrameSubtype,
    *,
    bssid: str | None,
    radio: RadioMetadata,
    management: ManagementFields,
) -> list[str]:
    warnings: list[str] = []
    if subtype in {
        FrameSubtype.BEACON,
        FrameSubtype.PROBE_RESPONSE,
        FrameSubtype.AUTHENTICATION,
        FrameSubtype.DEAUTHENTICATION,
        FrameSubtype.DISASSOCIATION,
    } and bssid is None:
        warnings.append("missing_bssid")

    if subtype in {FrameSubtype.BEACON, FrameSubtype.PROBE_RESPONSE}:
        if management.ssid_state is SsidState.ABSENT:
            warnings.append("missing_ssid_element")
        if (
            management.advertised_channel is None
            and radio.channel is None
        ):
            warnings.append("missing_channel")
        if management.security is None:
            warnings.append("missing_security_profile")
    if subtype is FrameSubtype.BEACON and management.beacon_interval_tu is None:
        warnings.append("missing_beacon_interval")
    if (
        subtype is FrameSubtype.PROBE_REQUEST
        and management.ssid_state is SsidState.ABSENT
    ):
        warnings.append("missing_ssid_element")
    if subtype is FrameSubtype.AUTHENTICATION:
        if management.authentication_algorithm is None:
            warnings.append("missing_authentication_algorithm")
        if management.authentication_sequence is None:
            warnings.append("missing_authentication_sequence")
    if subtype in {
        FrameSubtype.DEAUTHENTICATION,
        FrameSubtype.DISASSOCIATION,
    } and management.reason_code is None:
        warnings.append("missing_reason_code")
    return warnings


def _frame_lengths(packet: Any) -> tuple[int, int]:
    frame_info = _layer(packet, "frame_info")
    if frame_info is None:
        frame_info = _layer(packet, "frame")
    original = _parse_int(
        _first_field(
            (frame_info, packet),
            ("len", "length", "original_length"),
        )
    )
    captured = _parse_int(
        _first_field(
            (frame_info, packet),
            ("cap_len", "captured_length", "capture_length"),
        )
    )
    raw = _raw_packet(packet)
    if captured is None and raw is not None:
        captured = len(raw)
    if original is None:
        original = captured
    if captured is None:
        captured = original
    original = max(int(original or 0), 0)
    captured = max(int(captured or 0), 0)
    if captured > original:
        original = captured
    return original, captured


def _observed_at(packet: Any) -> datetime:
    value = _field(packet, "sniff_time")
    if isinstance(value, datetime):
        return ensure_utc(value)

    epoch = _parse_float(
        _first_field(
            (packet, _layer(packet, "frame_info"), _layer(packet, "frame")),
            ("sniff_timestamp", "time_epoch"),
        )
    )
    if epoch is not None and math.isfinite(epoch):
        return datetime.fromtimestamp(epoch, tz=UTC)

    text = _optional_text(value)
    if text:
        try:
            return ensure_utc(
                datetime.fromisoformat(text.replace("Z", "+00:00"))
            )
        except ValueError:
            pass
    raise _ParserFailure(
        ParserReason.MALFORMED_REQUIRED_FIELD,
        "Packet timestamp is missing or malformed.",
    )


def _is_explicitly_truncated(packet: Any) -> bool:
    value = _first_field(
        (packet, _layer(packet, "frame_info"), _layer(packet, "frame")),
        ("truncated", "is_truncated", "packet_truncated"),
    )
    return _parse_bool(value) is True


def _ieee80211_bytes(packet: Any) -> bytes | None:
    wlan_raw = _field(packet, "wlan_raw", "ieee80211_raw")
    if not _is_missing(wlan_raw):
        raw = _field_bytes(wlan_raw, raw_is_hex=True)
        if raw:
            return raw

    raw = _raw_packet(packet)
    if not raw:
        return None
    if _layer(packet, "radiotap") is not None and len(raw) >= 4:
        radiotap_length = int.from_bytes(raw[2:4], "little")
        if 4 <= radiotap_length < len(raw):
            return raw[radiotap_length:]
    return raw


def _raw_packet(packet: Any) -> bytes | None:
    getter = getattr(packet, "get_raw_packet", None)
    if callable(getter):
        try:
            value = getter()
        except (AssertionError, AttributeError, RuntimeError, TypeError):
            return None
        if isinstance(value, bytes):
            return value
    value = _field(packet, "raw_packet")
    return value if isinstance(value, bytes) else None


def _optional_mac(
    value: Any,
    *,
    fallback: str | None = None,
) -> tuple[str | None, bool]:
    if _is_missing(value):
        return fallback, False
    try:
        return normalize_mac(_text(value)), False
    except ValueError:
        return None, True


def _canonical_suite(value: str, table: dict[int, str]) -> str:
    normalized = _canonical_token(value)
    if normalized in table.values():
        return normalized
    numeric = _parse_int(value)
    if numeric is not None and numeric in table:
        return table[numeric]
    selector = re.search(
        r"(?P<oui>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){2})"
        r"[:\-\s]+(?P<type>\d+)",
        value,
    )
    if selector:
        oui = selector.group("oui").replace(":", "").lower()
        return f"unknown_{oui}_{selector.group('type')}"
    return normalized or "unknown_value"


def _canonical_token(value: str) -> str:
    token = re.sub(r"[^a-zA-Z0-9]+", "_", str(value)).strip("_").lower()
    aliases = {
        "ccmp": "ccmp_128",
        "aes_ccm": "ccmp_128",
        "802_1x": "ieee8021x",
        "ieee_802_1x": "ieee8021x",
        "wpa_2": "wpa2",
        "wpa_3": "wpa3",
    }
    return aliases.get(token, token)


def _bounded(value: int | None, minimum: int, maximum: int) -> int | None:
    if value is None or not minimum <= value <= maximum:
        return None
    return value


def _layer(packet: Any, name: str) -> Any | None:
    value = _field(packet, name)
    if not _is_missing(value):
        return value
    layers = getattr(packet, "layers", ())
    try:
        for layer in layers:
            layer_name = getattr(layer, "layer_name", None)
            if str(layer_name).lower() == name:
                return layer
    except TypeError:
        return None
    return None


def _first_field(objects: Iterable[Any | None], names: tuple[str, ...]) -> Any:
    for item in objects:
        if item is None:
            continue
        value = _field(item, *names)
        if not _is_missing(value):
            return value
    return _MISSING


def _field(item: Any, *names: str) -> Any:
    if item is None:
        return _MISSING
    for name in names:
        variants = (name, name.replace(".", "_"))
        for variant in variants:
            if isinstance(item, dict) and variant in item:
                return item[variant]
            try:
                value = getattr(item, variant)
            except (AttributeError, KeyError):
                value = _MISSING
            if not _is_missing(value):
                return value
            getter = getattr(item, "get_field", None)
            if callable(getter):
                try:
                    value = getter(variant)
                except (AttributeError, KeyError, TypeError):
                    value = _MISSING
                if not _is_missing(value):
                    return value
    return _MISSING


def _is_missing(value: Any) -> bool:
    return value is _MISSING or value is None


def _text(value: Any) -> str:
    if _is_missing(value):
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    for name in ("show", "showname_value", "value"):
        candidate = getattr(value, name, None)
        if candidate is not None and candidate is not value:
            return str(candidate)
    return str(value)


def _optional_text(value: Any) -> str | None:
    if _is_missing(value):
        return None
    text = _text(value).strip()
    return text or None


def _parse_int(value: Any) -> int | None:
    if _is_missing(value):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else None
    text = _text(value).strip()
    try:
        if text.lower().startswith(("0x", "-0x")):
            return int(text, 16)
    except ValueError:
        return None
    match = _INT_RE.search(text)
    return int(match.group()) if match else None


def _parse_float(value: Any) -> float | None:
    if _is_missing(value):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        return number if math.isfinite(number) else None
    match = _FLOAT_RE.search(_text(value))
    if not match:
        return None
    number = float(match.group())
    return number if math.isfinite(number) else None


def _parse_bool(value: Any) -> bool | None:
    if _is_missing(value):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = _text(value).strip().lower()
    if normalized in {"1", "true", "yes", "set", "enabled", "on"}:
        return True
    if normalized in {"0", "false", "no", "not set", "disabled", "off"}:
        return False
    if "not set" in normalized:
        return False
    return None


def _field_bytes(value: Any, *, raw_is_hex: bool) -> bytes | None:
    if _is_missing(value):
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)

    raw_value = getattr(value, "raw_value", _MISSING)
    if not _is_missing(raw_value):
        decoded = _decode_hex(_text(raw_value))
        if decoded is not None:
            return decoded

    text = _text(value)
    if raw_is_hex:
        decoded = _decode_hex(text)
        if decoded is not None:
            return decoded
    return text.encode("utf-8")


def _decode_hex(value: str) -> bytes | None:
    compact = re.sub(r"[:\-\s]", "", value)
    if not compact:
        return b""
    if len(compact) % 2 or not _HEX_RE.fullmatch(compact):
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def _field_values(value: Any) -> list[str]:
    if _is_missing(value):
        return []
    all_fields = getattr(value, "all_fields", None)
    if all_fields:
        return [_text(item) for item in all_fields]
    if isinstance(value, (list, tuple, set)):
        return [_text(item) for item in value]
    text = _text(value)
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text] if text.strip() else []


def _has_any_field(layer: Any, names: tuple[str, ...]) -> bool:
    return any(not _is_missing(_field(layer, name)) for name in names)
