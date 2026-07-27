"""Generate small sanitized IEEE 802.11 management-frame PCAP fixtures."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import struct


OUTPUT = Path(__file__).with_name("lab_management_frames.pcap")
DLT_IEEE802_11_RADIO = 127
RADIOTAP_EMPTY = b"\x00\x00\x08\x00\x00\x00\x00\x00"
AP = bytes.fromhex("aabbccddeeff")
STATION = bytes.fromhex("112233445566")
BROADCAST = bytes.fromhex("ffffffffffff")


def management_header(
    frame_control: int,
    receiver: bytes,
    transmitter: bytes,
    bssid: bytes,
    sequence: int,
) -> bytes:
    return struct.pack(
        "<HH6s6s6sH",
        frame_control,
        0,
        receiver,
        transmitter,
        bssid,
        sequence << 4,
    )


def beacon() -> bytes:
    header = management_header(0x0080, BROADCAST, AP, AP, 100)
    fixed = struct.pack("<QHH", 0, 100, 0x0011)
    ssid = b"\x00\x08WIDS-Lab"
    channel = b"\x03\x01\x06"
    rsn_body = (
        b"\x01\x00"
        b"\x00\x0f\xac\x04"
        b"\x01\x00\x00\x0f\xac\x04"
        b"\x01\x00\x00\x0f\xac\x02"
        b"\x80\x00"
    )
    rsn = bytes((48, len(rsn_body))) + rsn_body
    return RADIOTAP_EMPTY + header + fixed + ssid + channel + rsn


def probe_request() -> bytes:
    header = management_header(
        0x0040,
        BROADCAST,
        STATION,
        BROADCAST,
        101,
    )
    return RADIOTAP_EMPTY + header + b"\x00\x00"


def authentication() -> bytes:
    header = management_header(0x00B0, AP, STATION, AP, 102)
    return RADIOTAP_EMPTY + header + struct.pack("<HHH", 0, 1, 0)


def deauthentication() -> bytes:
    header = management_header(0x00C0, STATION, AP, AP, 103)
    return RADIOTAP_EMPTY + header + struct.pack("<H", 7)


def disassociation() -> bytes:
    header = management_header(0x00A0, STATION, AP, AP, 104)
    return RADIOTAP_EMPTY + header + struct.pack("<H", 8)


def write_pcap(path: Path, packets: list[bytes]) -> None:
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        DLT_IEEE802_11_RADIO,
    )
    base = int(
        datetime(2026, 7, 27, 6, 31, 44, tzinfo=timezone.utc).timestamp()
    )
    with path.open("wb") as stream:
        stream.write(global_header)
        for index, packet in enumerate(packets):
            stream.write(
                struct.pack(
                    "<IIII",
                    base + index,
                    index * 1000,
                    len(packet),
                    len(packet),
                )
            )
            stream.write(packet)


def main() -> None:
    write_pcap(
        OUTPUT,
        [
            beacon(),
            probe_request(),
            authentication(),
            deauthentication(),
            disassociation(),
        ],
    )


if __name__ == "__main__":
    main()
