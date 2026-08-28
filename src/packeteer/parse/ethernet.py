from __future__ import annotations

import struct

from packeteer.generate.ethernet import (
    ETHERNET_MIN_FRAME_SIZE,
    ETHERTYPE_8021Q,
    EthernetHeader,
    VLANTag,
)


def packet_parser(data: bytes) -> tuple[int, int | None, EthernetHeader | None]:
    """Parse an Ethernet II frame header from raw bytes.

    Handles both plain 14-byte headers and 18-byte headers that include an
    IEEE 802.1Q VLAN tag.

    A frame shorter than the 60-byte Ethernet minimum was captured before a
    sender's padding was added — padding is applied by the hardware, so a
    capture taken above the driver never sees it.  The returned header records
    that with ``pad=False``, so rebuilding the frame reproduces its captured
    length instead of padding it out.

    Args:
        data: Raw bytes whose first bytes form an Ethernet header.  The whole
            frame, not just the header: its length is what decides *pad*.

    Returns:
        A tuple of ``(header_size, next_protocol, header)`` where
        *header_size* is the number of bytes consumed (14 or 18),
        *next_protocol* is the EtherType of the encapsulated protocol, and
        *header* is the parsed :class:`EthernetHeader` object.
        Returns ``(0, None, None)`` if parsing fails.

    """
    if len(data) < 14:
        return (0, None, None)

    pad = len(data) >= ETHERNET_MIN_FRAME_SIZE

    try:
        dst_bytes = data[0:6]
        src_bytes = data[6:12]
        ethertype = struct.unpack("!H", data[12:14])[0]

        dst_mac = ":".join(f"{b:02x}" for b in dst_bytes)
        src_mac = ":".join(f"{b:02x}" for b in src_bytes)

        if ethertype == ETHERTYPE_8021Q:
            if len(data) < 18:
                return (0, None, None)
            tci = struct.unpack("!H", data[14:16])[0]
            inner_ethertype = struct.unpack("!H", data[16:18])[0]
            pcp = (tci >> 13) & 0x7
            dei = (tci >> 12) & 0x1
            vid = tci & 0xFFF
            outer_tag = VLANTag(vid=vid, pcp=pcp, dei=dei)

            if inner_ethertype == ETHERTYPE_8021Q:
                # QinQ (802.1ad): parse the inner VLAN tag as well.
                if len(data) < 22:
                    return (0, None, None)
                inner_tci = struct.unpack("!H", data[18:20])[0]
                final_ethertype = struct.unpack("!H", data[20:22])[0]
                inner_vid = inner_tci & 0xFFF
                inner_pcp = (inner_tci >> 13) & 0x7
                inner_dei = (inner_tci >> 12) & 0x1
                hdr = EthernetHeader(
                    dst_mac=dst_mac,
                    src_mac=src_mac,
                    ethertype=final_ethertype,
                    vlan_tag=outer_tag,
                    inner_vlan_tag=VLANTag(vid=inner_vid, pcp=inner_pcp, dei=inner_dei),
                    pad=pad,
                )
                return (22, final_ethertype, hdr)

            hdr = EthernetHeader(
                dst_mac=dst_mac,
                src_mac=src_mac,
                ethertype=inner_ethertype,
                vlan_tag=outer_tag,
                pad=pad,
            )
            return (18, inner_ethertype, hdr)

        hdr = EthernetHeader(
            dst_mac=dst_mac, src_mac=src_mac, ethertype=ethertype, pad=pad,
        )
        return (14, ethertype, hdr)

    except struct.error:
        return (0, None, None)
