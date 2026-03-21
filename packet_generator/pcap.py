"""libpcap file writer.

This module writes raw packet bytes to a libpcap (``pcap``) file that can be
opened directly in Wireshark, tcpdump, or replayed with tcpreplay.

File format overview::

    Global header (24 bytes)
        magic_number  (4) — 0xA1B2C3D4, little-endian, microsecond timestamps
        version_major (2) — 2
        version_minor (2) — 4
        thiszone      (4) — 0 (UTC)
        sigfigs       (4) — 0
        snaplen       (4) — 65535
        network       (4) — link-layer type

    Per-packet record (16 bytes + data)
        ts_sec   (4) — capture timestamp, whole seconds
        ts_usec  (4) — capture timestamp, microseconds fraction
        incl_len (4) — number of bytes captured (= orig_len for complete packets)
        orig_len (4) — original packet length on the wire
        data     (incl_len bytes)

Constants:
    LINKTYPE_ETHERNET (int): Link-layer type ``1`` — Ethernet II.  Use for
        packets that include an Ethernet header.
    LINKTYPE_RAW (int): Link-layer type ``101`` — Raw IP.  Use for packets
        built with ``include_ethernet=False``.
"""
from __future__ import annotations

import os
import struct
import time
import io

LINKTYPE_ETHERNET: int = 1    # Ethernet II
LINKTYPE_RAW: int = 101       # Raw IP (no Ethernet header)


def _write_pcap(
    file_obj: io.IOBase,
    packets: list[tuple[bytes, int, int]],
    link_type: int) -> None:
    """Low level function
    """
    # Global header
    file_obj.write(struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic — little-endian, microsecond timestamps
        2, 4,        # version 2.4
        0,           # UTC
        0,           # timestamp accuracy (always 0)
        65535,       # snaplen
        link_type,
    ))
    for idx, pkt_tuple in enumerate(packets):
        pkt = pkt_tuple[0]
        sec = pkt_tuple[1]
        usec = pkt_tuple[2]
        length = len(pkt)
        file_obj.write(struct.pack("<IIII", sec, usec, length, length))
        file_obj.write(pkt)



def write_pcap(
    packets: list[tuple[bytes, int, int]],
    *,
    path: str | os.PathLike | None = None,
    file_object: io.IOBase | None = None,
    link_type: int = LINKTYPE_ETHERNET
) -> None:
    """Write raw packet bytes to a libpcap (``.pcap``) file.

    Args:
        packets: Ordered list of ``(raw packet byte strings, ts_sec, ts_usec)`` 
        — one per pcap record.  Each byte string is typically the return value of
            :meth:`PacketBuilder.build` or one fragment from
            :meth:`PacketBuilder.fragment`.
        path: Destination file path.  Created or overwritten.
        file_object: Destination file object.
        link_type: PCAP link-layer type written into the global header.
            Use :data:`LINKTYPE_ETHERNET` (``1``, default) for packets that
            include an Ethernet header, or :data:`LINKTYPE_RAW` (``101``) for
            raw IP packets built with ``include_ethernet=False``.

    Raises:
        ValueError: If *timestamps* is provided but its length differs from
            that of *packets*.
        OSError: If *path* cannot be opened for writing.

    Example::

        from packet_generator import PacketBuilder, Protocol, write_pcap

        now = time.time()
        now_sec, now_usec = (int(now), int((now -int(now)) * 1_000_000))
        pkts = [
            (PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP).build(), now_sec, now_usec),
            (PacketBuilder("10.0.0.2", "10.0.0.1", Protocol.TCP).build(), now_sec, now_usec + 1000)
        ]
        write_pcap("out.pcap", pkts)
    """
    if path is not None:
        with open(path, "wb") as f:
            _write_pcap(f, packets, link_type)
    if file_object is not None:
        _write_pcap(file_object, packets, link_type)            
