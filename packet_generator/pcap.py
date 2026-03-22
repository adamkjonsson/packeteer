"""libpcap file writer.

This module writes raw packet bytes to a libpcap (``pcap``) file that can be
opened directly in Wireshark, tcpdump, or replayed with tcpreplay.

File format overview::

    Global header (24 bytes)
        magic_number  (4) — 0xA1B2C3D4 (usec) or 0xA1B23C4D (nsec), little-endian
        version_major (2) — 2
        version_minor (2) — 4
        thiszone      (4) — 0 (UTC)
        sigfigs       (4) — 0
        snaplen       (4) — 65535
        network       (4) — link-layer type

    Per-packet record (16 bytes + data)
        ts_sec   (4) — capture timestamp, whole seconds
        ts_usec  (4) — capture timestamp, microseconds (usec) or nanoseconds (nsec) fraction
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

_MAGIC_USEC: int = 0xA1B2C3D4
_MAGIC_NSEC: int = 0xA1B23C4D


def _write_pcap(
    file_obj: io.IOBase,
    packets: list[tuple[bytes, int, int]],
    link_type: int,
    nanoseconds: bool,
) -> None:
    magic = _MAGIC_NSEC if nanoseconds else _MAGIC_USEC
    file_obj.write(struct.pack(
        "<IHHiIII",
        magic,
        2, 4,   # version 2.4
        0,      # UTC
        0,      # timestamp accuracy (always 0)
        65535,  # snaplen
        link_type,
    ))
    for pkt_tuple in packets:
        pkt = pkt_tuple[0]
        sec = pkt_tuple[1]
        frac = pkt_tuple[2]
        length = len(pkt)
        file_obj.write(struct.pack("<IIII", sec, frac, length, length))
        file_obj.write(pkt)


def write_pcap(
    packets: list[tuple[bytes, int, int]],
    *,
    path: str | os.PathLike | None = None,
    file_object: io.IOBase | None = None,
    link_type: int = LINKTYPE_ETHERNET,
    nanoseconds: bool = False,
) -> None:
    """Write raw packet bytes to a libpcap (``.pcap``) file.

    Args:
        packets: Ordered list of ``(raw_bytes, ts_sec, ts_frac)`` — one per
            pcap record.  *ts_frac* is microseconds when *nanoseconds* is
            ``False`` (default) or nanoseconds when *nanoseconds* is ``True``.
        path: Destination file path.  Created or overwritten.
        file_object: Destination file object.
        link_type: PCAP link-layer type written into the global header.
            Use :data:`LINKTYPE_ETHERNET` (``1``, default) for packets that
            include an Ethernet header, or :data:`LINKTYPE_RAW` (``101``) for
            raw IP packets built with ``include_ethernet=False``.
        nanoseconds: When ``True``, write magic ``0xA1B23C4D`` so readers
            interpret the timestamp fraction field as nanoseconds instead of
            the default microseconds (magic ``0xA1B2C3D4``).

    Raises:
        OSError: If *path* cannot be opened for writing.

    Example (nanosecond timestamps)::

        from packet_generator import PacketBuilder, Protocol, write_pcap

        now_ns = time.time_ns()
        now_sec, now_nsec = divmod(now_ns, 1_000_000_000)
        pkts = [
            (PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP).build(), now_sec, now_nsec),
        ]
        write_pcap(pkts, path="out.pcap", nanoseconds=True)
    """
    if path is not None:
        with open(path, "wb") as f:
            _write_pcap(f, packets, link_type, nanoseconds)
    if file_object is not None:
        _write_pcap(file_object, packets, link_type, nanoseconds)
