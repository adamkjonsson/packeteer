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

LINKTYPE_ETHERNET: int = 1    # Ethernet II
LINKTYPE_RAW: int = 101       # Raw IP (no Ethernet header)


def write_pcap(
    path: str | os.PathLike,
    packets: list[bytes],
    *,
    link_type: int = LINKTYPE_ETHERNET,
    ts_sec: int | None = None,
    ts_usec: int = 0,
    timestamps: list[tuple[int, int]] | None = None,
) -> None:
    """Write raw packet bytes to a libpcap (``.pcap``) file.

    Args:
        path: Destination file path.  Created or overwritten.
        packets: Ordered list of raw packet byte strings — one per pcap
            record.  Each element is typically the return value of
            :meth:`PacketBuilder.build` or one fragment from
            :meth:`PacketBuilder.fragment`.
        link_type: PCAP link-layer type written into the global header.
            Use :data:`LINKTYPE_ETHERNET` (``1``, default) for packets that
            include an Ethernet header, or :data:`LINKTYPE_RAW` (``101``) for
            raw IP packets built with ``include_ethernet=False``.
        ts_sec: Capture timestamp — whole seconds — applied to every record.
            Defaults to the current wall-clock time.  Ignored when
            *timestamps* is provided.
        ts_usec: Capture timestamp — microseconds fraction (0–999 999) —
            applied to every record alongside *ts_sec*.  Defaults to ``0``.
            Ignored when *timestamps* is provided.
        timestamps: Per-packet list of ``(ts_sec, ts_usec)`` tuples.  When
            supplied it must have the same length as *packets* and takes
            precedence over *ts_sec* / *ts_usec*.  Use this to assign
            distinct capture times to each packet.

    Raises:
        ValueError: If *timestamps* is provided but its length differs from
            that of *packets*.
        OSError: If *path* cannot be opened for writing.

    Example — shared timestamp::

        from packet_generator import PacketBuilder, Protocol, write_pcap

        pkts = [
            PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP).build(),
            PacketBuilder("10.0.0.2", "10.0.0.1", Protocol.TCP).build(),
        ]
        write_pcap("out.pcap", pkts)

    Example — per-packet timestamps::

        from packet_generator import (
            PacketBuilder, Protocol,
            write_pcap, LINKTYPE_ETHERNET,
        )

        pkts = [...]          # list[bytes]
        ts   = [(1000, 0), (1000, 500_000), (1001, 0)]
        write_pcap("out.pcap", pkts, timestamps=ts)
    """
    if timestamps is not None and len(timestamps) != len(packets):
        raise ValueError(
            f"timestamps length ({len(timestamps)}) must match "
            f"packets length ({len(packets)})"
        )

    # Resolve shared timestamp (used when timestamps is not provided)
    if ts_sec is None:
        t = time.time()
        ts_sec = int(t)
        ts_usec = int((t - ts_sec) * 1_000_000)
    shared = (ts_sec, ts_usec)

    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,  # magic — little-endian, microsecond timestamps
            2, 4,        # version 2.4
            0,           # UTC
            0,           # timestamp accuracy (always 0)
            65535,       # snaplen
            link_type,
        ))
        for idx, pkt in enumerate(packets):
            sec, usec = timestamps[idx] if timestamps is not None else shared
            length = len(pkt)
            f.write(struct.pack("<IIII", sec, usec, length, length))
            f.write(pkt)
