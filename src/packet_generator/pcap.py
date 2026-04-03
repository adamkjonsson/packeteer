"""libpcap and pcapng file writer.

This module writes raw packet bytes to a libpcap (``.pcap``) or pcapng
(``.pcapng``) file that can be opened directly in Wireshark, tcpdump, or
replayed with tcpreplay.

pcap file format overview::

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

pcapng file format overview::

    Section Header Block (SHB) — type 0x0A0D0D0A
        block_type         (4) — 0x0A0D0D0A
        block_total_length (4)
        byte_order_magic   (4) — 0x1A2B3C4D (little-endian)
        version_major      (2) — 1
        version_minor      (2) — 0
        section_length     (8) — -1 (unspecified)
        block_total_length (4)

    Interface Description Block (IDB) — type 0x00000001
        block_type         (4)
        block_total_length (4)
        link_type          (2)
        reserved           (2) — 0
        snap_len           (4) — 65535
        options            (variable) — if_tsresol (code 9)
        block_total_length (4)

    Enhanced Packet Block (EPB) — type 0x00000006
        block_type             (4)
        block_total_length     (4)
        interface_id           (4) — 0
        timestamp_high         (4) — upper 32 bits of 64-bit timestamp
        timestamp_low          (4) — lower 32 bits
        captured_packet_length (4)
        original_packet_length (4)
        packet_data            (captured_packet_length bytes, padded to 4-byte boundary)
        block_total_length     (4)

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

# pcapng block type constants
_PCAPNG_SHB_TYPE: int = 0x0A0D0D0A
_PCAPNG_IDB_TYPE: int = 0x00000001
_PCAPNG_EPB_TYPE: int = 0x00000006
_PCAPNG_BOM:      int = 0x1A2B3C4D  # byte-order magic (little-endian)
_PCAPNG_OPT_END:  int = 0           # opt_endofopt
_PCAPNG_IDB_OPT_TSRESOL: int = 9    # if_tsresol option code


def _pcapng_opt(code: int, value: bytes) -> bytes:
    """Pack one TLV option with a 4-byte-padded value."""
    pad = (4 - len(value) % 4) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


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

        import time
        from packet_generator import PacketBuilder, write_pcap

        now_ns = time.time_ns()
        now_sec, now_nsec = divmod(now_ns, 1_000_000_000)
        pkts = [
            (PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build(),
             now_sec, now_nsec),
        ]
        write_pcap(pkts, path="out.pcap", nanoseconds=True)
    """
    if path is not None:
        with open(path, "wb") as f:
            _write_pcap(f, packets, link_type, nanoseconds)
    if file_object is not None:
        _write_pcap(file_object, packets, link_type, nanoseconds)


def _write_pcapng(
    file_obj: io.IOBase,
    packets: list[tuple[bytes, int, int]],
    link_type: int,
    nanoseconds: bool,
) -> None:
    # Section Header Block (28 bytes)
    shb_body = struct.pack("<IHHq", _PCAPNG_BOM, 1, 0, -1)
    shb_total = 12 + len(shb_body)
    file_obj.write(struct.pack("<II", _PCAPNG_SHB_TYPE, shb_total))
    file_obj.write(shb_body)
    file_obj.write(struct.pack("<I", shb_total))

    # Interface Description Block
    tsresol = 9 if nanoseconds else 6  # 10^-9 (ns) or 10^-6 (us)
    idb_body = (
        struct.pack("<HHI", link_type, 0, 65535)
        + _pcapng_opt(_PCAPNG_IDB_OPT_TSRESOL, bytes([tsresol]))
        + struct.pack("<HH", _PCAPNG_OPT_END, 0)
    )
    idb_total = 12 + len(idb_body)
    file_obj.write(struct.pack("<II", _PCAPNG_IDB_TYPE, idb_total))
    file_obj.write(idb_body)
    file_obj.write(struct.pack("<I", idb_total))

    # Enhanced Packet Blocks
    resolution = 1_000_000_000 if nanoseconds else 1_000_000
    for pkt_data, ts_sec, ts_frac in packets:
        ts64 = ts_sec * resolution + ts_frac
        ts_hi = (ts64 >> 32) & 0xFFFFFFFF
        ts_lo = ts64 & 0xFFFFFFFF
        cap_len = len(pkt_data)
        pad = (4 - cap_len % 4) % 4
        epb_body = (
            struct.pack("<IIIII", 0, ts_hi, ts_lo, cap_len, cap_len)
            + pkt_data
            + b"\x00" * pad
        )
        epb_total = 12 + len(epb_body)
        file_obj.write(struct.pack("<II", _PCAPNG_EPB_TYPE, epb_total))
        file_obj.write(epb_body)
        file_obj.write(struct.pack("<I", epb_total))


def write_pcapng(
    packets: list[tuple[bytes, int, int]],
    *,
    path: str | os.PathLike | None = None,
    file_object: io.IOBase | None = None,
    link_type: int = LINKTYPE_ETHERNET,
    nanoseconds: bool = False,
) -> None:
    """Write raw packet bytes to a pcapng (``.pcapng``) file.

    Produces a pcapng file containing one Section Header Block, one Interface
    Description Block, and one Enhanced Packet Block per packet.

    Args:
        packets: Ordered list of ``(raw_bytes, ts_sec, ts_frac)`` — one per
            packet.  *ts_frac* is microseconds when *nanoseconds* is ``False``
            (default) or nanoseconds when *nanoseconds* is ``True``.
        path: Destination file path.  Created or overwritten.
        file_object: Destination file object.
        link_type: Link-layer type written into the Interface Description
            Block.  Use :data:`LINKTYPE_ETHERNET` (``1``, default) or
            :data:`LINKTYPE_RAW` (``101``).
        nanoseconds: When ``True``, timestamps are interpreted as nanoseconds
            and the ``if_tsresol`` option is set to ``9`` (10^-9).
            Defaults to ``False`` (microseconds, ``if_tsresol`` = 6).

    Raises:
        OSError: If *path* cannot be opened for writing.

    Example::

        from packet_generator import PacketBuilder, write_pcapng

        pkt = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build()
        write_pcapng([(pkt, 1700000000, 500000)], path="out.pcapng")
    """
    if path is not None:
        with open(path, "wb") as f:
            _write_pcapng(f, packets, link_type, nanoseconds)
    if file_object is not None:
        _write_pcapng(file_object, packets, link_type, nanoseconds)
