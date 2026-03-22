"""libpcap file reader.

This module reads raw packet bytes and capture timestamps from a libpcap
(``.pcap``) file produced by Wireshark, tcpdump, or
:mod:`packet_generator.pcap`.

Supported magic numbers::

    0xA1B2C3D4  little-endian, microsecond timestamps  (most common)
    0xD4C3B2A1  big-endian,    microsecond timestamps
    0xA1B23C4D  little-endian, nanosecond  timestamps
    0x4D3CB2A1  big-endian,    nanosecond  timestamps

Nanosecond-resolution files report ``ts_usec`` values in nanoseconds; the
field is left as-is so callers can distinguish resolution via
:attr:`PcapFileHeader.nanoseconds`.

File format overview::

    Global header (24 bytes)
        magic_number  (4) — determines byte order and timestamp resolution
        version_major (2) — 2
        version_minor (2) — 4
        thiszone      (4) — UTC offset in seconds (almost always 0)
        sigfigs       (4) — timestamp accuracy (almost always 0)
        snaplen       (4) — max bytes captured per packet
        network       (4) — link-layer type

    Per-packet record (16 bytes + data)
        ts_sec   (4) — capture timestamp, whole seconds
        ts_usec  (4) — capture timestamp, sub-second fraction
        incl_len (4) — bytes present in the file for this packet
        orig_len (4) — original on-wire packet length
        data     (incl_len bytes)
"""
from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass, field

# The pcap magic value is always 0xA1B2C3D4 (usec) or 0xA1B23C4D (nsec).
# Endianness is determined by which byte-order interpretation matches.
_MAGIC_USEC: int = 0xA1B2C3D4
_MAGIC_NSEC: int = 0xA1B23C4D

_GLOBAL_HDR_SIZE: int = 24
_PKT_HDR_SIZE: int = 16


@dataclass
class PcapFileHeader:
    """Metadata from the pcap global header.

    Attributes:
        link_type: Link-layer type (e.g. ``1`` = Ethernet, ``101`` = Raw IP).
        version_major: Pcap format major version (always ``2``).
        version_minor: Pcap format minor version (always ``4``).
        snaplen: Maximum number of bytes captured per packet.
        nanoseconds: ``True`` if sub-second timestamps are in nanoseconds
            rather than microseconds.
    """
    link_type: int
    version_major: int
    version_minor: int
    snaplen: int
    nanoseconds: bool


@dataclass
class PcapFile:
    """Parsed contents of a pcap file.

    Attributes:
        header: Global file metadata.
        packets: Ordered list of ``(data, ts_sec, ts_usec)`` tuples.
            *ts_usec* holds microseconds or nanoseconds depending on
            :attr:`PcapFileHeader.nanoseconds`.
    """
    header: PcapFileHeader
    packets: list[tuple[bytes, int, int]] = field(default_factory=list)


def _read_pcap(file_obj: io.RawIOBase | io.BufferedIOBase) -> PcapFile:
    global_hdr = file_obj.read(_GLOBAL_HDR_SIZE)
    if len(global_hdr) < _GLOBAL_HDR_SIZE:
        raise ValueError(
            f"File too short for pcap global header: got {len(global_hdr)} bytes, need {_GLOBAL_HDR_SIZE}"
        )

    # Detect byte order and timestamp resolution from the magic number.
    # Both endiannesses use the same magic value; the file's byte order is
    # whichever interpretation of the first 4 bytes yields a known value.
    (magic_le,) = struct.unpack_from("<I", global_hdr, 0)
    (magic_be,) = struct.unpack_from(">I", global_hdr, 0)
    if magic_le in (_MAGIC_USEC, _MAGIC_NSEC):
        endian = "<"
        nanoseconds = magic_le == _MAGIC_NSEC
    elif magic_be in (_MAGIC_USEC, _MAGIC_NSEC):
        endian = ">"
        nanoseconds = magic_be == _MAGIC_NSEC
    else:
        raise ValueError(f"Unrecognised pcap magic number: 0x{magic_le:08X}")

    fmt = endian + "IHHiIII"
    _, version_major, version_minor, _, _, snaplen, link_type = struct.unpack_from(fmt, global_hdr)

    file_header = PcapFileHeader(
        link_type=link_type,
        version_major=version_major,
        version_minor=version_minor,
        snaplen=snaplen,
        nanoseconds=nanoseconds,
    )

    packets: list[tuple[bytes, int, int]] = []
    pkt_fmt = endian + "IIII"

    while True:
        pkt_hdr_raw = file_obj.read(_PKT_HDR_SIZE)
        if not pkt_hdr_raw:
            break
        if len(pkt_hdr_raw) < _PKT_HDR_SIZE:
            raise ValueError(
                f"Truncated packet header: got {len(pkt_hdr_raw)} bytes, need {_PKT_HDR_SIZE}"
            )

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(pkt_fmt, pkt_hdr_raw)
        _ = orig_len

        data = file_obj.read(incl_len)
        if len(data) < incl_len:
            raise ValueError(
                f"Truncated packet data: got {len(data)} bytes, need {incl_len}"
            )

        packets.append((data, ts_sec, ts_usec))

    return PcapFile(header=file_header, packets=packets)


def read_pcap(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
) -> PcapFile:
    """Read packets and capture timestamps from a libpcap (``.pcap``) file.

    Exactly one of *path* or *file_object* must be supplied.

    Args:
        path: Path to the ``.pcap`` file to read.
        file_object: Readable binary file-like object positioned at the
            start of the pcap data (e.g. ``io.BytesIO``).

    Returns:
        A :class:`PcapFile` whose ``header`` attribute contains global
        metadata and whose ``packets`` attribute is a list of
        ``(data, ts_sec, ts_usec)`` tuples — one entry per captured packet.
        The tuple layout matches the input format of
        :func:`packet_generator.pcap.write_pcap`.

    Raises:
        ValueError: If neither or both of *path* / *file_object* are given,
            if the magic number is unrecognised, or if the file is truncated.
        OSError: If *path* cannot be opened for reading.

    Example::

        from packet_parser.pcap import read_pcap

        result = read_pcap(path="capture.pcap")
        print(result.header.link_type)
        for data, ts_sec, ts_usec in result.packets:
            print(ts_sec, ts_usec, data.hex())
    """
    if (path is None) == (file_object is None):
        raise ValueError("Provide exactly one of 'path' or 'file_object'.")

    if path is not None:
        with open(path, "rb") as f:
            return _read_pcap(f)
    else:
        assert(file_object is not None)
        return _read_pcap(file_object)
