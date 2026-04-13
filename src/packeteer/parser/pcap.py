"""libpcap and pcapng file reader.

This module reads raw packet bytes and capture timestamps from a libpcap
(``.pcap``) or pcapng (``.pcapng``) file.  The format is detected
automatically from the file's magic number, so :func:`read_pcap` accepts
both formats transparently.

Supported pcap magic numbers::

    0xA1B2C3D4  little-endian, microsecond timestamps  (most common)
    0xD4C3B2A1  big-endian,    microsecond timestamps
    0xA1B23C4D  little-endian, nanosecond  timestamps
    0x4D3CB2A1  big-endian,    nanosecond  timestamps

Nanosecond-resolution pcap files report ``ts_usec`` values in nanoseconds;
the field is left as-is so callers can distinguish resolution via
:attr:`PcapFileHeader.nanoseconds`.

Supported pcapng block types:

* **Section Header Block** (``0x0A0D0D0A``) — marks start of a section;
  byte-order magic determines endianness of subsequent blocks.
* **Interface Description Block** (``0x00000001``) — captures link-layer
  type, snap length, and ``if_tsresol`` timestamp resolution option.
* **Enhanced Packet Block** (``0x00000006``) — primary packet block with
  64-bit timestamps.
* **Obsolete Packet Block** (``0x00000002``) — legacy packet block; read
  for compatibility but not written.

pcap file format overview::

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

# pcapng constants
_PCAPNG_SHB_TYPE: int = 0x0A0D0D0A
_PCAPNG_IDB_TYPE: int = 0x00000001
_PCAPNG_EPB_TYPE: int = 0x00000006
_PCAPNG_OPB_TYPE: int = 0x00000002  # Obsolete Packet Block
_PCAPNG_BOM_LE:   int = 0x1A2B3C4D  # byte-order magic, LE file
_PCAPNG_BOM_BE:   int = 0x4D3C2B1A  # byte-order magic, BE file
_PCAPNG_IDB_OPT_TSRESOL: int = 9    # if_tsresol option code
_OPT_ENDOFOPT: int = 0


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


def _parse_idb_tsresol(body: bytes, offset: int, endian: str) -> int:
    """Return the timestamp ticks-per-second from IDB options (default: 1_000_000)."""
    while offset + 4 <= len(body):
        opt_code, opt_len = struct.unpack_from(endian + "HH", body, offset)
        offset += 4
        if opt_code == _OPT_ENDOFOPT:
            break
        opt_value = body[offset : offset + opt_len]
        offset += (opt_len + 3) & ~3  # advance past padded value
        if opt_code == _PCAPNG_IDB_OPT_TSRESOL and opt_len >= 1:
            tsresol_byte = opt_value[0]
            exp = tsresol_byte & 0x7F
            if tsresol_byte & 0x80:   # binary: 2^exp ticks per second
                return 1 << exp
            else:                     # decimal: 10^exp ticks per second
                return 10 ** exp
    return 1_000_000  # default: microseconds


def _read_pcapng(file_obj: io.RawIOBase | io.BufferedIOBase) -> PcapFile:
    """Read a pcapng file.  *file_obj* must be positioned at the start."""
    # --- Section Header Block ---
    type_raw      = file_obj.read(4)   # 0x0A0D0D0A (byte-order symmetric)
    total_len_raw = file_obj.read(4)
    bom_raw       = file_obj.read(4)
    if len(type_raw) < 4 or len(total_len_raw) < 4 or len(bom_raw) < 4:
        raise ValueError("Truncated pcapng SHB")

    (bom,) = struct.unpack_from("<I", bom_raw)
    if bom == _PCAPNG_BOM_LE:
        endian = "<"
    elif bom == _PCAPNG_BOM_BE:
        endian = ">"
    else:
        raise ValueError(f"Unrecognised pcapng byte-order magic: 0x{bom:08X}")

    (total_len,) = struct.unpack(endian + "I", total_len_raw)
    if total_len < 12:
        raise ValueError(f"SHB total length {total_len} too small (minimum 12)")
    # Skip remainder of SHB: body_len - 4 (already read BOM) + 4 (trailing total_len)
    file_obj.read(total_len - 12)

    # --- Subsequent blocks ---
    interfaces: list[tuple[int, int]] = []  # (link_type, ticks_per_second)
    link_type = 1       # LINKTYPE_ETHERNET default
    snaplen   = 65535
    nanoseconds = False
    packets: list[tuple[bytes, int, int]] = []

    while True:
        block_hdr = file_obj.read(8)
        if not block_hdr:
            break
        if len(block_hdr) < 8:
            raise ValueError("Truncated pcapng block header")
        block_type, total_len = struct.unpack(endian + "II", block_hdr)
        if total_len < 12:
            raise ValueError(f"Block total length {total_len} too small (minimum 12)")
        body_len = total_len - 12
        body = file_obj.read(body_len)
        if len(body) < body_len:
            raise ValueError(f"Truncated block body: got {len(body)}, need {body_len}")
        trailing = file_obj.read(4)
        if len(trailing) < 4:
            raise ValueError("Truncated trailing block total length")

        if block_type == _PCAPNG_IDB_TYPE:
            if len(body) < 8:
                raise ValueError("IDB body too short")
            idb_link_type, _, idb_snaplen = struct.unpack_from(endian + "HHI", body)
            resolution = _parse_idb_tsresol(body, 8, endian)
            interfaces.append((idb_link_type, resolution))
            if len(interfaces) == 1:
                link_type   = idb_link_type
                snaplen     = idb_snaplen
                nanoseconds = (resolution == 1_000_000_000)

        elif block_type == _PCAPNG_EPB_TYPE:
            if len(body) < 20:
                raise ValueError("EPB body too short")
            iface_id, ts_hi, ts_lo, cap_len, _ = struct.unpack_from(endian + "IIIII", body)
            pkt_data = body[20 : 20 + cap_len]
            if len(pkt_data) < cap_len:
                raise ValueError("EPB packet data truncated")
            ts64 = (ts_hi << 32) | ts_lo
            resolution = interfaces[iface_id][1] if iface_id < len(interfaces) else 1_000_000
            ts_sec, ts_frac = divmod(ts64, resolution)
            packets.append((pkt_data, ts_sec, ts_frac))

        elif block_type == _PCAPNG_OPB_TYPE:
            if len(body) < 16:
                raise ValueError("OPB body too short")
            iface_id_16, _, ts_hi, ts_lo, cap_len, _ = struct.unpack_from(endian + "HHIIII", body)
            pkt_data = body[16 : 16 + cap_len]
            if len(pkt_data) < cap_len:
                raise ValueError("OPB packet data truncated")
            ts64 = (ts_hi << 32) | ts_lo
            resolution = interfaces[iface_id_16][1] if iface_id_16 < len(interfaces) else 1_000_000
            ts_sec, ts_frac = divmod(ts64, resolution)
            packets.append((pkt_data, ts_sec, ts_frac))
        # All other block types (NRB, ISB, further SHBs, …) are silently skipped.

    file_header = PcapFileHeader(
        link_type=link_type,
        version_major=1,
        version_minor=0,
        snaplen=snaplen,
        nanoseconds=nanoseconds,
    )
    return PcapFile(header=file_header, packets=packets)


def _detect_and_read(file_obj: io.RawIOBase | io.BufferedIOBase) -> PcapFile:
    """Detect pcap vs pcapng from the first 4 bytes and dispatch."""
    header4 = file_obj.read(4)
    if len(header4) < 4:
        raise ValueError(f"File too short: got {len(header4)} bytes, need at least 4")
    rest = file_obj.read()
    buf = io.BytesIO(header4 + rest)
    (magic,) = struct.unpack_from("<I", header4)
    if magic == _PCAPNG_SHB_TYPE:
        return _read_pcapng(buf)
    return _read_pcap(buf)


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

        from .pcap import read_pcap

        result = read_pcap(path="capture.pcap")
        print(result.header.link_type)
        for data, ts_sec, ts_usec in result.packets:
            print(ts_sec, ts_usec, data.hex())
    """
    if (path is None) == (file_object is None):
        raise ValueError("Provide exactly one of 'path' or 'file_object'.")

    if path is not None:
        with open(path, "rb") as f:
            return _detect_and_read(f)
    else:
        assert file_object is not None
        return _detect_and_read(file_object)
