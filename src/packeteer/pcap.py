"""libpcap and pcapng file I/O.

This module reads and writes raw packet bytes from/to libpcap (``.pcap``) and
pcapng (``.pcapng``) files that can be opened in Wireshark, tcpdump, or
replayed with tcpreplay.  The format is detected automatically by
:func:`read_pcap` from the file's magic number.

pcap file format overview::

    Global header (24 bytes)
        magic_number  (4) — 0xA1B2C3D4 (usec) or 0xA1B23C4D (nsec)
        version_major (2) — 2
        version_minor (2) — 4
        thiszone      (4) — 0 (UTC)
        sigfigs       (4) — 0
        snaplen       (4) — 65535
        network       (4) — link-layer type

    Per-packet record (16 bytes + data)
        ts_sec   (4) — capture timestamp, whole seconds
        ts_usec  (4) — capture timestamp, sub-second fraction
        incl_len (4) — bytes present in the file for this packet
        orig_len (4) — original on-wire packet length
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

Supported pcap magic numbers::

    0xA1B2C3D4  little-endian, microsecond timestamps  (most common)
    0xD4C3B2A1  big-endian,    microsecond timestamps
    0xA1B23C4D  little-endian, nanosecond  timestamps
    0x4D3CB2A1  big-endian,    nanosecond  timestamps

Supported pcapng block types:

* **Section Header Block** (``0x0A0D0D0A``) — marks start of a section.
* **Interface Description Block** (``0x00000001``) — captures link-layer
  type, snap length, and ``if_tsresol`` timestamp resolution option.
* **Enhanced Packet Block** (``0x00000006``) — primary packet block with
  64-bit timestamps.
* **Obsolete Packet Block** (``0x00000002``) — legacy packet block; read
  for compatibility but not written.

Constants:
    LINKTYPE_ETHERNET (int): Link-layer type ``1`` — Ethernet II.
    LINKTYPE_RAW (int): Link-layer type ``101`` — Raw IP (no Ethernet header).
    LINKTYPE_LINUX_SLL (int): Link-layer type ``113`` — Linux "cooked" v1.
    LINKTYPE_LINUX_SLL2 (int): Link-layer type ``276`` — Linux "cooked" v2.
"""
from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

#: Largest value the 32-bit pcap ``ts_sec`` field can hold (year 2106).
_MAX_TS_SEC: int = 0xFFFFFFFF

LINKTYPE_ETHERNET: int = 1    # Ethernet II
LINKTYPE_RAW: int = 101       # Raw IP (no Ethernet header)
LINKTYPE_LINUX_SLL: int = 113   # Linux "cooked" capture v1 (tcpdump -i any)
LINKTYPE_LINUX_SLL2: int = 276  # Linux "cooked" capture v2

_MAGIC_USEC: int = 0xA1B2C3D4
_MAGIC_NSEC: int = 0xA1B23C4D

_GLOBAL_HDR_SIZE: int = 24
_PKT_HDR_SIZE: int = 16

# pcapng block types
_PCAPNG_SHB_TYPE: int = 0x0A0D0D0A
_PCAPNG_IDB_TYPE: int = 0x00000001
_PCAPNG_EPB_TYPE: int = 0x00000006
_PCAPNG_OPB_TYPE: int = 0x00000002  # Obsolete Packet Block (read-only)

# pcapng byte-order magic values
_PCAPNG_BOM_LE: int = 0x1A2B3C4D
_PCAPNG_BOM_BE: int = 0x4D3C2B1A

# pcapng option codes
_OPT_ENDOFOPT: int = 0
_PCAPNG_IDB_OPT_TSRESOL: int = 9


# ── Dataclasses ───────────────────────────────────────────────────────────────

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
    """Parsed contents of a pcap or pcapng file.

    Attributes:
        header: Global file metadata.
        packets: Ordered list of ``(data, ts_sec, ts_frac)`` tuples.
            *ts_frac* holds microseconds or nanoseconds depending on
            :attr:`PcapFileHeader.nanoseconds`.

    """

    header: PcapFileHeader
    packets: list[tuple[bytes, int, int]] = field(default_factory=list)


# ── Read helpers ──────────────────────────────────────────────────────────────

def _parse_idb_tsresol(body: bytes, offset: int, endian: str) -> int:
    """Return the timestamp ticks-per-second from IDB options (default: 1_000_000)."""
    while offset + 4 <= len(body):
        opt_code, opt_len = struct.unpack_from(endian + "HH", body, offset)
        offset += 4
        if opt_code == _OPT_ENDOFOPT:
            break
        opt_value = body[offset : offset + opt_len]
        offset += (opt_len + 3) & ~3
        if opt_code == _PCAPNG_IDB_OPT_TSRESOL and opt_len >= 1:
            tsresol_byte = opt_value[0]
            exp = tsresol_byte & 0x7F
            if tsresol_byte & 0x80:   # binary: 2^exp ticks per second
                return 1 << exp
            # decimal: 10^exp ticks per second
            return 10 ** exp
    return 1_000_000  # default: microseconds


def _read_pcapng_packet(
    block_type: int, body: bytes, endian: str, interfaces: list[tuple[int, int]],
) -> tuple[bytes, int, int]:
    """Decode an Enhanced or Simple Packet Block body into a packet tuple."""
    if block_type == _PCAPNG_EPB_TYPE:
        if len(body) < 20:
            raise ValueError("EPB body too short")
        iface_id, ts_hi, ts_lo, cap_len, _ = struct.unpack_from(endian + "IIIII", body)
        offset = 20
    else:  # _PCAPNG_OPB_TYPE
        if len(body) < 16:
            raise ValueError("OPB body too short")
        iface_id, _, ts_hi, ts_lo, cap_len, _ = struct.unpack_from(endian + "HHIIII", body)
        offset = 16
    pkt_data = body[offset : offset + cap_len]
    if len(pkt_data) < cap_len:
        raise ValueError("Packet block data truncated")
    ts64 = (ts_hi << 32) | ts_lo
    resolution = interfaces[iface_id][1] if iface_id < len(interfaces) else 1_000_000
    ts_sec, ts_frac = divmod(ts64, resolution)
    return (pkt_data, ts_sec, ts_frac)


def _read_pcapng(
    file_obj: io.RawIOBase | io.BufferedIOBase | _ChainedReader,
    max_packets: int | None = None,
) -> PcapFile:
    """Read a pcapng file.  *file_obj* must be positioned at the start."""
    type_raw      = file_obj.read(4)
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
    file_obj.read(total_len - 12)

    interfaces: list[tuple[int, int]] = []  # (link_type, ticks_per_second)
    link_type = 1
    snaplen   = 65535
    nanoseconds = False
    packets: list[tuple[bytes, int, int]] = []

    while True:
        if max_packets is not None and len(packets) >= max_packets:
            break
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

        elif block_type in (_PCAPNG_EPB_TYPE, _PCAPNG_OPB_TYPE):
            packets.append(_read_pcapng_packet(block_type, body, endian, interfaces))

    file_header = PcapFileHeader(
        link_type=link_type,
        version_major=1,
        version_minor=0,
        snaplen=snaplen,
        nanoseconds=nanoseconds,
    )
    return PcapFile(header=file_header, packets=packets)


def _read_pcap(
    file_obj: io.RawIOBase | io.BufferedIOBase | _ChainedReader,
    max_packets: int | None = None,
) -> PcapFile:
    global_hdr = file_obj.read(_GLOBAL_HDR_SIZE)
    if len(global_hdr) < _GLOBAL_HDR_SIZE:
        raise ValueError(
            f"File too short for pcap global header: "
            f"got {len(global_hdr)} bytes, need {_GLOBAL_HDR_SIZE}"
        )

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
        if max_packets is not None and len(packets) >= max_packets:
            break
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


class _ChainedReader:
    """Serve a small byte prefix, then delegate further reads to a stream.

    Lets :func:`_detect_and_read` peek the 4-byte magic number and then keep
    reading without buffering the whole file — so an early-stopping reader
    (``max_packets``) can avoid loading a large capture into memory.
    """

    def __init__(self, prefix: bytes, rest: io.RawIOBase | io.BufferedIOBase) -> None:
        self._prefix = prefix
        self._pos = 0
        self._rest = rest

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            out = self._prefix[self._pos:] + self._rest.read()
            self._pos = len(self._prefix)
            return out
        out = b""
        if self._pos < len(self._prefix):
            chunk = self._prefix[self._pos : self._pos + size]
            self._pos += len(chunk)
            out += chunk
            size -= len(chunk)
        if size > 0:
            out += self._rest.read(size)
        return out


def _detect_and_read(
    file_obj: io.RawIOBase | io.BufferedIOBase, max_packets: int | None = None,
) -> PcapFile:
    """Detect pcap vs pcapng from the first 4 bytes and dispatch."""
    header4 = file_obj.read(4)
    if len(header4) < 4:
        raise ValueError(f"File too short: got {len(header4)} bytes, need at least 4")
    (magic,) = struct.unpack_from("<I", header4)
    if max_packets is None:
        # Buffer the whole file — the simple, well-trodden path.
        buf: io.RawIOBase | io.BufferedIOBase | _ChainedReader = io.BytesIO(
            header4 + file_obj.read()
        )
    else:
        # Stream from the original object so we can stop without reading it all.
        buf = _ChainedReader(header4, file_obj)
    if magic == _PCAPNG_SHB_TYPE:
        return _read_pcapng(buf, max_packets)
    return _read_pcap(buf, max_packets)


# ── Write helpers ─────────────────────────────────────────────────────────────

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
        0,      # timestamp accuracy
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


def _write_pcapng(
    file_obj: io.IOBase,
    packets: list[tuple[bytes, int, int]],
    link_type: int,
    nanoseconds: bool,
) -> None:
    # Section Header Block
    shb_body = struct.pack("<IHHq", _PCAPNG_BOM_LE, 1, 0, -1)
    shb_total = 12 + len(shb_body)
    file_obj.write(struct.pack("<II", _PCAPNG_SHB_TYPE, shb_total))
    file_obj.write(shb_body)
    file_obj.write(struct.pack("<I", shb_total))

    # Interface Description Block
    tsresol = 9 if nanoseconds else 6
    idb_body = (
        struct.pack("<HHI", link_type, 0, 65535)
        + _pcapng_opt(_PCAPNG_IDB_OPT_TSRESOL, bytes([tsresol]))
        + struct.pack("<HH", _OPT_ENDOFOPT, 0)
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


# ── Public API ────────────────────────────────────────────────────────────────

def is_pcap_or_pcapng(path: str | os.PathLike) -> bool:
    """Return True if *path* begins with a recognised pcap or pcapng magic number.

    Reads only the first 4 bytes of the file; does not validate the rest.
    Returns False on any I/O error or if the file is too short.

    Args:
        path: Path to the file to inspect.

    Returns:
        True if the file starts with a pcap or pcapng magic number.

    """
    _pcap_magics = {
        _MAGIC_USEC.to_bytes(4, "little"),
        _MAGIC_USEC.to_bytes(4, "big"),
        _MAGIC_NSEC.to_bytes(4, "little"),
        _MAGIC_NSEC.to_bytes(4, "big"),
        _PCAPNG_SHB_TYPE.to_bytes(4, "little"),
    }
    try:
        with open(path, "rb") as f:
            header = f.read(4)
    except OSError:
        return False
    return header in _pcap_magics


def read_pcap(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
    link_type: int | None = None,
    max_packets: int | None = None,
) -> PcapFile:
    """Read packets and capture timestamps from a ``.pcap`` or ``.pcapng`` file.

    The format is detected automatically from the magic number, so this
    function accepts both pcap and pcapng files.

    Exactly one of *path* or *file_object* must be supplied.

    Args:
        path: Path to the file to read.
        file_object: Readable binary file-like object positioned at the
            start of the data (e.g. ``io.BytesIO``).
        link_type: When given, override the link-layer type recorded in the
            file header (e.g. :data:`LINKTYPE_ETHERNET` or :data:`LINKTYPE_RAW`).
            Use this when a capture declares the wrong link type and the
            recorded value would otherwise drive incorrect parsing.  The
            returned :attr:`PcapFile.header` reflects the override.
        max_packets: When given, stop after reading this many packet records.
            Reading streams from the source and stops early, so the rest of a
            large file is never loaded.  The file header is always read first,
            so :attr:`PcapFile.header` is populated regardless.

    Returns:
        A :class:`PcapFile` whose ``header`` attribute contains global
        metadata and whose ``packets`` attribute is a list of
        ``(data, ts_sec, ts_frac)`` tuples — one entry per captured packet.
        The tuple layout matches the input format of :func:`write_pcap`.

    Raises:
        ValueError: If neither or both of *path* / *file_object* are given,
            if the magic number is unrecognised, or if the file is truncated.
        OSError: If *path* cannot be opened for reading.

    Example::

        from packeteer.pcap import read_pcap

        result = read_pcap(path="capture.pcap")
        print(result.header.link_type)
        for data, ts_sec, ts_frac in result.packets:
            print(ts_sec, ts_frac, data.hex())

    """
    if (path is None) == (file_object is None):
        raise ValueError("Provide exactly one of 'path' or 'file_object'.")
    if max_packets is not None and max_packets < 0:
        raise ValueError(f"max_packets must be non-negative, got {max_packets}")
    if path is not None:
        with open(path, "rb") as f:
            result = _detect_and_read(f, max_packets)
    else:
        assert file_object is not None
        result = _detect_and_read(file_object, max_packets)
    if link_type is not None:
        result.header.link_type = link_type
    return result


def datetime_to_pcap_ts(
    dt: datetime, *, nanoseconds: bool = False,
) -> tuple[int, int]:
    """Convert a :class:`~datetime.datetime` to a pcap ``(ts_sec, ts_frac)`` pair.

    Use this to build the timestamp portion of the tuples passed to
    :func:`write_pcap` / :func:`write_pcapng` when your timestamps are
    :class:`~datetime.datetime` objects::

        write_pcap([(raw, *datetime_to_pcap_ts(dt))], path="out.pcap")

    A **naive** *dt* (no ``tzinfo``) is assumed to already be UTC, matching the
    pcap convention that timestamps are UTC.  A timezone-aware *dt* is converted
    to UTC via its offset.  Conversion uses integer arithmetic, so it is exact
    to the microsecond.

    Note that :class:`~datetime.datetime` only has microsecond resolution: when
    *nanoseconds* is ``True`` the returned fraction is a whole number of
    microseconds scaled to nanoseconds (the last three digits are always zero).

    Args:
        dt: The capture time.  Naive values are treated as UTC.
        nanoseconds: When ``True``, return the fraction in nanoseconds (for a
            nanosecond-resolution file); otherwise in microseconds (the
            default).  Must match the *nanoseconds* argument of the writer.

    Returns:
        ``(ts_sec, ts_frac)`` where *ts_sec* is whole seconds since the Unix
        epoch and *ts_frac* is the sub-second remainder in microseconds (or
        nanoseconds when *nanoseconds* is ``True``).

    Raises:
        ValueError: If *dt* predates the Unix epoch or is beyond what the
            32-bit ``ts_sec`` field can hold (year 2106).

    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - _EPOCH
    total_us = delta // timedelta(microseconds=1)
    ts_sec, us_frac = divmod(total_us, 1_000_000)
    if not 0 <= ts_sec <= _MAX_TS_SEC:
        raise ValueError(
            f"timestamp {dt.isoformat()} is out of range for a pcap file "
            f"(ts_sec must be between 0 and {_MAX_TS_SEC}, got {ts_sec})"
        )
    return (ts_sec, us_frac * 1000 if nanoseconds else us_frac)


def pcap_ts_to_datetime(
    ts_sec: int, ts_frac: int, *, nanoseconds: bool = False,
) -> datetime:
    """Convert a pcap ``(ts_sec, ts_frac)`` pair to a timezone-aware UTC datetime.

    The inverse of :func:`datetime_to_pcap_ts`, for turning the tuples returned
    by :func:`read_pcap` back into :class:`~datetime.datetime` objects::

        pcap = read_pcap(path="in.pcap")
        for data, ts_sec, ts_frac in pcap.packets:
            when = pcap_ts_to_datetime(ts_sec, ts_frac, nanoseconds=pcap.header.nanoseconds)

    Because :class:`~datetime.datetime` only has microsecond resolution, any
    sub-microsecond part of a nanosecond timestamp is truncated.

    Args:
        ts_sec: Whole seconds since the Unix epoch.
        ts_frac: Sub-second remainder — microseconds, or nanoseconds when
            *nanoseconds* is ``True``.
        nanoseconds: When ``True``, *ts_frac* is interpreted as nanoseconds;
            otherwise as microseconds (the default).

    Returns:
        A timezone-aware :class:`~datetime.datetime` in UTC.

    """
    us = ts_frac // 1000 if nanoseconds else ts_frac
    return _EPOCH + timedelta(seconds=ts_sec, microseconds=us)


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
            For :class:`~datetime.datetime` timestamps, build the pair with
            :func:`datetime_to_pcap_ts`, e.g.
            ``(raw, *datetime_to_pcap_ts(dt, nanoseconds=nanoseconds))``.
        path: Destination file path.  Created or overwritten.
        file_object: Destination file-like object.
        link_type: pcap link-layer type.  Use :data:`LINKTYPE_ETHERNET`
            (``1``, default) for packets with an Ethernet header, or
            :data:`LINKTYPE_RAW` (``101``) for raw IP packets.
        nanoseconds: When ``True``, write magic ``0xA1B23C4D`` so readers
            interpret the timestamp fraction as nanoseconds instead of the
            default microseconds (magic ``0xA1B2C3D4``).

    Raises:
        OSError: If *path* cannot be opened for writing.

    Example::

        import time
        from packeteer.generate import PacketBuilder
        from packeteer.pcap import write_pcap

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
            For :class:`~datetime.datetime` timestamps, build the pair with
            :func:`datetime_to_pcap_ts`, e.g.
            ``(raw, *datetime_to_pcap_ts(dt, nanoseconds=nanoseconds))``.
        path: Destination file path.  Created or overwritten.
        file_object: Destination file-like object.
        link_type: Link-layer type written into the Interface Description
            Block.  Use :data:`LINKTYPE_ETHERNET` (``1``, default) or
            :data:`LINKTYPE_RAW` (``101``).
        nanoseconds: When ``True``, timestamps are in nanoseconds and the
            ``if_tsresol`` option is set to ``9`` (10^-9).  Defaults to
            ``False`` (microseconds, ``if_tsresol`` = 6).

    Raises:
        OSError: If *path* cannot be opened for writing.

    Example::

        from packeteer.generate import PacketBuilder
        from packeteer.pcap import write_pcapng

        pkt = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build()
        write_pcapng([(pkt, 1700000000, 500000)], path="out.pcapng")

    """
    if path is not None:
        with open(path, "wb") as f:
            _write_pcapng(f, packets, link_type, nanoseconds)
    if file_object is not None:
        _write_pcapng(file_object, packets, link_type, nanoseconds)
