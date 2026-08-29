"""libpcap and pcapng file I/O.

This module reads and writes raw packet bytes from/to libpcap (``.pcap``) and
pcapng (``.pcapng``) files that can be opened in Wireshark, tcpdump, or
replayed with tcpreplay.  The format is detected automatically from the file's
magic number by :func:`read_pcap`, which returns every packet at once, and by
:func:`open_pcap`, which streams them one record at a time with byte offsets.

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
import itertools
import os
import struct
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

#: Largest value the 32-bit pcap ``ts_sec`` field can hold (year 2106).
_MAX_TS_SEC: int = 0xFFFFFFFF

LINKTYPE_NULL: int = 0        # BSD loopback (4-byte address family)
LINKTYPE_ETHERNET: int = 1    # Ethernet II
LINKTYPE_RAW: int = 101       # Raw IP (no Ethernet header)
LINKTYPE_LOOP: int = 108      # OpenBSD loopback (big-endian family)
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

#: Bytes of block type + block total length preceding every pcapng block body.
_PCAPNG_BLOCK_HDR_SIZE: int = 8

# pcapng byte-order magic values
_PCAPNG_BOM_LE: int = 0x1A2B3C4D
_PCAPNG_BOM_BE: int = 0x4D3C2B1A

# pcapng option codes
_OPT_ENDOFOPT: int = 0
_PCAPNG_IDB_OPT_TSRESOL: int = 9

# Timestamp resolutions, in ticks per second
_US_PER_SECOND: int = 1_000_000
_NS_PER_SECOND: int = 1_000_000_000


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
            rather than microseconds.  A convenience view of *tick_hz* — a
            capture may use neither resolution, in which case this is
            ``False`` and *tick_hz* is the field to read.
        tick_hz: Sub-second timestamp resolution in ticks per second, i.e. the
            unit of ``ts_frac``.  Classic pcap is always ``1_000_000`` or
            ``1_000_000_000`` (selected by the magic number), while pcapng
            declares any resolution per interface via ``if_tsresol`` —
            milliseconds (``1_000``) and binary resolutions (``2**n``) are
            both legal.  Pass ``0`` (the default) to derive it from
            *nanoseconds*; when given explicitly it wins, and *nanoseconds* is
            set to match.

    Raises:
        ValueError: If *tick_hz* is negative.

    """

    link_type: int
    version_major: int
    version_minor: int
    snaplen: int
    nanoseconds: bool = False
    tick_hz: int = 0

    def __post_init__(self) -> None:
        """Reconcile *tick_hz* and *nanoseconds* so the two never disagree."""
        if self.tick_hz < 0:
            raise ValueError(f"tick_hz must be non-negative, got {self.tick_hz}")
        if self.tick_hz == 0:
            self.tick_hz = _NS_PER_SECOND if self.nanoseconds else _US_PER_SECOND
        else:
            self.nanoseconds = self.tick_hz == _NS_PER_SECOND


@dataclass
class PcapRecord:
    """One packet record, with its position in the source file.

    Yielded by :func:`open_pcap`.  Unpacks like the ``(data, ts_sec, ts_frac)``
    tuples in :attr:`PcapFile.packets` for the first three fields, so the two
    reading styles line up.

    Attributes:
        data: Captured packet bytes.  Shorter than *orig_len* when the capture
            was taken with a snaplen smaller than the packet.
        ts_sec: Whole seconds of the capture timestamp.
        ts_frac: Sub-second remainder, in units of
            :attr:`PcapFileHeader.tick_hz`.
        offset: Byte offset of the start of this record within the file — the
            16-byte record header for pcap, the block header for pcapng.
        data_offset: Byte offset of the first captured packet byte.  This is
            the offset to cite when referring to packet bytes in the file.
        orig_len: Length of the packet on the wire, before any snaplen
            truncation.
        tick_hz: Ticks per second that *ts_frac* is expressed in.  Carried on
            the record so a timestamp is never separated from its unit — for
            pcapng it is the resolution declared by *this record's* interface,
            which in a multi-interface capture can differ from
            :attr:`PcapFileHeader.tick_hz`.

    """

    data: bytes
    ts_sec: int
    ts_frac: int
    offset: int
    data_offset: int
    orig_len: int
    tick_hz: int = _US_PER_SECOND

    def __iter__(self) -> Iterator[Any]:
        """Yield ``data``, ``ts_sec``, ``ts_frac`` so the record unpacks."""
        return iter((self.data, self.ts_sec, self.ts_frac))

    @property
    def timestamp(self) -> float:
        """Capture time in seconds since the Unix epoch.

        Convenience for ``ts_sec + ts_frac / tick_hz``.  A float cannot hold a
        modern epoch to nanosecond precision — roughly the last three digits
        of a nanosecond timestamp are lost — so keep using *ts_sec*,
        *ts_frac* and *tick_hz* where exactness matters, or
        :attr:`timestamp_ns`.
        """
        return self.ts_sec + self.ts_frac / self.tick_hz

    @property
    def timestamp_ns(self) -> int:
        """Capture time in whole nanoseconds since the Unix epoch, exactly."""
        return self.ts_sec * _NS_PER_SECOND + self.ts_frac * _NS_PER_SECOND // self.tick_hz

    def datetime(self) -> datetime:
        """Return the capture time as a timezone-aware UTC datetime.

        Truncated to microseconds, which is all :class:`~datetime.datetime`
        holds.
        """
        return pcap_ts_to_datetime(self.ts_sec, self.ts_frac, tick_hz=self.tick_hz)


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
    block_offset: int,
) -> PcapRecord:
    """Decode an Enhanced or Simple Packet Block body into a :class:`PcapRecord`.

    *block_offset* is the block's position in the file; the record's
    ``data_offset`` is derived from it by stepping over the 8-byte block
    header and the block type's fixed fields.
    """
    if block_type == _PCAPNG_EPB_TYPE:
        if len(body) < 20:
            raise ValueError("EPB body too short")
        iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(
            endian + "IIIII", body,
        )
        body_offset = 20
    else:  # _PCAPNG_OPB_TYPE
        # interface_id(2) drops_count(2) ts_high(4) ts_low(4)
        # captured_len(4) packet_len(4) — 20 bytes before the packet data.
        if len(body) < 20:
            raise ValueError("OPB body too short")
        iface_id, _, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(
            endian + "HHIIII", body,
        )
        body_offset = 20
    pkt_data = body[body_offset : body_offset + cap_len]
    if len(pkt_data) < cap_len:
        raise ValueError("Packet block data truncated")
    ts64 = (ts_hi << 32) | ts_lo
    resolution = interfaces[iface_id][1] if iface_id < len(interfaces) else _US_PER_SECOND
    ts_sec, ts_frac = divmod(ts64, resolution)
    return PcapRecord(
        data=pkt_data,
        ts_sec=ts_sec,
        ts_frac=ts_frac,
        offset=block_offset,
        data_offset=block_offset + _PCAPNG_BLOCK_HDR_SIZE + body_offset,
        orig_len=orig_len,
        tick_hz=resolution,
    )


def _read_pcapng_block(
    reader: _ChainedReader, endian: str,
) -> tuple[int, bytes, int] | None:
    """Read one pcapng block.

    Args:
        reader: Positioned at a block boundary.
        endian: Byte-order prefix for :mod:`struct`.

    Returns:
        A ``(block_type, body, offset)`` tuple, where *offset* is the block's
        position in the file, or ``None`` at end of file.

    Raises:
        ValueError: If the block header, body, or trailing length is
            truncated, or the declared length is below the 12-byte minimum.

    """
    offset = reader.pos
    block_hdr = reader.read(8)
    if not block_hdr:
        return None
    if len(block_hdr) < 8:
        raise ValueError("Truncated pcapng block header")
    block_type, total_len = struct.unpack(endian + "II", block_hdr)
    if total_len < 12:
        raise ValueError(f"Block total length {total_len} too small (minimum 12)")
    body_len = total_len - 12
    body = reader.read(body_len)
    if len(body) < body_len:
        raise ValueError(f"Truncated block body: got {len(body)}, need {body_len}")
    trailing = reader.read(4)
    if len(trailing) < 4:
        raise ValueError("Truncated trailing block total length")
    return (block_type, body, offset)


def _open_pcapng(reader: _ChainedReader) -> tuple[PcapFileHeader, Iterator[PcapRecord]]:
    """Read a pcapng file's header blocks and return a record iterator.

    The Section Header Block is consumed and blocks are then read until the
    first Interface Description Block supplies the link type, snaplen, and
    timestamp resolution — so the returned header is complete before any
    record is yielded.  A packet block encountered first (no IDB, which is
    malformed but readable) ends the search and is handed to the iterator
    rather than dropped.

    Args:
        reader: Positioned at the start of the file.

    Returns:
        A ``(header, records)`` tuple.

    Raises:
        ValueError: If the SHB is truncated or its byte-order magic is
            unrecognised.

    """
    type_raw      = reader.read(4)
    total_len_raw = reader.read(4)
    bom_raw       = reader.read(4)
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
    reader.read(total_len - 12)

    interfaces: list[tuple[int, int]] = []  # (link_type, ticks_per_second)
    link_type = 1
    snaplen   = 65535
    tick_hz   = _US_PER_SECOND
    pending: tuple[int, bytes, int] | None = None

    while True:
        block = _read_pcapng_block(reader, endian)
        if block is None:
            break
        block_type, body, _ = block
        if block_type == _PCAPNG_IDB_TYPE:
            if len(body) < 8:
                raise ValueError("IDB body too short")
            link_type, _, snaplen = struct.unpack_from(endian + "HHI", body)
            tick_hz = _parse_idb_tsresol(body, 8, endian)
            interfaces.append((link_type, tick_hz))
            break
        if block_type in (_PCAPNG_EPB_TYPE, _PCAPNG_OPB_TYPE):
            pending = block
            break

    header = PcapFileHeader(
        link_type=link_type,
        version_major=1,
        version_minor=0,
        snaplen=snaplen,
        tick_hz=tick_hz,
    )
    return (header, _iter_pcapng_records(reader, endian, interfaces, pending))


def _iter_pcapng_records(
    reader: _ChainedReader,
    endian: str,
    interfaces: list[tuple[int, int]],
    pending: tuple[int, bytes, int] | None,
) -> Iterator[PcapRecord]:
    """Yield each packet block as a :class:`PcapRecord`.

    Later Interface Description Blocks are appended to *interfaces* as they
    are met, so a packet block's timestamp resolution is looked up from the
    interface it names.
    """
    block: tuple[int, bytes, int] | None = pending
    while True:
        if block is None:
            block = _read_pcapng_block(reader, endian)
            if block is None:
                return
        block_type, body, offset = block
        block = None

        if block_type == _PCAPNG_IDB_TYPE:
            if len(body) < 8:
                raise ValueError("IDB body too short")
            idb_link_type, _, _ = struct.unpack_from(endian + "HHI", body)
            interfaces.append((idb_link_type, _parse_idb_tsresol(body, 8, endian)))
        elif block_type in (_PCAPNG_EPB_TYPE, _PCAPNG_OPB_TYPE):
            yield _read_pcapng_packet(block_type, body, endian, interfaces, offset)


def _open_pcap(reader: _ChainedReader) -> tuple[PcapFileHeader, Iterator[PcapRecord]]:
    """Read a classic pcap global header and return a record iterator.

    Args:
        reader: Positioned at the start of the file.

    Returns:
        A ``(header, records)`` tuple.

    Raises:
        ValueError: If the global header is short or the magic number is
            unrecognised.

    """
    global_hdr = reader.read(_GLOBAL_HDR_SIZE)
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

    header = PcapFileHeader(
        link_type=link_type,
        version_major=version_major,
        version_minor=version_minor,
        snaplen=snaplen,
        tick_hz=_NS_PER_SECOND if nanoseconds else _US_PER_SECOND,
    )
    return (header, _iter_pcap_records(reader, endian, header.tick_hz))


def _iter_pcap_records(
    reader: _ChainedReader, endian: str, tick_hz: int,
) -> Iterator[PcapRecord]:
    """Yield each classic-pcap packet record as a :class:`PcapRecord`."""
    pkt_fmt = endian + "IIII"
    while True:
        offset = reader.pos
        pkt_hdr_raw = reader.read(_PKT_HDR_SIZE)
        if not pkt_hdr_raw:
            return
        if len(pkt_hdr_raw) < _PKT_HDR_SIZE:
            raise ValueError(
                f"Truncated packet header: got {len(pkt_hdr_raw)} bytes, need {_PKT_HDR_SIZE}"
            )
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(pkt_fmt, pkt_hdr_raw)
        data = reader.read(incl_len)
        if len(data) < incl_len:
            raise ValueError(
                f"Truncated packet data: got {len(data)} bytes, need {incl_len}"
            )
        yield PcapRecord(
            data=data,
            ts_sec=ts_sec,
            ts_frac=ts_frac,
            offset=offset,
            data_offset=offset + _PKT_HDR_SIZE,
            orig_len=orig_len,
            tick_hz=tick_hz,
        )


class _ChainedReader:
    """Serve a small byte prefix, then delegate further reads to a stream.

    Lets the format-detection step peek the 4-byte magic number and then keep
    reading without buffering the whole file, so a capture of any size can be
    read record by record.

    Tracks how many bytes have been consumed in :attr:`pos`.  Neither
    ``io.BytesIO`` positions nor the underlying stream's ``tell()`` correspond
    to an offset within the capture once the prefix is in play, and a source
    stream need not be seekable at all, so the count is kept here — it is the
    only way a record's byte offset can be reported.
    """

    def __init__(self, prefix: bytes, rest: io.RawIOBase | io.BufferedIOBase) -> None:
        self._prefix = prefix
        self._prefix_pos = 0
        self._rest = rest
        self.pos = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            out = self._prefix[self._prefix_pos:] + self._rest.read()
            self._prefix_pos = len(self._prefix)
            self.pos += len(out)
            return out
        out = b""
        if self._prefix_pos < len(self._prefix):
            chunk = self._prefix[self._prefix_pos : self._prefix_pos + size]
            self._prefix_pos += len(chunk)
            out += chunk
            size -= len(chunk)
        if size > 0:
            out += self._rest.read(size)
        self.pos += len(out)
        return out


def _detect_and_open(
    file_obj: io.RawIOBase | io.BufferedIOBase,
) -> tuple[PcapFileHeader, Iterator[PcapRecord]]:
    """Detect pcap vs pcapng from the first 4 bytes and dispatch."""
    header4 = file_obj.read(4)
    if len(header4) < 4:
        raise ValueError(f"File too short: got {len(header4)} bytes, need at least 4")
    (magic,) = struct.unpack_from("<I", header4)
    reader = _ChainedReader(header4, file_obj)
    if magic == _PCAPNG_SHB_TYPE:
        return _open_pcapng(reader)
    return _open_pcap(reader)


class PcapReader:
    """Streaming reader over a pcap or pcapng file.

    Yields one :class:`PcapRecord` at a time instead of materialising every
    packet, so a capture larger than memory can be processed record by record.
    Each record carries its byte offset within the file, which cannot be
    reconstructed afterwards for pcapng — blocks are variable-length and
    option padding is not visible in the decoded data.

    Obtain one from :func:`open_pcap`.  Records are decoded lazily as the
    reader is iterated, so the file stays open until the reader is closed —
    unlike :func:`read_pcap`, which returns a finished result and holds
    nothing open.  Use it as a context manager and that is handled:

    .. code-block:: python

        from packeteer.pcap import open_pcap

        with open_pcap(path="capture.pcap") as reader:
            print(reader.header.link_type)
            for record in reader:
                print(record.offset, record.ts_sec, len(record.data))

    Closing is the caller's responsibility, and neither exhausting the
    iterator nor an error raised part-way through it closes the file.  A
    reader dropped without closing leaks the handle until it is collected,
    which raises a ``ResourceWarning``.  Without a ``with`` block, close it
    from a ``finally``.

    Attributes:
        header: File-level metadata, populated before the first record is
            read.  For pcapng this comes from the first Interface Description
            Block; a file whose interfaces declare different link types is
            described by the first one.

    """

    def __init__(
        self,
        header: PcapFileHeader,
        records: Iterator[PcapRecord],
        stack: ExitStack,
    ) -> None:
        self.header = header
        self._records = records
        self._stack = stack

    def __iter__(self) -> Iterator[PcapRecord]:
        """Iterate the capture's packet records."""
        return self._records

    def __enter__(self) -> PcapReader:
        """Enter the context manager, returning this reader."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the underlying file if this reader opened it."""
        self.close()

    def close(self) -> None:
        """Close the underlying file, if this reader opened it from a path.

        Safe to call more than once, and safe to call from a ``finally`` block
        alongside a ``with`` statement.

        A reader created from a *file_object* never closes it — the caller
        owns that object, so only a file this reader opened is registered for
        closing.  Iteration cannot continue after closing.
        """
        self._stack.close()


def open_pcap(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
    link_type: int | None = None,
) -> PcapReader:
    """Open a ``.pcap`` or ``.pcapng`` file for streaming, record by record.

    The eager counterpart is :func:`read_pcap`, which returns every packet in
    a list; prefer this when a capture is large, when only a prefix is needed,
    or when a record's byte offset matters.  The format is detected from the
    magic number, so both pcap and pcapng are accepted.

    Exactly one of *path* or *file_object* must be supplied.

    The returned reader keeps the file open while records are read from it,
    so **close it when done** — as a context manager, or from a ``finally``
    block.  Neither running out of records nor an error during iteration
    closes it.  See :class:`PcapReader` for the full contract.

    Args:
        path: Path to the file to read.  The reader opens it and closes it on
            :meth:`PcapReader.close` or context-manager exit.
        file_object: Readable binary file-like object positioned at the start
            of the data.  It is never closed by the reader — the caller keeps
            ownership of an object it supplied.
        link_type: When given, override the link-layer type recorded in the
            file header.  :attr:`PcapReader.header` reflects the override.

    Returns:
        A :class:`PcapReader` whose ``header`` is already populated and which
        iterates :class:`PcapRecord` objects.

    Raises:
        ValueError: If neither or both of *path* / *file_object* are given, if
            the magic number is unrecognised, or if the file header is
            truncated.  A malformed *record* raises during iteration instead.
            Nothing leaks when this is raised: a file opened here is closed
            before the exception propagates, and no reader is returned.
        OSError: If *path* cannot be opened for reading.

    Example::

        from packeteer.pcap import open_pcap

        with open_pcap(path="capture.pcap") as reader:
            for record in reader:
                print(record.data_offset, record.orig_len)

    """
    if (path is None) == (file_object is None):
        raise ValueError("Provide exactly one of 'path' or 'file_object'.")

    stack = ExitStack()
    try:
        if path is not None:
            # Spelled out rather than open(path, "rb") — which returns exactly
            # this pair — because the reader hands the file's lifetime to the
            # caller, so it cannot be acquired by a `with` block here.
            source: io.RawIOBase | io.BufferedIOBase = stack.enter_context(
                io.BufferedReader(io.FileIO(path, "rb")),
            )
        else:
            assert file_object is not None
            source = file_object
        header, records = _detect_and_open(source)
    except BaseException:
        stack.close()
        raise

    if link_type is not None:
        header.link_type = link_type
    return PcapReader(header, records, stack)


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
    if max_packets is not None and max_packets < 0:
        raise ValueError(f"max_packets must be non-negative, got {max_packets}")

    with open_pcap(path=path, file_object=file_object, link_type=link_type) as reader:
        records: Iterator[PcapRecord] = iter(reader)
        if max_packets is not None:
            records = itertools.islice(records, max_packets)
        packets = [(r.data, r.ts_sec, r.ts_frac) for r in records]
    return PcapFile(header=reader.header, packets=packets)


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
    tick_hz: int | None = None,
) -> datetime:
    """Convert a pcap ``(ts_sec, ts_frac)`` pair to a timezone-aware UTC datetime.

    The inverse of :func:`datetime_to_pcap_ts`, for turning the tuples returned
    by :func:`read_pcap` back into :class:`~datetime.datetime` objects::

        pcap = read_pcap(path="in.pcap")
        for data, ts_sec, ts_frac in pcap.packets:
            when = pcap_ts_to_datetime(ts_sec, ts_frac, tick_hz=pcap.header.tick_hz)

    Pass *tick_hz* rather than *nanoseconds*: a pcapng may declare any
    resolution, and the boolean can only say microseconds or nanoseconds, so
    it reads a millisecond capture's fraction a thousand times too small.

    Because :class:`~datetime.datetime` only has microsecond resolution, any
    finer part of the timestamp is truncated.

    Args:
        ts_sec: Whole seconds since the Unix epoch.
        ts_frac: Sub-second remainder, in units of *tick_hz*.
        nanoseconds: Legacy selector, used only when *tick_hz* is omitted:
            ``True`` interprets *ts_frac* as nanoseconds, ``False`` (the
            default) as microseconds.
        tick_hz: Ticks per second that *ts_frac* is expressed in — take it
            from :attr:`PcapFileHeader.tick_hz` or
            :attr:`PcapRecord.tick_hz`.  Overrides *nanoseconds* when given.

    Returns:
        A timezone-aware :class:`~datetime.datetime` in UTC.

    """
    if tick_hz is None:
        tick_hz = _NS_PER_SECOND if nanoseconds else _US_PER_SECOND
    us = ts_frac * _US_PER_SECOND // tick_hz
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
