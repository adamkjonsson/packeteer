"""TCP header construction (RFC 9293).

This module builds TCP headers (minimum 20 bytes with no options, up to 60
bytes with options) and computes the TCP checksum over the appropriate IPv4
or IPv6 pseudo-header as required by the respective RFCs.

Pseudo-header formats used for checksum calculation:

* **IPv4** (RFC 793, 12 bytes)::

      Source IP (4) | Dest IP (4) | Zero (1) | Protocol=6 (1) | TCP length (2)

* **IPv6** (RFC 8200 §8.1, 40 bytes)::

      Source IP (16) | Dest IP (16) | TCP length (4) | Zeros (3) | Next Header=6 (1)
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .checksum import ones_complement_checksum

# TCP control flag bit masks (RFC 9293 §3.1)
# Bit order within the flags byte (MSB → LSB): CWR ECE URG ACK PSH RST SYN FIN
TCP_FIN: int = 0x001  # No more data from sender
TCP_SYN: int = 0x002  # Synchronise sequence numbers
TCP_RST: int = 0x004  # Reset the connection
TCP_PSH: int = 0x008  # Push buffered data to the application
TCP_ACK: int = 0x010  # Acknowledgement field is significant
TCP_URG: int = 0x020  # Urgent pointer field is significant
TCP_ECE: int = 0x040  # ECN-Echo: SYN=1 → sender is ECN-capable; SYN=0 → congestion experienced (RFC 3168)
TCP_CWR: int = 0x080  # Congestion Window Reduced — sender reduced its congestion window (RFC 3168)


@dataclass
class TCPOptions:
    """Optional fields carried in the TCP header Options area (RFC 9293 §3.2).

    Each attribute corresponds to one well-known TCP option.  Set an attribute
    to a non-None / non-False value to include that option in the header.
    Options are encoded in the order MSS → Window Scale → SACK Permitted →
    Timestamps → SACK, followed by NOP (0x01) padding to the nearest 4-byte
    boundary.

    Attributes:
        mss: Maximum Segment Size (kind 2, length 4).  16-bit value in bytes.
            Typical values: ``1460`` (Ethernet IPv4), ``1440`` (Ethernet IPv6).
        window_scale: Window Scale shift count (kind 3, length 3).  Scales the
            ``window`` field by ``2**window_scale``.  Valid range 0–14
            (RFC 7323 §2).
        sack_permitted: SACK Permitted option (kind 4, length 2).  When
            ``True``, signals that the sender is willing to receive SACK blocks.
            Typically sent on SYN and SYN-ACK segments only.
        sack_blocks: Selective Acknowledgement blocks (kind 5).  List of
            ``(left_edge, right_edge)`` sequence-number pairs, each a 32-bit
            unsigned integer.  Up to four blocks per segment (RFC 2018).
        timestamps: TCP Timestamps option (kind 8, length 10).  Tuple of
            ``(TSval, TSecr)`` — the sender's timestamp value and the most
            recent timestamp received from the remote end.  Both are 32-bit
            unsigned integers (RFC 7323 §3).
    """

    mss: int | None = None
    window_scale: int | None = None
    sack_permitted: bool = False
    sack_blocks: list[tuple[int, int]] = field(default_factory=list)
    timestamps: tuple[int, int] | None = None


def _build_options(opts: TCPOptions) -> bytes:
    """Encode *opts* as bytes padded to a 4-byte boundary with NOP (0x01).

    Options are emitted in the order:
    MSS (2) → Window Scale (3) → SACK Permitted (4) → Timestamps (8) → SACK (5).
    """
    raw = b""
    if opts.mss is not None:
        raw += struct.pack("!BBH", 2, 4, opts.mss)
    if opts.window_scale is not None:
        raw += struct.pack("!BBB", 3, 3, opts.window_scale)
    if opts.sack_permitted:
        raw += struct.pack("!BB", 4, 2)
    if opts.timestamps is not None:
        tsval, tsecr = opts.timestamps
        raw += struct.pack("!BBII", 8, 10, tsval, tsecr)
    if opts.sack_blocks:
        sack_len = 2 + 8 * len(opts.sack_blocks)
        raw += struct.pack("!BB", 5, sack_len)
        for left, right in opts.sack_blocks:
            raw += struct.pack("!II", left, right)
    # Pad to 4-byte boundary with NOP (kind 1)
    remainder = len(raw) % 4
    if remainder:
        raw += b"\x01" * (4 - remainder)
    return raw


@dataclass
class TCPHeader:
    """Fields of a TCP segment header.

    Attributes:
        src_port: Source port number (0–65535).
        dst_port: Destination port number (0–65535).
        seq: 32-bit sequence number.  Defaults to ``0``.
        ack: 32-bit acknowledgement number.  Defaults to ``0``.
        reserved: 4-bit reserved field between Data Offset and the flags byte.
            Must be zero per RFC 9293; exposed here for completeness.
            Defaults to ``0``.
        flags: 8-bit control flags bitmask.  Use the module-level flag
            constants — :data:`TCP_FIN`, :data:`TCP_SYN`, :data:`TCP_RST`,
            :data:`TCP_PSH`, :data:`TCP_ACK`, :data:`TCP_URG`,
            :data:`TCP_ECE`, :data:`TCP_CWR` — or combine them with ``|``::

                TCPHeader(src_port=1234, dst_port=80, flags=TCP_PSH | TCP_ACK)

            Defaults to :data:`TCP_ACK` (``0x010``).
        window: Receive-window size in bytes advertised by the sender.
            Defaults to ``65535``.
        urgent_ptr: Urgent pointer; only meaningful when the URG flag is set.
            Defaults to ``0``.
        options: Optional TCP header options.  When set, the Data Offset field
            is adjusted automatically to reflect the extended header length.
            Defaults to ``None`` (no options, 20-byte header).
    """

    src_port: int
    dst_port: int
    seq: int = 0
    ack: int = 0
    reserved: int = 0
    flags: int = TCP_ACK
    window: int = 65535
    urgent_ptr: int = 0
    options: TCPOptions | None = None


def _pseudo_header_v4(src_ip: str, dst_ip: str, tcp_length: int) -> bytes:
    """Build the 12-byte IPv4 TCP pseudo-header used for checksum calculation.

    Args:
        src_ip: Source IPv4 address in dotted-decimal notation.
        dst_ip: Destination IPv4 address in dotted-decimal notation.
        tcp_length: Total length of the TCP segment (header + payload) in bytes.

    Returns:
        12 bytes: src(4) + dst(4) + zero(1) + protocol=6(1) + tcp_length(2).
    """
    return (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 6, tcp_length)
    )


def _pseudo_header_v6(src_ip: str, dst_ip: str, tcp_length: int) -> bytes:
    """Build the 40-byte IPv6 TCP pseudo-header used for checksum calculation.

    Args:
        src_ip: Source IPv6 address in any notation accepted by
            :func:`socket.inet_pton`.
        dst_ip: Destination IPv6 address in the same format.
        tcp_length: Total length of the TCP segment (header + payload) in bytes.

    Returns:
        40 bytes: src(16) + dst(16) + tcp_length(4) + zeros(3) + next_header=6(1).
    """
    return (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', tcp_length, b'\x00\x00\x00', 6)
    )


def build_tcp_header(
    hdr: TCPHeader,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ip_version: int = 4,
) -> bytes:
    """Build a TCP header with a correct checksum.

    The minimum header is 20 bytes (data offset = 5) with no options.  When
    TCP options are present in *hdr*, the data offset and total header length
    are adjusted accordingly (maximum 60 bytes per RFC 9293).  The checksum
    is computed over the appropriate pseudo-header (IPv4 or IPv6) concatenated
    with the TCP header and *payload*, as required by RFC 793 / RFC 8200.

    Args:
        hdr: A :class:`TCPHeader` instance with the desired field values.
        payload: Application-layer payload bytes that will follow this TCP
            header.  Included in the checksum calculation but **not** in the
            returned bytes.
        src_ip: Source IP address (IPv4 dotted-decimal or IPv6 colon-hex),
            used to build the pseudo-header.
        dst_ip: Destination IP address in the same format as *src_ip*.
        ip_version: ``4`` for IPv4 pseudo-header (default) or ``6`` for
            IPv6 pseudo-header.

    Returns:
        Exactly 20 bytes representing the TCP header in network byte order,
        with a valid checksum.

    Raises:
        OSError: If *src_ip* or *dst_ip* is not a valid address for the
            specified *ip_version*.

    Example:
        >>> from packet_generator.tcp import TCPHeader, build_tcp_header
        >>> hdr = TCPHeader(src_port=12345, dst_port=80)
        >>> raw = build_tcp_header(hdr, b"GET / HTTP/1.0\\r\\n", "10.0.0.1", "10.0.0.2")
        >>> len(raw)
        20
        >>> (raw[12] >> 4)  # data offset (should be 5)
        5
    """
    options_bytes = _build_options(hdr.options) if hdr.options is not None else b""
    data_offset = 5 + len(options_bytes) // 4   # in 32-bit words
    data_offset_reserved = (data_offset << 4) | (hdr.reserved & 0xF)
    tcp_length = 20 + len(options_bytes) + len(payload)

    raw = struct.pack(
        '!HHIIBBHHH',
        hdr.src_port,
        hdr.dst_port,
        hdr.seq,
        hdr.ack,
        data_offset_reserved,
        hdr.flags,
        hdr.window,
        0,                  # checksum placeholder
        hdr.urgent_ptr,
    ) + options_bytes

    if ip_version == 6:
        pseudo = _pseudo_header_v6(src_ip, dst_ip, tcp_length)
    else:
        pseudo = _pseudo_header_v4(src_ip, dst_ip, tcp_length)

    checksum = ones_complement_checksum(pseudo + raw + payload)
    return raw[:16] + struct.pack('!H', checksum) + raw[18:]
