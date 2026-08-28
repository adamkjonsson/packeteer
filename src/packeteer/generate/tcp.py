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
TCP_ECE: int = 0x040  # ECN-Echo: SYN=1 → ECN-capable; SYN=0 → congestion experienced (RFC 3168)
TCP_CWR: int = 0x080  # Congestion Window Reduced — sender reduced its congestion window (RFC 3168)


@dataclass
class TCPOptions:
    """Optional fields carried in the TCP header Options area (RFC 9293 §3.2).

    Each attribute corresponds to one well-known TCP option.  Set an attribute
    to a non-None / non-False value to include that option in the header.
    Options are encoded in the order MSS → Window Scale → SACK Permitted →
    Timestamps → SACK, followed by NOP (0x01) padding to the nearest 4-byte
    boundary — unless *raw* holds the bytes to write instead.

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
        unknown: Options with no dedicated field above, as ``(kind, value)``
            pairs where *value* is the option's bytes excluding the kind and
            length bytes.  The parser puts anything it does not model here —
            including a recognised kind carrying an unexpected length — and
            the builder re-emits them, so an option survives a parse → build
            round trip even when packeteer does not understand it.  Defaults
            to an empty list.
        raw: The option region exactly as captured, written out verbatim in
            place of a re-encoding.  The parser sets it only when re-encoding
            the decoded options would *not* reproduce the captured bytes —
            different option order, or NOP padding in a different place — so it
            is ``None`` for options the encoder round-trips on its own, and
            ordinary specs never carry it.

            **It takes precedence over every other attribute.**  Editing
            ``mss`` or ``timestamps`` on an instance whose *raw* is set has no
            effect on the encoded header; clear *raw* first when changing a
            field.

    """

    mss: int | None = None
    window_scale: int | None = None
    sack_permitted: bool = False
    sack_blocks: list[tuple[int, int]] = field(default_factory=list)
    timestamps: tuple[int, int] | None = None
    unknown: list[tuple[int, bytes]] = field(default_factory=list)
    raw: bytes | None = None


#: Window scale a modern client advertises: a 64 KiB window scaled by 2**7.
DEFAULT_WINDOW_SCALE: int = 7

#: MSS a client advertises on an Ethernet IPv4 path: 1500 - 20 (IP) - 20 (TCP).
DEFAULT_MSS: int = 1460


def default_syn_options(mss: int = DEFAULT_MSS) -> TCPOptions:
    """Return the TCP options a plausible modern client puts on a SYN.

    Every current stack advertises at least a Maximum Segment Size, and
    generally SACK-permitted and a window scale beside it.  A SYN carrying no
    options at all — a bare 20-byte header — is the most conspicuous mark of
    generated traffic in a TCP capture, which is what this exists to avoid.

    Timestamps are deliberately absent.  A connection that negotiates them
    carries one on *every* segment, and the generators put options on the
    handshake only; advertising them and then never sending one would trade
    one implausibility for another.

    Args:
        mss: Maximum Segment Size to advertise.  Pass the value the traffic is
            actually segmented at, so the capture and its own advertisement
            agree.

    Returns:
        A fresh :class:`TCPOptions`; callers may modify it freely.

    """
    return TCPOptions(
        mss=mss, sack_permitted=True, window_scale=DEFAULT_WINDOW_SCALE,
    )


def _align_nops(offset: int) -> bytes:
    """NOP padding placing the option that follows on a useful boundary.

    Timestamps and SACK carry 32-bit fields after a two-byte kind and length,
    so a sender puts NOPs ahead of them until the option starts two bytes short
    of a four-byte boundary, leaving those fields aligned.  RFC 7323 A.2
    recommends exactly this for Timestamps — ``NOP, NOP, Timestamp`` — and it
    is what real senders emit.

    Padding placed *after* an option instead would leave the same option
    present with the same value, but arranged as no stack arranges it.

    Args:
        offset: How many option bytes have been written so far.

    Returns:
        Zero to three NOP bytes.

    """
    return b"\x01" * ((2 - offset) % 4)


def _build_options(opts: TCPOptions) -> bytes:
    """Encode *opts* as bytes padded to a 4-byte boundary with NOP (0x01).

    When ``opts.raw`` is set it is returned verbatim.  That is how a capture's
    own option layout survives a parse → build round trip: senders order
    options differently and place NOP padding ahead of the option it aligns,
    whereas the encoding below is canonical, so re-encoding preserves every
    option's presence and value but not the original bytes.  Stacks disagree
    with each other too — Linux and macOS lay out a SYN's options differently
    — so replaying what was captured is the only thing that reproduces them in
    general.

    Otherwise options are emitted in the order:
    MSS (2) → Window Scale (3) → SACK Permitted (4) → Timestamps (8) →
    SACK (5) → anything in ``unknown``.

    NOP padding goes **ahead** of Timestamps and SACK, so that their 32-bit
    fields land on a four-byte boundary the way a sender aligns them (see
    :func:`_align_nops`); any remainder pads the tail.

    Args:
        opts: The options to encode.

    Returns:
        The encoded option region, a multiple of 4 bytes long.

    """
    if opts.raw is not None:
        return opts.raw

    raw = b""
    if opts.mss is not None:
        raw += struct.pack("!BBH", 2, 4, opts.mss)
    if opts.window_scale is not None:
        raw += struct.pack("!BBB", 3, 3, opts.window_scale)
    if opts.sack_permitted:
        raw += struct.pack("!BB", 4, 2)
    if opts.timestamps is not None:
        tsval, tsecr = opts.timestamps
        raw += _align_nops(len(raw)) + struct.pack("!BBII", 8, 10, tsval, tsecr)
    if opts.sack_blocks:
        sack_len = 2 + 8 * len(opts.sack_blocks)
        raw += _align_nops(len(raw)) + struct.pack("!BB", 5, sack_len)
        for left, right in opts.sack_blocks:
            raw += struct.pack("!II", left, right)
    for kind, value in opts.unknown:
        raw += struct.pack("!BB", kind, 2 + len(value)) + value
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
        checksum: Explicit checksum, overriding the computed one.  ``None``
            (the default) computes it.  TCP has no length field of its own, so
            this is the only field a fragmented datagram's first fragment needs
            recorded: the pseudo-header length used for the checksum covers the
            whole datagram, not the fragment.  Setting it also reproduces a
            checksum that was wrong on the wire.

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
    checksum: int | None = None


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


def _build_tcp_header(
    hdr: TCPHeader,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ip_version: int = 4,
) -> bytes:
    r"""Build a TCP header with a correct checksum.

    The minimum header is 20 bytes (data offset = 5) with no options.  When
    TCP options are present in *hdr*, the data offset and total header length
    are adjusted accordingly (maximum 60 bytes per RFC 9293).  The checksum
    is computed over the appropriate pseudo-header (IPv4 or IPv6) concatenated
    with the TCP header and *payload*, as required by RFC 793 / RFC 8200 —
    unless ``hdr.checksum`` is set, in which case it is written out as given.

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

    if hdr.checksum is not None:
        return raw[:16] + struct.pack('!H', hdr.checksum) + raw[18:]

    if ip_version == 6:
        pseudo = _pseudo_header_v6(src_ip, dst_ip, tcp_length)
    else:
        pseudo = _pseudo_header_v4(src_ip, dst_ip, tcp_length)

    checksum = ones_complement_checksum(pseudo + raw + payload)
    return raw[:16] + struct.pack('!H', checksum) + raw[18:]
