"""SCTP packet builder (RFC 9260).

This module provides dataclasses for every SCTP chunk type defined in
RFC 9260 and a :func:`build_sctp_packet` function that assembles them into
wire-format bytes with a correct CRC-32c checksum.

SCTP packet structure::

    Common Header (12 bytes)
        Source Port       (2)
        Destination Port  (2)
        Verification Tag  (4)
        Checksum          (4)  — CRC-32c, RFC 9260 §6.8

    One or more chunks, each 4-byte aligned::
        Type    (1)
        Flags   (1)
        Length  (2)  — includes the 4-byte chunk header, excludes padding
        Value   (Length - 4 bytes)
        Padding (0–3 zero bytes to reach next 4-byte boundary, NOT in Length)

Chunk types (RFC 9260 §3.3):

    0   DATA
    1   INIT
    2   INIT ACK
    3   SACK
    4   HEARTBEAT
    5   HEARTBEAT ACK
    6   ABORT
    7   SHUTDOWN
    8   SHUTDOWN ACK
    9   ERROR
    10  COOKIE ECHO
    11  COOKIE ACK
    14  SHUTDOWN COMPLETE

Example::

    from packet_generator.sctp import (
        SCTPHeader, SCTPDataChunk, build_sctp_packet,
        SCTP_DATA_FLAG_BEGINNING, SCTP_DATA_FLAG_ENDING,
    )

    hdr = SCTPHeader(
        src_port=1234,
        dst_port=9999,
        verification_tag=0xDEADBEEF,
        chunks=[
            SCTPDataChunk(
                tsn=0,
                stream_id=0,
                stream_seq=0,
                ppid=0,
                data=b"Hello, SCTP!",
                flags=SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING,
            )
        ],
    )
    raw = build_sctp_packet(hdr)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Union

from .checksum import crc32c

# ── Protocol constant ─────────────────────────────────────────────────────────

IPPROTO_SCTP: int = 132

# ── Chunk type constants ──────────────────────────────────────────────────────

SCTP_CHUNK_DATA:              int = 0
SCTP_CHUNK_INIT:              int = 1
SCTP_CHUNK_INIT_ACK:          int = 2
SCTP_CHUNK_SACK:              int = 3
SCTP_CHUNK_HEARTBEAT:         int = 4
SCTP_CHUNK_HEARTBEAT_ACK:     int = 5
SCTP_CHUNK_ABORT:             int = 6
SCTP_CHUNK_SHUTDOWN:          int = 7
SCTP_CHUNK_SHUTDOWN_ACK:      int = 8
SCTP_CHUNK_ERROR:             int = 9
SCTP_CHUNK_COOKIE_ECHO:       int = 10
SCTP_CHUNK_COOKIE_ACK:        int = 11
SCTP_CHUNK_SHUTDOWN_COMPLETE: int = 14

# ── DATA chunk flag bits (RFC 9260 §3.3.1) ────────────────────────────────────

SCTP_DATA_FLAG_ENDING:    int = 0x01  # E — last (or only) fragment
SCTP_DATA_FLAG_BEGINNING: int = 0x02  # B — first (or only) fragment
SCTP_DATA_FLAG_UNORDERED: int = 0x04  # U — unordered delivery
SCTP_DATA_FLAG_IMMEDIATE: int = 0x08  # I — immediate send (RFC 9260 §3.3.1)

# ── Chunk dataclasses ─────────────────────────────────────────────────────────


@dataclass
class SCTPDataChunk:
    """SCTP DATA chunk (type 0, RFC 9260 §3.3.1).

    Carries user payload from one endpoint to the other.

    Attributes:
        tsn: Transmission Sequence Number (32-bit).
        stream_id: Stream Identifier (16-bit).
        stream_seq: Stream Sequence Number (16-bit).  Ignored when the
            Unordered (U) flag is set.
        ppid: Payload Protocol Identifier (32-bit).  Not interpreted by
            SCTP; used by the upper layer to identify the data type.
        data: User payload bytes.
        flags: Chunk flags byte.  Combine :data:`SCTP_DATA_FLAG_BEGINNING`,
            :data:`SCTP_DATA_FLAG_ENDING`, :data:`SCTP_DATA_FLAG_UNORDERED`,
            and :data:`SCTP_DATA_FLAG_IMMEDIATE`.  Defaults to B|E (complete,
            unfragmented message).

    """

    tsn:        int
    stream_id:  int   = 0
    stream_seq: int   = 0
    ppid:       int   = 0
    data:       bytes = b""
    flags:      int   = SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING


@dataclass
class SCTPInitChunk:
    """SCTP INIT chunk (type 1, RFC 9260 §3.3.2).

    Sent by an endpoint to initiate an association.

    Attributes:
        initiate_tag: Verification tag chosen by the sender (32-bit).
        a_rwnd: Advertised Receiver Window Credit in bytes (32-bit).
        outbound_streams: Number of outbound streams requested (16-bit).
        inbound_streams: Maximum inbound streams the sender will accept (16-bit).
        initial_tsn: Initial TSN value (32-bit).
        params: Raw bytes of optional/variable-length parameters that follow
            the fixed fields (e.g. Supported Address Types, ECN Capable).

    """

    initiate_tag:     int   = 0
    a_rwnd:           int   = 131072
    outbound_streams: int   = 1
    inbound_streams:  int   = 1
    initial_tsn:      int   = 0
    params:           bytes = b""


@dataclass
class SCTPInitAckChunk:
    """SCTP INIT ACK chunk (type 2, RFC 9260 §3.3.3).

    Response to an INIT; same fixed fields plus a State Cookie parameter.

    Attributes:
        initiate_tag: Verification tag chosen by the responder (32-bit).
        a_rwnd: Advertised Receiver Window Credit (32-bit).
        outbound_streams: Number of outbound streams the responder supports (16-bit).
        inbound_streams: Maximum inbound streams the responder will accept (16-bit).
        initial_tsn: Initial TSN value (32-bit).
        params: Raw bytes of optional/variable-length parameters (must include
            a State Cookie parameter — type 7).

    """

    initiate_tag:     int   = 0
    a_rwnd:           int   = 131072
    outbound_streams: int   = 1
    inbound_streams:  int   = 1
    initial_tsn:      int   = 0
    params:           bytes = b""


@dataclass
class SCTPSackChunk:
    """SCTP SACK chunk (type 3, RFC 9260 §3.3.4).

    Selective acknowledgement of received DATA chunks.

    Attributes:
        cum_tsn_ack: Cumulative TSN Acknowledgement (32-bit).
        a_rwnd: Advertised Receiver Window Credit (32-bit).
        gap_ack_blocks: List of ``(start, end)`` pairs of TSN gap blocks
            relative to *cum_tsn_ack* (each value 16-bit).
        dup_tsns: List of duplicate TSNs received (each 32-bit).

    """

    cum_tsn_ack:    int                     = 0
    a_rwnd:         int                     = 131072
    gap_ack_blocks: list[tuple[int, int]]   = field(default_factory=list)
    dup_tsns:       list[int]               = field(default_factory=list)


@dataclass
class SCTPHeartbeatChunk:
    """SCTP HEARTBEAT chunk (type 4, RFC 9260 §3.3.5).

    Keep-alive probe; the receiver must echo the info back in a HEARTBEAT ACK.

    Attributes:
        info: Sender-specific heartbeat information bytes.  Encoded on the
            wire as a Heartbeat Info parameter (type 1).

    """

    info: bytes = b""


@dataclass
class SCTPHeartbeatAckChunk:
    """SCTP HEARTBEAT ACK chunk (type 5, RFC 9260 §3.3.6).

    Echo response to a HEARTBEAT.

    Attributes:
        info: The heartbeat info bytes copied verbatim from the HEARTBEAT.

    """

    info: bytes = b""


@dataclass
class SCTPAbortChunk:
    """SCTP ABORT chunk (type 6, RFC 9260 §3.3.7).

    Abruptly terminates an association.

    Attributes:
        causes: Raw bytes of zero or more Error Cause blocks.
        flags: Chunk flags byte.  Bit 0 (T) indicates the Verification Tag
            is reflected from the peer (not from the sender's own tag).

    """

    causes: bytes = b""
    flags:  int   = 0


@dataclass
class SCTPShutdownChunk:
    """SCTP SHUTDOWN chunk (type 7, RFC 9260 §3.3.8).

    Initiates the graceful shutdown of an association.

    Attributes:
        cum_tsn_ack: Cumulative TSN acknowledged up to this point (32-bit).

    """

    cum_tsn_ack: int = 0


@dataclass
class SCTPShutdownAckChunk:
    """SCTP SHUTDOWN ACK chunk (type 8, RFC 9260 §3.3.9).

    Acknowledges a SHUTDOWN chunk.  Carries no fields beyond the chunk header.
    """


@dataclass
class SCTPErrorChunk:
    """SCTP ERROR chunk (type 9, RFC 9260 §3.3.10).

    Reports one or more error conditions.

    Attributes:
        causes: Raw bytes of one or more Error Cause blocks.

    """

    causes: bytes = b""


@dataclass
class SCTPCookieEchoChunk:
    """SCTP COOKIE ECHO chunk (type 10, RFC 9260 §3.3.11).

    Echoes the State Cookie received in an INIT ACK back to the responder.

    Attributes:
        cookie: The opaque cookie bytes from the INIT ACK.

    """

    cookie: bytes = b""


@dataclass
class SCTPCookieAckChunk:
    """SCTP COOKIE ACK chunk (type 11, RFC 9260 §3.3.12).

    Acknowledges a COOKIE ECHO.  Carries no fields beyond the chunk header.
    """


@dataclass
class SCTPShutdownCompleteChunk:
    """SCTP SHUTDOWN COMPLETE chunk (type 14, RFC 9260 §3.3.13).

    Final chunk in the shutdown sequence.

    Attributes:
        flags: Chunk flags byte.  Bit 0 (T) has the same meaning as in
            :class:`SCTPAbortChunk`.

    """

    flags: int = 0


@dataclass
class SCTPGenericChunk:
    """Fallback container for chunk types not explicitly decoded.

    Attributes:
        chunk_type: Raw chunk type byte (0–255).
        flags: Chunk flags byte.
        value: Raw value bytes (excluding the 4-byte chunk header).

    """

    chunk_type: int   = 0
    flags:      int   = 0
    value:      bytes = b""


# Union type for all chunk variants
SCTPChunk = Union[
    SCTPDataChunk,
    SCTPInitChunk,
    SCTPInitAckChunk,
    SCTPSackChunk,
    SCTPHeartbeatChunk,
    SCTPHeartbeatAckChunk,
    SCTPAbortChunk,
    SCTPShutdownChunk,
    SCTPShutdownAckChunk,
    SCTPErrorChunk,
    SCTPCookieEchoChunk,
    SCTPCookieAckChunk,
    SCTPShutdownCompleteChunk,
    SCTPGenericChunk,
]


@dataclass
class SCTPHeader:
    """SCTP common header plus a list of chunks.

    Attributes:
        src_port: Source port number (16-bit).
        dst_port: Destination port number (16-bit).
        verification_tag: Verification Tag (32-bit).  Both endpoints agree
            on each other's tag during the handshake.
        chunks: List of SCTP chunks to include in this packet.  Defaults to
            a single unfragmented DATA chunk carrying an empty payload when
            ``None`` is passed to :func:`build_sctp_packet`.

    """

    src_port:         int             = 0
    dst_port:         int             = 0
    verification_tag: int             = 0
    chunks:           list[SCTPChunk] = field(default_factory=list)


# ── Wire encoding helpers ─────────────────────────────────────────────────────

def _pad4(n: int) -> int:
    """Round *n* up to the next multiple of 4."""
    return (n + 3) & ~3


def _encode_chunk(chunk: SCTPChunk) -> bytes:
    """Encode one SCTP chunk to wire bytes (including any 4-byte padding)."""
    if isinstance(chunk, SCTPDataChunk):
        value = struct.pack(
            "!IHHH",
            chunk.tsn,
            chunk.stream_id,
            chunk.stream_seq,
            0,          # padding for alignment in the fixed header
        )
        # Replace the last 2 bytes (padding) with ppid high bytes, then add
        # ppid low bytes — actually simpler to re-pack the full 12-byte value:
        value = struct.pack(
            "!IHHI",
            chunk.tsn,
            chunk.stream_id,
            chunk.stream_seq,
            chunk.ppid,
        ) + chunk.data
        chunk_type  = SCTP_CHUNK_DATA
        chunk_flags = chunk.flags

    elif isinstance(chunk, (SCTPInitChunk, SCTPInitAckChunk)):
        value = struct.pack(
            "!IIHHI",
            chunk.initiate_tag,
            chunk.a_rwnd,
            chunk.outbound_streams,
            chunk.inbound_streams,
            chunk.initial_tsn,
        ) + chunk.params
        chunk_type  = SCTP_CHUNK_INIT if isinstance(chunk, SCTPInitChunk) else SCTP_CHUNK_INIT_ACK
        chunk_flags = 0

    elif isinstance(chunk, SCTPSackChunk):
        n_gap = len(chunk.gap_ack_blocks)
        n_dup = len(chunk.dup_tsns)
        value = struct.pack("!IIHH", chunk.cum_tsn_ack, chunk.a_rwnd, n_gap, n_dup)
        for start, end in chunk.gap_ack_blocks:
            value += struct.pack("!HH", start, end)
        for tsn in chunk.dup_tsns:
            value += struct.pack("!I", tsn)
        chunk_type  = SCTP_CHUNK_SACK
        chunk_flags = 0

    elif isinstance(chunk, (SCTPHeartbeatChunk, SCTPHeartbeatAckChunk)):
        # Heartbeat Info parameter: type=1, length=4+len(info), data
        hb_len = 4 + len(chunk.info)
        param  = struct.pack("!HH", 1, hb_len) + chunk.info
        # Pad the parameter itself to a 4-byte boundary
        if hb_len % 4:
            param += b"\x00" * (4 - hb_len % 4)
        value       = param
        chunk_type  = (
            SCTP_CHUNK_HEARTBEAT if isinstance(chunk, SCTPHeartbeatChunk)
            else SCTP_CHUNK_HEARTBEAT_ACK
        )
        chunk_flags = 0

    elif isinstance(chunk, SCTPAbortChunk):
        value       = chunk.causes
        chunk_type  = SCTP_CHUNK_ABORT
        chunk_flags = chunk.flags

    elif isinstance(chunk, SCTPShutdownChunk):
        value       = struct.pack("!I", chunk.cum_tsn_ack)
        chunk_type  = SCTP_CHUNK_SHUTDOWN
        chunk_flags = 0

    elif isinstance(chunk, SCTPShutdownAckChunk):
        value       = b""
        chunk_type  = SCTP_CHUNK_SHUTDOWN_ACK
        chunk_flags = 0

    elif isinstance(chunk, SCTPErrorChunk):
        value       = chunk.causes
        chunk_type  = SCTP_CHUNK_ERROR
        chunk_flags = 0

    elif isinstance(chunk, SCTPCookieEchoChunk):
        value       = chunk.cookie
        chunk_type  = SCTP_CHUNK_COOKIE_ECHO
        chunk_flags = 0

    elif isinstance(chunk, SCTPCookieAckChunk):
        value       = b""
        chunk_type  = SCTP_CHUNK_COOKIE_ACK
        chunk_flags = 0

    elif isinstance(chunk, SCTPShutdownCompleteChunk):
        value       = b""
        chunk_type  = SCTP_CHUNK_SHUTDOWN_COMPLETE
        chunk_flags = chunk.flags

    else:  # SCTPGenericChunk
        value       = chunk.value
        chunk_type  = chunk.chunk_type
        chunk_flags = chunk.flags

    length = 4 + len(value)
    header = struct.pack("!BBH", chunk_type, chunk_flags, length)
    raw    = header + value
    # Pad to 4-byte boundary (padding is NOT reflected in the Length field)
    pad_len = _pad4(length) - length
    return raw + b"\x00" * pad_len


# ── Public builder function ───────────────────────────────────────────────────

def build_sctp_packet(hdr: SCTPHeader) -> bytes:
    """Encode *hdr* to a complete wire-format SCTP packet with CRC-32c checksum.

    Encodes each chunk, pads it to a 4-byte boundary, concatenates them, then
    builds the 12-byte common header with the checksum field initially zero,
    computes CRC-32c over the full packet (RFC 9260 §6.8), and inserts the
    result.

    If *hdr.chunks* is empty a single :class:`SCTPDataChunk` with default
    values (zero TSN, zero stream/ppid, empty payload) is substituted.

    Args:
        hdr: The SCTP common header and chunk list.

    Returns:
        Wire-format SCTP packet bytes (common header + encoded chunks).

    Example::

        from packet_generator.sctp import SCTPHeader, SCTPDataChunk, build_sctp_packet

        raw = build_sctp_packet(SCTPHeader(
            src_port=1234, dst_port=9999,
            verification_tag=0x12345678,
            chunks=[SCTPDataChunk(tsn=1, data=b"hello")],
        ))
        assert len(raw) >= 12 + 16 + 5  # header + chunk header + data

    """
    chunks = hdr.chunks if hdr.chunks else [SCTPDataChunk(tsn=0)]
    chunks_bytes = b"".join(_encode_chunk(c) for c in chunks)

    # Build common header with checksum = 0
    common = struct.pack(
        "!HHII",
        hdr.src_port,
        hdr.dst_port,
        hdr.verification_tag,
        0,  # checksum placeholder
    )
    packet   = common + chunks_bytes
    checksum = crc32c(packet)

    # Insert computed checksum at offset 8
    return packet[:8] + struct.pack("!I", checksum) + packet[12:]
