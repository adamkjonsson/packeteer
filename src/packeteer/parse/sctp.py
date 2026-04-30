"""SCTP packet parser (RFC 9260).

Decodes the 12-byte SCTP common header followed by one or more typed chunks.
Unknown chunk types are returned as :class:`~packeteer.generate.sctp.SCTPGenericChunk`.
"""
from __future__ import annotations

import struct

from packeteer.generate.sctp import (
    SCTP_CHUNK_ABORT,
    SCTP_CHUNK_COOKIE_ACK,
    SCTP_CHUNK_COOKIE_ECHO,
    SCTP_CHUNK_DATA,
    SCTP_CHUNK_ERROR,
    SCTP_CHUNK_HEARTBEAT,
    SCTP_CHUNK_HEARTBEAT_ACK,
    SCTP_CHUNK_INIT,
    SCTP_CHUNK_INIT_ACK,
    SCTP_CHUNK_SACK,
    SCTP_CHUNK_SHUTDOWN,
    SCTP_CHUNK_SHUTDOWN_ACK,
    SCTP_CHUNK_SHUTDOWN_COMPLETE,
    SCTPAbortChunk,
    SCTPChunk,
    SCTPCookieAckChunk,
    SCTPCookieEchoChunk,
    SCTPDataChunk,
    SCTPErrorChunk,
    SCTPGenericChunk,
    SCTPHeader,
    SCTPHeartbeatAckChunk,
    SCTPHeartbeatChunk,
    SCTPInitAckChunk,
    SCTPInitChunk,
    SCTPSackChunk,
    SCTPShutdownAckChunk,
    SCTPShutdownChunk,
    SCTPShutdownCompleteChunk,
    _pad4,
)


def _decode_data_chunk(flags: int, value: bytes) -> SCTPDataChunk:
    """Decode an SCTP DATA chunk (type 0).

    Args:
        flags: Chunk flags byte.
        value: Chunk value bytes (after the 4-byte chunk header).

    Returns:
        Decoded :class:`SCTPDataChunk`.

    Raises:
        ValueError: If *value* is shorter than 12 bytes.

    """
    if len(value) < 12:
        raise ValueError("DATA chunk too short")
    tsn, stream_id, stream_seq, ppid = struct.unpack("!IHHI", value[:12])
    return SCTPDataChunk(
        tsn=tsn, stream_id=stream_id, stream_seq=stream_seq,
        ppid=ppid, data=value[12:], flags=flags,
    )


def _decode_init_chunk(
    chunk_type: int, value: bytes,
) -> SCTPInitChunk | SCTPInitAckChunk:
    """Decode an SCTP INIT or INIT-ACK chunk.

    Args:
        chunk_type: Chunk type byte (SCTP_CHUNK_INIT or SCTP_CHUNK_INIT_ACK).
        value: Chunk value bytes (after the 4-byte chunk header).

    Returns:
        Decoded :class:`SCTPInitChunk` or :class:`SCTPInitAckChunk`.

    Raises:
        ValueError: If *value* is shorter than 16 bytes.

    """
    if len(value) < 16:
        raise ValueError("INIT chunk too short")
    initiate_tag, a_rwnd, out_streams, in_streams, initial_tsn = struct.unpack(
        "!IIHHI", value[:16]
    )
    cls: type[SCTPInitChunk | SCTPInitAckChunk] = (
        SCTPInitChunk if chunk_type == SCTP_CHUNK_INIT else SCTPInitAckChunk
    )
    return cls(
        initiate_tag=initiate_tag, a_rwnd=a_rwnd,
        outbound_streams=out_streams, inbound_streams=in_streams,
        initial_tsn=initial_tsn, params=value[16:],
    )


def _decode_sack_chunk(value: bytes) -> SCTPSackChunk:
    """Decode an SCTP SACK chunk (type 3).

    Args:
        value: Chunk value bytes (after the 4-byte chunk header).

    Returns:
        Decoded :class:`SCTPSackChunk`.

    Raises:
        ValueError: If *value* is shorter than 12 bytes.

    """
    if len(value) < 12:
        raise ValueError("SACK chunk too short")
    cum_tsn, a_rwnd, n_gap, n_dup = struct.unpack("!IIHH", value[:12])
    offset = 12
    gap_blocks: list[tuple[int, int]] = []
    for _ in range(n_gap):
        if offset + 4 > len(value):
            break
        start, end = struct.unpack("!HH", value[offset:offset + 4])
        gap_blocks.append((start, end))
        offset += 4
    dup_tsns: list[int] = []
    for _ in range(n_dup):
        if offset + 4 > len(value):
            break
        (tsn,) = struct.unpack("!I", value[offset:offset + 4])
        dup_tsns.append(tsn)
        offset += 4
    return SCTPSackChunk(
        cum_tsn_ack=cum_tsn, a_rwnd=a_rwnd,
        gap_ack_blocks=gap_blocks, dup_tsns=dup_tsns,
    )


def _decode_heartbeat_chunk(
    chunk_type: int, value: bytes,
) -> SCTPHeartbeatChunk | SCTPHeartbeatAckChunk:
    """Decode an SCTP HEARTBEAT or HEARTBEAT-ACK chunk.

    Args:
        chunk_type: Chunk type byte.
        value: Chunk value bytes (after the 4-byte chunk header).

    Returns:
        Decoded :class:`SCTPHeartbeatChunk` or :class:`SCTPHeartbeatAckChunk`.

    """
    info = b""
    if len(value) >= 4:
        param_type, param_len = struct.unpack("!HH", value[:4])
        if param_type == 1 and param_len >= 4:
            info = value[4:param_len]
    cls: type[SCTPHeartbeatChunk | SCTPHeartbeatAckChunk] = (
        SCTPHeartbeatChunk if chunk_type == SCTP_CHUNK_HEARTBEAT else SCTPHeartbeatAckChunk
    )
    return cls(info=info)


def _decode_shutdown_chunk(value: bytes) -> SCTPShutdownChunk:
    """Decode an SCTP SHUTDOWN chunk (type 7).

    Args:
        value: Chunk value bytes (after the 4-byte chunk header).

    Returns:
        Decoded :class:`SCTPShutdownChunk`.

    Raises:
        ValueError: If *value* is shorter than 4 bytes.

    """
    if len(value) < 4:
        raise ValueError("SHUTDOWN chunk too short")
    (cum_tsn,) = struct.unpack("!I", value[:4])
    return SCTPShutdownChunk(cum_tsn_ack=cum_tsn)


def _decode_chunk(chunk_type: int, flags: int, value: bytes) -> SCTPChunk:
    """Decode one chunk value into the appropriate dataclass."""
    try:
        if chunk_type == SCTP_CHUNK_DATA:
            return _decode_data_chunk(flags, value)
        if chunk_type in (SCTP_CHUNK_INIT, SCTP_CHUNK_INIT_ACK):
            return _decode_init_chunk(chunk_type, value)
        if chunk_type == SCTP_CHUNK_SACK:
            return _decode_sack_chunk(value)
        if chunk_type in (SCTP_CHUNK_HEARTBEAT, SCTP_CHUNK_HEARTBEAT_ACK):
            return _decode_heartbeat_chunk(chunk_type, value)
        if chunk_type == SCTP_CHUNK_ABORT:
            return SCTPAbortChunk(causes=value, flags=flags)
        if chunk_type == SCTP_CHUNK_SHUTDOWN:
            return _decode_shutdown_chunk(value)
        if chunk_type == SCTP_CHUNK_SHUTDOWN_ACK:
            return SCTPShutdownAckChunk()
        if chunk_type == SCTP_CHUNK_ERROR:
            return SCTPErrorChunk(causes=value)
        if chunk_type == SCTP_CHUNK_COOKIE_ECHO:
            return SCTPCookieEchoChunk(cookie=value)
        if chunk_type == SCTP_CHUNK_COOKIE_ACK:
            return SCTPCookieAckChunk()
        if chunk_type == SCTP_CHUNK_SHUTDOWN_COMPLETE:
            return SCTPShutdownCompleteChunk(flags=flags)
    except (struct.error, ValueError):
        pass

    return SCTPGenericChunk(chunk_type=chunk_type, flags=flags, value=value)


def packet_parser(data: bytes) -> tuple[int, int | None, SCTPHeader | None]:
    """Parse an SCTP packet from raw bytes (RFC 9260).

    Decodes the 12-byte common header and all following chunks.  The checksum
    field is read but not verified so that captures with incorrect checksums
    (e.g. from checksum offload) are still parsed.

    Args:
        data: Raw bytes starting at the first byte of the SCTP common header.

    Returns:
        ``(consumed, dst_port, header)`` where *consumed* is the number of
        bytes consumed (the full length of *data* — SCTP has no reliable
        length field in the common header; it relies on the IP length),
        *dst_port* is the destination port number, and *header* is the parsed
        :class:`~packeteer.generate.sctp.SCTPHeader`.  Returns
        ``(0, None, None)`` if fewer than 12 bytes are available.

    """
    if len(data) < 12:
        return (0, None, None)

    try:
        src_port, dst_port, verification_tag, _checksum = struct.unpack(
            "!HHII", data[:12]
        )
    except struct.error:
        return (0, None, None)

    chunks: list[SCTPChunk] = []
    offset = 12
    while offset + 4 <= len(data):
        try:
            chunk_type, chunk_flags, chunk_length = struct.unpack(
                "!BBH", data[offset:offset + 4]
            )
        except struct.error:
            break
        if chunk_length < 4:
            break
        value_end = offset + chunk_length
        if value_end > len(data):
            break
        value = data[offset + 4:value_end]
        chunks.append(_decode_chunk(chunk_type, chunk_flags, value))
        # Advance past this chunk including any 4-byte padding
        offset += _pad4(chunk_length)

    hdr = SCTPHeader(
        src_port=src_port,
        dst_port=dst_port,
        verification_tag=verification_tag,
        chunks=chunks,
    )
    return (len(data), dst_port, hdr)
