"""SCTP packet parser (RFC 9260).

Decodes the 12-byte SCTP common header followed by one or more typed chunks.
Unknown chunk types are returned as :class:`~packet_generator.sctp.SCTPGenericChunk`.
"""
from __future__ import annotations

import struct

from packet_generator.sctp import (
    IPPROTO_SCTP,
    SCTP_CHUNK_DATA,
    SCTP_CHUNK_INIT,
    SCTP_CHUNK_INIT_ACK,
    SCTP_CHUNK_SACK,
    SCTP_CHUNK_HEARTBEAT,
    SCTP_CHUNK_HEARTBEAT_ACK,
    SCTP_CHUNK_ABORT,
    SCTP_CHUNK_SHUTDOWN,
    SCTP_CHUNK_SHUTDOWN_ACK,
    SCTP_CHUNK_ERROR,
    SCTP_CHUNK_COOKIE_ECHO,
    SCTP_CHUNK_COOKIE_ACK,
    SCTP_CHUNK_SHUTDOWN_COMPLETE,
    SCTPHeader,
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
    SCTPChunk,
    _pad4,
)


def _decode_chunk(chunk_type: int, flags: int, value: bytes) -> SCTPChunk:
    """Decode one chunk value into the appropriate dataclass."""
    try:
        if chunk_type == SCTP_CHUNK_DATA:
            if len(value) < 12:
                return SCTPGenericChunk(chunk_type=chunk_type, flags=flags, value=value)
            tsn, stream_id, stream_seq, ppid = struct.unpack("!IHHI", value[:12])
            return SCTPDataChunk(
                tsn=tsn, stream_id=stream_id, stream_seq=stream_seq,
                ppid=ppid, data=value[12:], flags=flags,
            )

        if chunk_type in (SCTP_CHUNK_INIT, SCTP_CHUNK_INIT_ACK):
            if len(value) < 16:
                return SCTPGenericChunk(chunk_type=chunk_type, flags=flags, value=value)
            initiate_tag, a_rwnd, out_streams, in_streams, initial_tsn = struct.unpack(
                "!IIHHI", value[:16]
            )
            cls = SCTPInitChunk if chunk_type == SCTP_CHUNK_INIT else SCTPInitAckChunk
            return cls(
                initiate_tag=initiate_tag, a_rwnd=a_rwnd,
                outbound_streams=out_streams, inbound_streams=in_streams,
                initial_tsn=initial_tsn, params=value[16:],
            )

        if chunk_type == SCTP_CHUNK_SACK:
            if len(value) < 12:
                return SCTPGenericChunk(chunk_type=chunk_type, flags=flags, value=value)
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

        if chunk_type in (SCTP_CHUNK_HEARTBEAT, SCTP_CHUNK_HEARTBEAT_ACK):
            # Heartbeat Info parameter: type(2) + length(2) + info
            info = b""
            if len(value) >= 4:
                param_type, param_len = struct.unpack("!HH", value[:4])
                if param_type == 1 and param_len >= 4:
                    info = value[4:param_len]
            cls = SCTPHeartbeatChunk if chunk_type == SCTP_CHUNK_HEARTBEAT else SCTPHeartbeatAckChunk
            return cls(info=info)

        if chunk_type == SCTP_CHUNK_ABORT:
            return SCTPAbortChunk(causes=value, flags=flags)

        if chunk_type == SCTP_CHUNK_SHUTDOWN:
            if len(value) < 4:
                return SCTPGenericChunk(chunk_type=chunk_type, flags=flags, value=value)
            (cum_tsn,) = struct.unpack("!I", value[:4])
            return SCTPShutdownChunk(cum_tsn_ack=cum_tsn)

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

    except Exception:
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
        :class:`~packet_generator.sctp.SCTPHeader`.  Returns
        ``(0, None, None)`` if fewer than 12 bytes are available.
    """
    if len(data) < 12:
        return (0, None, None)

    try:
        src_port, dst_port, verification_tag, _checksum = struct.unpack(
            "!HHII", data[:12]
        )
    except Exception:
        return (0, None, None)

    chunks: list[SCTPChunk] = []
    offset = 12
    while offset + 4 <= len(data):
        try:
            chunk_type, chunk_flags, chunk_length = struct.unpack(
                "!BBH", data[offset:offset + 4]
            )
        except Exception:
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
