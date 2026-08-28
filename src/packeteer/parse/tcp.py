from __future__ import annotations

import struct

from packeteer.generate.tcp import TCPHeader, TCPOptions, _build_options

# TCP option kinds (RFC 9293 §3.2 and the IANA registry)
_OPT_EOL: int = 0             # End of Option List — stop parsing
_OPT_NOP: int = 1             # No-Operation — alignment padding
_OPT_MSS: int = 2
_OPT_WINDOW_SCALE: int = 3
_OPT_SACK_PERMITTED: int = 4
_OPT_SACK: int = 5
_OPT_TIMESTAMPS: int = 8

# Wire lengths of the fixed-size options, including the kind and length bytes.
_LEN_MSS: int = 4
_LEN_WINDOW_SCALE: int = 3
_LEN_SACK_PERMITTED: int = 2
_LEN_TIMESTAMPS: int = 10

_SACK_BLOCK_LEN: int = 8      # two 32-bit sequence numbers per block


def _parse_options(data: bytes) -> TCPOptions | None:
    """Decode the TCP options region into a :class:`TCPOptions`.

    Walks the kind/length TLV list.  EOL (kind ``0``) ends the walk and NOP
    (kind ``1``) is skipped — neither is modelled as an option, since both are
    structural padding.  A recognised kind carrying an unexpected length is
    kept as an unknown option rather than discarded, as are kinds with no
    dedicated field, so no option bytes are lost.

    The decoded options describe *what* was sent, not the byte layout it was
    sent in: option order and the placement of padding are the sender's
    choice.  When re-encoding the decoded result would not reproduce the
    region, :attr:`~packeteer.generate.tcp.TCPOptions.raw` is set to the bytes
    as captured, so a rebuild reproduces them exactly.  It stays ``None``
    whenever the encoder's own output already matches.

    A malformed list (a length byte below the 2-byte minimum, or one running
    past the end of the region) stops the walk; options decoded up to that
    point are still returned.

    Args:
        data: The options region only — the bytes between the fixed 20-byte
            header and the end of the header given by Data Offset.

    Returns:
        A :class:`TCPOptions` instance, or ``None`` when the region holds no
        options at all (empty, or only padding).

    """
    opts = TCPOptions()
    found = False
    i = 0

    while i < len(data):
        kind = data[i]
        if kind == _OPT_EOL:
            break
        if kind == _OPT_NOP:
            i += 1
            continue

        if i + 1 >= len(data):
            break
        length = data[i + 1]
        if length < 2 or i + length > len(data):
            break

        value = data[i + 2: i + length]

        if kind == _OPT_MSS and length == _LEN_MSS:
            opts.mss = struct.unpack("!H", value)[0]
        elif kind == _OPT_WINDOW_SCALE and length == _LEN_WINDOW_SCALE:
            opts.window_scale = value[0]
        elif kind == _OPT_SACK_PERMITTED and length == _LEN_SACK_PERMITTED:
            opts.sack_permitted = True
        elif kind == _OPT_TIMESTAMPS and length == _LEN_TIMESTAMPS:
            opts.timestamps = struct.unpack("!II", value)
        elif kind == _OPT_SACK and len(value) % _SACK_BLOCK_LEN == 0 and value:
            opts.sack_blocks = [
                struct.unpack("!II", value[b: b + _SACK_BLOCK_LEN])
                for b in range(0, len(value), _SACK_BLOCK_LEN)
            ]
        else:
            opts.unknown.append((kind, bytes(value)))

        found = True
        i += length

    if not found:
        return None

    # Keep the captured bytes when re-encoding would not reproduce them.  The
    # encoder writes a canonical order and appends its NOP padding, while a
    # sender chooses its own order and puts padding ahead of the option it
    # aligns, so the two agree only sometimes.  Storing the region only on
    # disagreement keeps it out of every spec that does not need it.
    if _build_options(opts) != data:
        opts.raw = bytes(data)
    return opts


def packet_parser(data: bytes) -> tuple[int, int | None, TCPHeader | None]:
    """Parse a TCP header from raw bytes (RFC 9293).

    Header layout (20+ bytes)::

        Source Port(2) | Destination Port(2) | Sequence Number(4)
        Acknowledgement Number(4) | Data Offset(4b) | Reserved(4b) | Flags(8b)
        Window(2) | Checksum(2) | Urgent Pointer(2)
        [ Options: (Data Offset - 5) * 4 bytes ]

    The Data Offset field (high nibble of byte 12) gives the header length in
    32-bit words; the minimum valid value is 5 (20 bytes).  Any option bytes
    beyond that are decoded into the ``options`` field of the returned
    :class:`TCPHeader` (``None`` when the header carries no options).

    Args:
        data: Raw bytes starting at the first byte of a TCP header.

    Returns:
        A tuple of ``(header_size, dst_port, header)`` where *header_size* is
        ``data_offset * 4``, *dst_port* is the destination port number, and
        *header* is the parsed :class:`TCPHeader` object.  Returns
        ``(0, None, None)`` if parsing fails.

    """
    if len(data) < 20:
        return (0, None, None)

    try:
        src_port, dst_port, seq, ack = struct.unpack("!HHII", data[0:12])
        data_offset = (data[12] >> 4) & 0xF
        reserved = data[12] & 0x0F
        flags = data[13]
        window, checksum, urgent_ptr = struct.unpack("!HHH", data[14:20])

        if data_offset < 5:
            return (0, None, None)

        header_size = data_offset * 4
        if len(data) < header_size:
            return (0, None, None)

        hdr = TCPHeader(
            src_port=src_port, dst_port=dst_port,
            seq=seq, ack=ack,
            reserved=reserved, flags=flags,
            window=window, urgent_ptr=urgent_ptr,
            options=_parse_options(data[20:header_size]),
            # Cleared by parse.core when it matches the computed checksum; see
            # the note in the UDP parser.
            checksum=checksum,
        )

    except struct.error:
        return (0, None, None)

    return (header_size, dst_port, hdr)
