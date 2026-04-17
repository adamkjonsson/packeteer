"""DNS message parser (RFC 1035).

Decodes DNS messages from wire-format bytes.  Name compression (pointer
following per RFC 1035 §4.1.4) is fully supported; pointer loops are
detected by tracking visited offsets.

Over TCP, DNS messages are prefixed with a 2-byte big-endian length field
(RFC 1035 §4.2.2).  Use :func:`parse_dns_tcp` for TCP payloads and
:func:`parse_dns_udp` for UDP.
"""
from __future__ import annotations

import socket
import struct

from packeteer.generate.dns import (
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    DNS_TYPE_MX,
    DNS_TYPE_NS,
    DNS_TYPE_PTR,
    DNS_TYPE_SOA,
    DNS_TYPE_TXT,
    DNSMessage,
    DNSQuestion,
    DNSRDataA,
    DNSRDataAAAA,
    DNSRDataCNAME,
    DNSRDataMX,
    DNSRDataNS,
    DNSRDataPTR,
    DNSRDataRaw,
    DNSRDataSOA,
    DNSRDataTXT,
    DNSResourceRecord,
    _unpack_flags,
)


def _decode_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name starting at *offset* within the full message *msg*.

    Follows compression pointers per RFC 1035 §4.1.4.  Returns
    ``(name, end_offset)`` where *end_offset* is the position immediately
    after the name bytes in the *original* stream (not after any pointer
    target — the caller should advance by *end_offset*, not by the pointer
    destination).

    Args:
        msg: The full DNS message bytes (needed for pointer resolution).
        offset: Starting offset of the name within *msg*.

    Returns:
        A ``(name, end_offset)`` tuple.  *name* is a fully-qualified domain
        name with a trailing dot (or ``"."`` for the root label).

    Raises:
        ValueError: If the name is malformed, truncated, or a pointer loop
            is detected.

    """
    labels: list[str] = []
    visited: set[int] = set()
    pos = offset
    jumped = False
    end_offset = offset

    while True:
        if pos >= len(msg):
            raise ValueError(
                f"DNS name decode past end of message at offset {pos}"
            )
        if pos in visited:
            raise ValueError(
                f"DNS name pointer loop detected at offset {pos}"
            )
        visited.add(pos)

        length = msg[pos]

        if length == 0:
            if not jumped:
                end_offset = pos + 1
            break

        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(msg):
                raise ValueError(
                    f"DNS compression pointer truncated at offset {pos}"
                )
            pointer = ((length & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                end_offset = pos + 2
            jumped = True
            pos = pointer
        else:
            pos += 1
            if pos + length > len(msg):
                raise ValueError(
                    f"DNS label truncated at offset {pos}"
                )
            labels.append(msg[pos : pos + length].decode("ascii", errors="replace"))
            pos += length

    name = ".".join(labels) + "." if labels else "."
    return name, end_offset


def _decode_rdata(
    rtype: int,
    rdata_bytes: bytes,
    msg: bytes,
    rdata_offset: int,
) -> (
    DNSRDataA | DNSRDataAAAA | DNSRDataCNAME | DNSRDataNS | DNSRDataPTR
    | DNSRDataMX | DNSRDataSOA | DNSRDataTXT | DNSRDataRaw
):
    """Decode RDATA for the given *rtype*.

    Args:
        rtype: DNS record type number.
        rdata_bytes: The raw RDATA bytes (already sliced).
        msg: The full message bytes (for pointer resolution in name-bearing
            RDATA types).
        rdata_offset: Offset of *rdata_bytes* within *msg*.

    Returns:
        A typed RDATA dataclass, or :class:`DNSRDataRaw` for unknown types.

    """
    if rtype == DNS_TYPE_A:
        if len(rdata_bytes) != 4:
            return DNSRDataRaw(rtype=rtype, data=rdata_bytes)
        return DNSRDataA(address=socket.inet_ntoa(rdata_bytes))

    if rtype == DNS_TYPE_AAAA:
        if len(rdata_bytes) != 16:
            return DNSRDataRaw(rtype=rtype, data=rdata_bytes)
        return DNSRDataAAAA(address=socket.inet_ntop(socket.AF_INET6, rdata_bytes))

    if rtype in (DNS_TYPE_CNAME, DNS_TYPE_NS, DNS_TYPE_PTR):
        name, _ = _decode_name(msg, rdata_offset)
        cls_map = {
            DNS_TYPE_CNAME: DNSRDataCNAME,
            DNS_TYPE_NS: DNSRDataNS,
            DNS_TYPE_PTR: DNSRDataPTR,
        }
        return cls_map[rtype](name=name)

    if rtype == DNS_TYPE_MX:
        if len(rdata_bytes) < 2:
            return DNSRDataRaw(rtype=rtype, data=rdata_bytes)
        preference = struct.unpack_from("!H", rdata_bytes, 0)[0]
        exchange, _ = _decode_name(msg, rdata_offset + 2)
        return DNSRDataMX(preference=preference, exchange=exchange)

    if rtype == DNS_TYPE_SOA:
        mname, pos = _decode_name(msg, rdata_offset)
        rname, pos = _decode_name(msg, pos)
        if pos + 20 > len(msg):
            return DNSRDataRaw(rtype=rtype, data=rdata_bytes)
        serial, refresh, retry, expire, minimum = struct.unpack_from(
            "!IIIII", msg, pos
        )
        return DNSRDataSOA(
            mname=mname, rname=rname,
            serial=serial, refresh=refresh, retry=retry,
            expire=expire, minimum=minimum,
        )

    if rtype == DNS_TYPE_TXT:
        strings: list[bytes] = []
        pos = 0
        while pos < len(rdata_bytes):
            slen = rdata_bytes[pos]
            pos += 1
            strings.append(rdata_bytes[pos : pos + slen])
            pos += slen
        return DNSRDataTXT(strings=strings)

    return DNSRDataRaw(rtype=rtype, data=rdata_bytes)


def _decode_question(msg: bytes, offset: int) -> tuple[DNSQuestion, int]:
    name, offset = _decode_name(msg, offset)
    if offset + 4 > len(msg):
        raise ValueError(f"DNS question truncated at offset {offset}")
    qtype, qclass = struct.unpack_from("!HH", msg, offset)
    return DNSQuestion(name=name, qtype=qtype, qclass=qclass), offset + 4


def _decode_rr(msg: bytes, offset: int) -> tuple[DNSResourceRecord, int]:
    name, offset = _decode_name(msg, offset)
    if offset + 10 > len(msg):
        raise ValueError(f"DNS RR header truncated at offset {offset}")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", msg, offset)
    offset += 10
    if offset + rdlength > len(msg):
        raise ValueError(f"DNS RDATA truncated at offset {offset}")
    rdata = _decode_rdata(rtype, msg[offset : offset + rdlength], msg, offset)
    return DNSResourceRecord(
        name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata,
    ), offset + rdlength


def parse_dns_udp(data: bytes) -> DNSMessage:
    """Parse a DNS message from a UDP payload.

    Args:
        data: Raw DNS message bytes (no length prefix).

    Returns:
        A populated :class:`~packeteer.generate.dns.DNSMessage`.

    Raises:
        ValueError: If the message is too short or malformed.

    """
    if len(data) < 12:
        raise ValueError(f"DNS message too short: {len(data)} bytes")

    msg_id, flags_word, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", data, 0
    )
    flags = _unpack_flags(flags_word)
    offset = 12

    questions: list[DNSQuestion] = []
    for _ in range(qdcount):
        q, offset = _decode_question(data, offset)
        questions.append(q)

    answers: list[DNSResourceRecord] = []
    for _ in range(ancount):
        rr, offset = _decode_rr(data, offset)
        answers.append(rr)

    authority: list[DNSResourceRecord] = []
    for _ in range(nscount):
        rr, offset = _decode_rr(data, offset)
        authority.append(rr)

    additional: list[DNSResourceRecord] = []
    for _ in range(arcount):
        rr, offset = _decode_rr(data, offset)
        additional.append(rr)

    return DNSMessage(
        id=msg_id,
        flags=flags,
        questions=questions,
        answers=answers,
        authority=authority,
        additional=additional,
    )


def parse_dns_tcp(data: bytes) -> DNSMessage:
    """Parse a DNS message from a TCP payload (strips 2-byte length prefix).

    Args:
        data: TCP payload bytes beginning with the 2-byte DNS length prefix.

    Returns:
        A populated :class:`~packeteer.generate.dns.DNSMessage`.

    Raises:
        ValueError: If the data is too short or the length prefix is
            inconsistent with the remaining bytes.

    """
    if len(data) < 2:
        raise ValueError("DNS/TCP payload too short for length prefix")
    (length,) = struct.unpack_from("!H", data, 0)
    if len(data) < 2 + length:
        raise ValueError(
            f"DNS/TCP length prefix says {length} bytes "
            f"but only {len(data) - 2} available"
        )
    return parse_dns_udp(data[2 : 2 + length])
