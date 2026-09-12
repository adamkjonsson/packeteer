"""DNS message construction (RFC 1035) and mDNS constants (RFC 6762).

This module provides dataclasses for DNS messages and a wire-format encoder.
DNS messages are application-layer payloads carried over UDP or TCP port 53.
mDNS uses the same wire format on UDP port 5353 to multicast addresses
:data:`MDNS_ADDR_IPV4` (``224.0.0.251``) and :data:`MDNS_ADDR_IPV6`
(``ff02::fb``), with two extra bits:

* :attr:`DNSQuestion.unicast_response` — the QU bit (top bit of ``QCLASS``)
  requests that the response be sent unicast rather than multicast.
* :attr:`DNSResourceRecord.cache_flush` — the CF bit (top bit of ``RRCLASS``)
  signals that existing cache entries for this record should be flushed.

Over TCP, each message is prefixed with a 2-byte big-endian length field per
RFC 1035 §4.2.2.  Use :func:`_build_dns_message_tcp` for TCP payloads and
:func:`_build_dns_message` for UDP.

Supported record types: A (1), NS (2), CNAME (5), SOA (6), PTR (12),
MX (15), TXT (16), AAAA (28).  Unknown types are represented as
:class:`DNSRDataRaw`.

Names are **compressed** when encoding (RFC 1035 §4.1.4), as every real
resolver does: a name whose suffix has already been written becomes a
pointer to that earlier occurrence.  The encoder chooses canonically — the
longest suffix already present, pointing backwards — which is one of the
choices the RFC permits and not the only one, so a captured message does not
necessarily re-encode to the bytes it came in with; :attr:`DNSMessage.raw`
is what carries those.  Pass ``compress=False`` to :func:`_build_dns_message`
to write every name out in full.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# ── Record type constants ─────────────────────────────────────────────────────

DNS_TYPE_A: int = 1
DNS_TYPE_NS: int = 2
DNS_TYPE_CNAME: int = 5
DNS_TYPE_SOA: int = 6
DNS_TYPE_PTR: int = 12
DNS_TYPE_MX: int = 15
DNS_TYPE_TXT: int = 16
DNS_TYPE_AAAA: int = 28

DNS_CLASS_IN: int = 1

# ── mDNS (RFC 6762) constants ─────────────────────────────────────────────────

MDNS_PORT: int = 5353
MDNS_ADDR_IPV4: str = "224.0.0.251"
MDNS_ADDR_IPV6: str = "ff02::fb"

# Bit masks for the QU and cache-flush bits (top bit of qclass / rrclass).
_MDNS_QU_BIT: int = 0x8000
_MDNS_CF_BIT: int = 0x8000

DNS_RCODE_NOERROR: int = 0
DNS_RCODE_FORMERR: int = 1
DNS_RCODE_SERVFAIL: int = 2
DNS_RCODE_NXDOMAIN: int = 3
DNS_RCODE_NOTIMP: int = 4
DNS_RCODE_REFUSED: int = 5


# ── Flags ─────────────────────────────────────────────────────────────────────

@dataclass
class DNSFlags:
    """DNS header flags word (second 16-bit field of the DNS header).

    Attributes:
        qr: ``False`` = query, ``True`` = response.
        opcode: 4-bit opcode.  0 = QUERY, 1 = IQUERY, 2 = STATUS.
        aa: Authoritative Answer.
        tc: TrunCated — message was truncated.
        rd: Recursion Desired.
        ra: Recursion Available.
        z: Reserved bits (should be 0).
        rcode: 4-bit response code.  0 = NOERROR, 3 = NXDOMAIN, etc.

    """

    qr: bool = False
    opcode: int = 0
    aa: bool = False
    tc: bool = False
    rd: bool = True
    ra: bool = False
    z: int = 0
    rcode: int = 0


def _pack_flags(f: DNSFlags) -> int:
    return (
        (int(f.qr) << 15)
        | ((f.opcode & 0xF) << 11)
        | (int(f.aa) << 10)
        | (int(f.tc) << 9)
        | (int(f.rd) << 8)
        | (int(f.ra) << 7)
        | ((f.z & 0x7) << 4)
        | (f.rcode & 0xF)
    )


def _unpack_flags(word: int) -> DNSFlags:
    return DNSFlags(
        qr=bool((word >> 15) & 1),
        opcode=(word >> 11) & 0xF,
        aa=bool((word >> 10) & 1),
        tc=bool((word >> 9) & 1),
        rd=bool((word >> 8) & 1),
        ra=bool((word >> 7) & 1),
        z=(word >> 4) & 0x7,
        rcode=word & 0xF,
    )


# ── RDATA types ───────────────────────────────────────────────────────────────

@dataclass
class DNSRDataA:
    """RDATA for an A record (IPv4 address).

    Attributes:
        address: IPv4 address in dotted-decimal notation.

    """

    address: str


@dataclass
class DNSRDataAAAA:
    """RDATA for an AAAA record (IPv6 address).

    Attributes:
        address: IPv6 address in any notation accepted by
            :func:`socket.inet_pton`.

    """

    address: str


@dataclass
class DNSRDataCNAME:
    """RDATA for a CNAME record.

    Attributes:
        name: Canonical domain name (fully qualified, trailing dot optional).

    """

    name: str


@dataclass
class DNSRDataNS:
    """RDATA for an NS record.

    Attributes:
        name: Name server domain name.

    """

    name: str


@dataclass
class DNSRDataPTR:
    """RDATA for a PTR record (reverse DNS).

    Attributes:
        name: Target domain name.

    """

    name: str


@dataclass
class DNSRDataMX:
    """RDATA for an MX record.

    Attributes:
        preference: Preference value — lower is preferred.
        exchange: Mail exchange domain name.

    """

    preference: int
    exchange: str


@dataclass
class DNSRDataSOA:
    """RDATA for a SOA record.

    Attributes:
        mname: Primary name server for the zone.
        rname: Mailbox of the responsible person (dots replace ``@``).
        serial: Zone serial number.
        refresh: Seconds between zone refresh checks.
        retry: Seconds before a failed refresh is retried.
        expire: Seconds after which the zone is considered stale.
        minimum: Minimum TTL for records in the zone.

    """

    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclass
class DNSRDataTXT:
    """RDATA for a TXT record.

    Attributes:
        strings: One or more character-strings.  Each element maps to one
            length-prefixed string in the wire format.

    """

    strings: list[bytes] = field(default_factory=list)


@dataclass
class DNSRDataRaw:
    """RDATA for an unrecognised record type (raw bytes).

    Attributes:
        rtype: The numeric record type.
        data: Raw RDATA bytes.

    """

    rtype: int
    data: bytes = b""


# ── Question and Resource Record ──────────────────────────────────────────────

@dataclass
class DNSQuestion:
    """A DNS question section entry.

    Attributes:
        name: Queried domain name (fully qualified, trailing dot optional).
        qtype: Query type (e.g. :data:`DNS_TYPE_A`).
        qclass: Query class (normally :data:`DNS_CLASS_IN`).
        unicast_response: mDNS QU bit (RFC 6762 §5.4) — request a unicast
            response rather than a multicast one.  Encoded as the top bit of
            the ``QCLASS`` field; ignored in plain DNS.

    """

    name: str
    qtype: int = DNS_TYPE_A
    qclass: int = DNS_CLASS_IN
    unicast_response: bool = False


@dataclass
class DNSResourceRecord:
    """A DNS resource record (answer, authority, or additional section).

    Attributes:
        name: Owner name (fully qualified, trailing dot optional).
        rtype: Record type (e.g. :data:`DNS_TYPE_A`).
        rclass: Record class (normally :data:`DNS_CLASS_IN`).
        ttl: Time to live in seconds.
        rdata: Decoded record data.
        cache_flush: mDNS cache-flush bit (RFC 6762 §11.3) — signals that
            existing cache entries for this name/type/class should be flushed.
            Encoded as the top bit of the ``RRCLASS`` field; ignored in plain
            DNS.

    """

    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: (
        DNSRDataA | DNSRDataAAAA | DNSRDataCNAME | DNSRDataNS | DNSRDataPTR
        | DNSRDataMX | DNSRDataSOA | DNSRDataTXT | DNSRDataRaw
    )
    cache_flush: bool = False


# ── DNS message ───────────────────────────────────────────────────────────────

@dataclass
class DNSMessage:
    """A complete DNS message (query or response).

    Attributes:
        id: 16-bit transaction identifier.
        flags: Header flags word as a :class:`DNSFlags` instance.
        questions: Entries in the question section.
        answers: Entries in the answer section.
        authority: Entries in the authority section.
        additional: Entries in the additional section.
        raw: The message exactly as captured, when re-encoding the decoded
            fields would not reproduce it.  Written out verbatim, so such a
            message round-trips; empty otherwise.

            **Name compression is why this exists.** RFC 1035 §4.1.4 lets a
            name be a pointer to any earlier occurrence, and senders disagree
            about which one to pick — across 476 real messages, packeteer's
            own encoder (longest suffix, pointing backwards) chooses a
            different target for 234 of 516 pointers.  So no single encoder
            reproduces every capture, and for the ones it does not the only
            thing that does is the bytes.  Same reasoning as
            :attr:`~packeteer.generate.tcp.TCPOptions.raw`.  A message
            packeteer compressed itself, and any capture whose sender chose
            as packeteer does, re-encodes from its fields and carries no
            *raw*.

            It takes precedence over the decoded fields, so **editing them has
            no effect while it is set** — clear it to hand-edit a captured
            message.  ``packeteer sanitise`` clears it whenever it changes the
            section, since redacting a name that is still in *raw* would not
            redact anything.

    """

    id: int = 0
    flags: DNSFlags = field(default_factory=DNSFlags)
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSResourceRecord] = field(default_factory=list)
    authority: list[DNSResourceRecord] = field(default_factory=list)
    additional: list[DNSResourceRecord] = field(default_factory=list)
    raw: bytes = b""


# ── Wire encoder ──────────────────────────────────────────────────────────────

#: The largest offset a compression pointer can hold: 14 bits (RFC 1035 §4.1.4).
_MAX_POINTER_OFFSET: int = 0x3FFF


class _NameWriter:
    """Accumulates a message and compresses the names written into it.

    RFC 1035 §4.1.4: a name, or any suffix of one, may be replaced by a
    two-byte pointer to an earlier occurrence of that suffix in the message.
    This writer remembers where every suffix it has written in full starts,
    and when a later name shares a suffix it writes the leading labels and a
    pointer to the longest match.  Matching is **case-sensitive**: the RFC
    permits a case-insensitive match, but a pointer resolves to the target's
    spelling, and a message with ``Example.COM`` and ``example.com`` would
    come back with one of them — which breaks ``decode(encode(m)) == m``,
    the contract every protocol is held to.  The cost is a pointer a real
    sender might have emitted; the trade is the right one.

    Compression is off when *compress* is ``False``, in which case every
    name is written out in full and the writer is a plain buffer.
    """

    def __init__(self, compress: bool) -> None:
        self.buf = bytearray()
        self.compress = compress
        self._suffixes: dict[tuple[str, ...], int] = {}

    def write(self, data: bytes) -> None:
        self.buf += data

    def name(self, name: str) -> None:
        """Write *name*, as labels and possibly a trailing pointer."""
        labels = tuple(name.rstrip(".").split(".")) if name.rstrip(".") else ()
        for index in range(len(labels)):
            suffix = labels[index:]
            target = self._suffixes.get(suffix) if self.compress else None
            if target is not None and target <= _MAX_POINTER_OFFSET:
                self.buf += struct.pack("!H", 0xC000 | target)
                return
            # This suffix starts here; a later name may point at it.  Only an
            # offset a pointer can address is worth remembering.
            if len(self.buf) <= _MAX_POINTER_OFFSET:
                self._suffixes[suffix] = len(self.buf)
            encoded = labels[index].encode("ascii")
            self.buf += bytes([len(encoded)]) + encoded
        self.buf += b"\x00"


def _encode_name(name: str) -> bytes:
    """Encode a DNS domain name as length-prefixed labels, uncompressed.

    The standalone form, for a name that is not part of a message — a
    pointer needs a message to point into.
    """
    w = _NameWriter(compress=False)
    w.name(name)
    return bytes(w.buf)


def _encode_rdata(
    rdata: (
        DNSRDataA | DNSRDataAAAA | DNSRDataCNAME | DNSRDataNS | DNSRDataPTR
        | DNSRDataMX | DNSRDataSOA | DNSRDataTXT | DNSRDataRaw
    ),
    w: _NameWriter,
) -> None:
    """Write RDATA into *w*.

    Names inside RDATA compress for the types RFC 1035 defines with them —
    CNAME, NS, PTR, MX and SOA — and for no other: RFC 3597 §4 forbids
    compression in the RDATA of any type not in the original RFC, so TXT,
    A, AAAA and raw RDATA are written as they are.
    """
    if isinstance(rdata, DNSRDataA):
        w.write(socket.inet_aton(rdata.address))
    elif isinstance(rdata, DNSRDataAAAA):
        w.write(socket.inet_pton(socket.AF_INET6, rdata.address))
    elif isinstance(rdata, (DNSRDataCNAME, DNSRDataNS, DNSRDataPTR)):
        w.name(rdata.name)
    elif isinstance(rdata, DNSRDataMX):
        w.write(struct.pack("!H", rdata.preference))
        w.name(rdata.exchange)
    elif isinstance(rdata, DNSRDataSOA):
        w.name(rdata.mname)
        w.name(rdata.rname)
        w.write(struct.pack("!IIIII",
                            rdata.serial, rdata.refresh, rdata.retry,
                            rdata.expire, rdata.minimum))
    elif isinstance(rdata, DNSRDataTXT):
        for string in rdata.strings:
            w.write(bytes([len(string)]) + string)
    else:
        w.write(rdata.data)  # DNSRDataRaw


def _encode_question(q: DNSQuestion, w: _NameWriter) -> None:
    qclass = q.qclass | (_MDNS_QU_BIT if q.unicast_response else 0)
    w.name(q.name)
    w.write(struct.pack("!HH", q.qtype, qclass))


def _encode_rr(rr: DNSResourceRecord, w: _NameWriter) -> None:
    rrclass = rr.rclass | (_MDNS_CF_BIT if rr.cache_flush else 0)
    w.name(rr.name)
    w.write(struct.pack("!HHIH", rr.rtype, rrclass, rr.ttl, 0))
    # RDLENGTH is the *compressed* length, so it can only be known once the
    # RDATA has been written; patch it in afterwards.
    length_at = len(w.buf) - 2
    _encode_rdata(rr.rdata, w)
    struct.pack_into("!H", w.buf, length_at, len(w.buf) - length_at - 2)


def _build_dns_message(msg: DNSMessage, *, compress: bool = True) -> bytes:
    """Build a DNS message as wire-format bytes (no TCP length prefix).

    Returns ``msg.raw`` unchanged when it is set.  Otherwise names are
    compressed (RFC 1035 §4.1.4) unless *compress* is ``False``.

    Args:
        msg: The DNS message to encode.
        compress: Whether to replace a repeated name suffix with a pointer to
            its earlier occurrence, as real resolvers do.  ``False`` writes
            every name in full, which is what packeteer did before 0.14.0.

    Returns:
        Wire-format bytes suitable for use as a UDP payload.

    """
    if msg.raw:
        # The captured bytes, which an encoder cannot reproduce when the
        # sender chose pointer targets this one would not — see `DNSMessage.raw`.
        return msg.raw
    w = _NameWriter(compress)
    w.write(struct.pack(
        "!HHHHHH",
        msg.id,
        _pack_flags(msg.flags),
        len(msg.questions),
        len(msg.answers),
        len(msg.authority),
        len(msg.additional),
    ))
    for q in msg.questions:
        _encode_question(q, w)
    for rr in msg.answers + msg.authority + msg.additional:
        _encode_rr(rr, w)
    return bytes(w.buf)


def _build_dns_message_tcp(msg: DNSMessage, *, compress: bool = True) -> bytes:
    """Build a DNS message with a 2-byte TCP length prefix (RFC 1035 §4.2.2).

    Args:
        msg: The DNS message to encode.
        compress: As for :func:`_build_dns_message`.  Pointer offsets are
            relative to the message, not the prefix.

    Returns:
        Wire-format bytes with a 2-byte big-endian length prefix, suitable
        for use as a TCP payload.

    """
    payload = _build_dns_message(msg, compress=compress)
    return struct.pack("!H", len(payload)) + payload
