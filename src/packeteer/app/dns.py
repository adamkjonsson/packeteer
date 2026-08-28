"""DNS as an :class:`~packeteer.protocols.AppProtocol`.

Assembles the encoder in :mod:`packeteer.generate.dns` and the decoder in
:mod:`packeteer.parse.dns` into one record, and owns the packet-spec mapping
in both directions.

:func:`from_spec` moved here from ``packeteer.__main__``, where a caller
holding a packet spec could not reach it without importing the CLI.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from packeteer.generate.dns import (
    DNS_CLASS_IN,
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    DNS_TYPE_MX,
    DNS_TYPE_NS,
    DNS_TYPE_PTR,
    DNS_TYPE_SOA,
    DNS_TYPE_TXT,
    MDNS_PORT,
    DNSFlags,
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
    _build_dns_message,
    _build_dns_message_tcp,
)
from packeteer.protocols import AppProtocol

if TYPE_CHECKING:
    from packeteer.generate.dns import _DNSRData

DNS_PORT: int = 53


def encode(msg: object, transport: str = "udp") -> bytes:
    """Encode a :class:`~packeteer.generate.dns.DNSMessage` to wire bytes.

    Args:
        msg: The message to encode.
        transport: ``"tcp"`` prefixes the 2-byte length field DNS-over-TCP
            requires (RFC 1035 §4.2.2); ``"udp"`` does not.

    Returns:
        The encoded message.

    """
    assert isinstance(msg, DNSMessage)
    return _build_dns_message_tcp(msg) if transport == "tcp" else _build_dns_message(msg)


def decode(payload: bytes, transport: str = "udp") -> DNSMessage:
    """Decode wire bytes into a :class:`~packeteer.generate.dns.DNSMessage`.

    Args:
        payload: Transport payload bytes.
        transport: ``"tcp"`` expects the 2-byte length prefix.

    Returns:
        The decoded message.

    Raises:
        ValueError: If *payload* is not a well-formed DNS message.

    """
    # Imported here so that `import packeteer.generate` does not pull in the
    # whole parser; see the note in packeteer.app.__init__.
    from packeteer.parse.dns import parse_dns_tcp, parse_dns_udp

    return parse_dns_tcp(payload) if transport == "tcp" else parse_dns_udp(payload)


def to_spec(msg: object) -> dict[str, Any]:
    """Return the ``dns`` packet-spec section for *msg*.

    Args:
        msg: The :class:`~packeteer.generate.dns.DNSMessage` to serialise.

    Returns:
        The section, as it appears under ``"dns"`` in a packet spec.

    """
    from packeteer.parse.to_config import _apply_dns

    config: dict[str, Any] = {}
    _apply_dns(config, msg)
    return config["dns"]


def _rdata_from_spec(rtype: int, rdata: dict[str, Any]) -> _DNSRData:
    """Build the RDATA object a resource record of *rtype* carries."""
    if rtype == DNS_TYPE_A:
        return DNSRDataA(address=rdata.get("address", "0.0.0.0"))
    if rtype == DNS_TYPE_AAAA:
        return DNSRDataAAAA(address=rdata.get("address", "::"))
    if rtype == DNS_TYPE_CNAME:
        return DNSRDataCNAME(name=rdata.get("name", "."))
    if rtype == DNS_TYPE_NS:
        return DNSRDataNS(name=rdata.get("name", "."))
    if rtype == DNS_TYPE_PTR:
        return DNSRDataPTR(name=rdata.get("name", "."))
    if rtype == DNS_TYPE_MX:
        return DNSRDataMX(
            preference=rdata.get("preference", 0),
            exchange=rdata.get("exchange", "."),
        )
    if rtype == DNS_TYPE_SOA:
        return DNSRDataSOA(
            mname=rdata.get("mname", "."),
            rname=rdata.get("rname", "."),
            serial=rdata.get("serial", 0),
            refresh=rdata.get("refresh", 0),
            retry=rdata.get("retry", 0),
            expire=rdata.get("expire", 0),
            minimum=rdata.get("minimum", 0),
        )
    if rtype == DNS_TYPE_TXT:
        strings = [
            s.encode("utf-8") if isinstance(s, str) else s
            for s in rdata.get("strings", [])
        ]
        return DNSRDataTXT(strings=strings)
    return DNSRDataRaw(rtype=rtype, data=bytes.fromhex(rdata.get("data", "")))


def from_spec(section: dict[str, Any]) -> DNSMessage:
    """Build a :class:`~packeteer.generate.dns.DNSMessage` from a spec section.

    Args:
        section: The object found under ``"dns"`` in a packet spec.

    Returns:
        The message it describes.

    """
    flags_d = section.get("flags", {})
    flags = DNSFlags(
        qr=flags_d.get("qr", False),
        opcode=flags_d.get("opcode", 0),
        aa=flags_d.get("aa", False),
        tc=flags_d.get("tc", False),
        rd=flags_d.get("rd", True),
        ra=flags_d.get("ra", False),
        rcode=flags_d.get("rcode", 0),
    )
    questions = [
        DNSQuestion(
            name=q["name"],
            qtype=q.get("qtype", DNS_TYPE_A),
            qclass=q.get("qclass", DNS_CLASS_IN),
            unicast_response=q.get("unicast_response", False),
        )
        for q in section.get("questions", [])
    ]

    def _rrs(key: str) -> list[DNSResourceRecord]:
        return [
            DNSResourceRecord(
                name=rr["name"],
                rtype=rr["rtype"],
                rclass=rr.get("rclass", DNS_CLASS_IN),
                ttl=rr.get("ttl", 0),
                rdata=_rdata_from_spec(rr["rtype"], rr.get("rdata", {})),
                cache_flush=rr.get("cache_flush", False),
            )
            for rr in section.get(key, [])
        ]

    return DNSMessage(
        id=section.get("id", 0),
        flags=flags,
        questions=questions,
        answers=_rrs("answers"),
        authority=_rrs("authority"),
        additional=_rrs("additional"),
    )


def sanitise(section: dict[str, Any], replacer: Any, options: Any) -> None:
    """Redact *section* in place.

    Args:
        section: A ``dns`` packet-spec section.
        replacer: The consistent-replacement map for the whole capture.
        options: The :class:`~packeteer.sanitise.SanitiseOptions` in force.

    """
    from packeteer.sanitise import _sanitise_dns

    _sanitise_dns(section, replacer, options)


PROTOCOL = AppProtocol(
    name="dns",
    over="either",
    ports=frozenset({DNS_PORT, MDNS_PORT}),
    messages=(DNSMessage,),
    decode=decode,
    encode=encode,
    to_spec=to_spec,
    from_spec=from_spec,
    sanitise=sanitise,
)
