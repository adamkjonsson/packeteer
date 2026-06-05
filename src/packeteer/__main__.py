#!/usr/bin/env python3
r"""packeteer — build, parse, sanitise, and generate raw network packets.

Subcommands:
  build      Build packets from a packet spec file and write to a pcap or pcapng file
  parse      Parse a pcap or pcapng file and produce a packet spec
  file-info  Summarise a pcap or pcapng file: packets, sessions, and layer stats
  sanitise   Replace sensitive fields in a packet spec with synthetic data
  stream     Generate a synthetic TCP/UDP/SCTP stream and write to a pcap or pcapng file
  fuzz       Generate adversarial packet variants for decoder robustness testing

Examples:
  packeteer build packets.json --pcap out.pcap
  packeteer build packets.json --pcapng out.pcapng
  packeteer parse capture.pcap
  packeteer parse capture.pcap --output replay.json
  packeteer file-info capture.pcap
  packeteer file-info capture.pcap --json
  packeteer file-info capture.pcap --link-type raw
  packeteer sanitise capture.json --output clean.json
  packeteer sanitise capture.json --ports --payload --output clean.json
  packeteer sanitise capture.pcap --output clean.json
  packeteer sanitise capture.pcap --pcap clean.pcap
  packeteer sanitise capture.pcap --pcap clean.pcap --output clean.json
  packeteer sanitise capture.pcapng --pcapng clean.pcapng
  packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 --packets 50 --pcap out.pcap
  packeteer stream --protocol udp --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
      --server-port 53 --packets 5 --pcap dns.pcap
  packeteer stream --protocol sctp --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
      --server-port 9999 --packets 20 --pcap sctp.pcap
  packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 --packets 10 --json stream.json
  packeteer fuzz capture.pcap --pcap fuzzed.pcap
  packeteer fuzz capture.json --mutations boundary tcp-flags --pcap fuzzed.pcap
  packeteer fuzz capture.json --mutations boundary --output variants.json

"""
# This module is the entry point for the `packeteer` CLI command.
# The mapping is declared in pyproject.toml: [project.scripts] packeteer = "packeteer_cli:main"
import argparse
import configparser
import json
import sys
from importlib.metadata import PackageNotFoundError as _PkgNotFoundError
from importlib.metadata import version as _pkg_version
from typing import Callable

from packeteer.filter import PacketFilter
from packeteer.fuzz import (
    ALL_MUTATION_NAMES,
    BYTE_MUTATION_NAMES,
    FuzzOptions,
    FuzzVariant,
    fuzz,
    fuzz_bytes,
)
from packeteer.generate import PacketBuilder
from packeteer.generate.dhcp import (
    DHCP_OPT_CLIENT_ID,
    DHCP_OPT_DNS_SERVER,
    DHCP_OPT_DOMAIN_NAME,
    DHCP_OPT_HOSTNAME,
    DHCP_OPT_LEASE_TIME,
    DHCP_OPT_MESSAGE_TYPE,
    DHCP_OPT_PARAM_REQUEST_LIST,
    DHCP_OPT_REQUESTED_IP,
    DHCP_OPT_ROUTER,
    DHCP_OPT_SERVER_ID,
    DHCP_OPT_SUBNET_MASK,
    DHCP_OPT_VENDOR_CLASS_ID,
    DHCPMessage,
    DHCPOpt,
    DHCPOptClientID,
    DHCPOptDNSServer,
    DHCPOptDomainName,
    DHCPOptHostname,
    DHCPOptLeaseTime,
    DHCPOptMessageType,
    DHCPOptParamRequestList,
    DHCPOptRaw,
    DHCPOptRequestedIP,
    DHCPOptRouter,
    DHCPOptServerID,
    DHCPOptSubnetMask,
    DHCPOptVendorClassID,
)
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
)
from packeteer.generate.http import HTTPMessage, HTTPRequest, HTTPResponse
from packeteer.generate.pppoe import PPPOE_CODE_SESSION, PPPoETag
from packeteer.generate.sctp import (
    SCTPAbortChunk,
    SCTPChunk,
    SCTPCookieAckChunk,
    SCTPCookieEchoChunk,
    SCTPDataChunk,
    SCTPErrorChunk,
    SCTPGenericChunk,
    SCTPHeartbeatAckChunk,
    SCTPHeartbeatChunk,
    SCTPInitAckChunk,
    SCTPInitChunk,
    SCTPSackChunk,
    SCTPShutdownAckChunk,
    SCTPShutdownChunk,
    SCTPShutdownCompleteChunk,
)
from packeteer.generate.sctp_stream import SCTPStreamConfig, generate_sctp_stream
from packeteer.generate.stream_encap import (
    EtherIPEncap,
    GREEncap,
    IPIPEncap,
    MPLSEncap,
    PPPoEEncap,
    QinQEncap,
    StreamEncap,
    VLANEncap,
)
from packeteer.generate.tcp import TCP_SYN, TCPOptions
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.generate.udp_stream import UDPStreamConfig, generate_udp_stream
from packeteer.parse.core import parse_packet, parse_pcap_file
from packeteer.parse.info import format_pcap_info, pcap_info
from packeteer.parse.to_config import (
    apply_tunneled,
    to_json_string,
    to_packet_spec,
    update_config,
)
from packeteer.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    is_pcap_or_pcapng,
    write_pcap,
    write_pcapng,
)
from packeteer.sanitise import SanitiseOptions, sanitise

_DNSRData = (
    DNSRDataA | DNSRDataAAAA | DNSRDataCNAME | DNSRDataNS | DNSRDataPTR
    | DNSRDataMX | DNSRDataSOA | DNSRDataTXT | DNSRDataRaw
)


def _build_dns_rdata(rtype: int, rdata: dict) -> _DNSRData:  # type: ignore[valid-type]
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


def _build_dns_from_spec(spec: dict) -> DNSMessage:
    """Convert a ``dns`` packet spec dict to a :class:`DNSMessage`."""
    flags_d = spec.get("flags", {})
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
        for q in spec.get("questions", [])
    ]

    def _rrs(section: str) -> list[DNSResourceRecord]:
        return [
            DNSResourceRecord(
                name=rr["name"],
                rtype=rr["rtype"],
                rclass=rr.get("rclass", DNS_CLASS_IN),
                ttl=rr.get("ttl", 0),
                rdata=_build_dns_rdata(rr["rtype"], rr.get("rdata", {})),
                cache_flush=rr.get("cache_flush", False),
            )
            for rr in spec.get(section, [])
        ]

    return DNSMessage(
        id=spec.get("id", 0),
        flags=flags,
        questions=questions,
        answers=_rrs("answers"),
        authority=_rrs("authority"),
        additional=_rrs("additional"),
    )


_DHCP_OPTION_BUILDERS: dict[int, Callable[[dict], DHCPOpt]] = {  # type: ignore[valid-type]
    DHCP_OPT_MESSAGE_TYPE:       lambda d: DHCPOptMessageType(mtype=d.get("mtype", 1)),
    DHCP_OPT_SUBNET_MASK:        lambda d: DHCPOptSubnetMask(mask=d.get("mask", "255.255.255.0")),
    DHCP_OPT_ROUTER:             lambda d: DHCPOptRouter(routers=d.get("routers", [])),
    DHCP_OPT_DNS_SERVER:         lambda d: DHCPOptDNSServer(servers=d.get("servers", [])),
    DHCP_OPT_HOSTNAME:           lambda d: DHCPOptHostname(hostname=d.get("hostname", "")),
    DHCP_OPT_DOMAIN_NAME:        lambda d: DHCPOptDomainName(domain=d.get("domain", "")),
    DHCP_OPT_REQUESTED_IP:       lambda d: DHCPOptRequestedIP(address=d.get("address", "0.0.0.0")),
    DHCP_OPT_LEASE_TIME:         lambda d: DHCPOptLeaseTime(seconds=d.get("seconds", 86400)),
    DHCP_OPT_SERVER_ID:          lambda d: DHCPOptServerID(address=d.get("address", "0.0.0.0")),
    DHCP_OPT_PARAM_REQUEST_LIST: lambda d: DHCPOptParamRequestList(codes=d.get("codes", [])),
    DHCP_OPT_VENDOR_CLASS_ID: lambda d: DHCPOptVendorClassID(data=bytes.fromhex(d.get("data", ""))),
    DHCP_OPT_CLIENT_ID:          lambda d: DHCPOptClientID(data=bytes.fromhex(d.get("data", ""))),
}


def _build_dhcp_option(d: dict) -> DHCPOpt:  # type: ignore[valid-type]
    """Convert one ``options`` entry from a packet spec dict to a DHCPOpt."""
    code = d.get("code", 0)
    fn = _DHCP_OPTION_BUILDERS.get(code)
    if fn is not None:
        return fn(d)
    return DHCPOptRaw(code=code, data=bytes.fromhex(d.get("data", "")))


def _build_dhcp_from_spec(spec: dict) -> DHCPMessage:
    """Convert a ``dhcp`` packet spec dict to a :class:`DHCPMessage`."""
    chaddr_hex = spec.get("chaddr", "00" * 16)
    chaddr = bytes.fromhex(chaddr_hex).ljust(16, b"\x00")[:16]
    sname_str = spec.get("sname", "")
    file_str  = spec.get("file", "")
    return DHCPMessage(
        op=spec.get("op", 1),
        htype=spec.get("htype", 1),
        hlen=spec.get("hlen", 6),
        hops=spec.get("hops", 0),
        xid=spec.get("xid", 0),
        secs=spec.get("secs", 0),
        flags=spec.get("flags", 0),
        ciaddr=spec.get("ciaddr", "0.0.0.0"),
        yiaddr=spec.get("yiaddr", "0.0.0.0"),
        siaddr=spec.get("siaddr", "0.0.0.0"),
        giaddr=spec.get("giaddr", "0.0.0.0"),
        chaddr=chaddr,
        sname=sname_str.encode("ascii")[:64].ljust(64, b"\x00"),
        file=file_str.encode("ascii")[:128].ljust(128, b"\x00"),
        options=[_build_dhcp_option(o) for o in spec.get("options", [])],
    )


def _build_http_from_spec(spec: dict) -> HTTPMessage:  # type: ignore[valid-type]
    """Convert an ``http`` packet spec dict to an HTTP message object."""
    headers = spec.get("headers", {})
    body = bytes.fromhex(spec.get("body", ""))
    if spec.get("type") == "response":
        return HTTPResponse(
            version=spec.get("version", "1.1"),
            status_code=spec.get("status_code", 200),
            reason=spec.get("reason", "OK"),
            headers=headers,
            body=body,
        )
    return HTTPRequest(
        method=spec.get("method", "GET"),
        path=spec.get("path", "/"),
        version=spec.get("version", "1.1"),
        headers=headers,
        body=body,
    )


def _parse_sctp_chunk(spec: dict, packet_num: int) -> SCTPChunk:
    """Convert one JSON chunk dict to an SCTP chunk dataclass."""
    chunk_type = spec.get("type", "generic")

    try:
        if chunk_type == "data":
            return SCTPDataChunk(
                tsn=spec.get("tsn", 0),
                stream_id=spec.get("stream_id", 0),
                stream_seq=spec.get("stream_seq", 0),
                ppid=spec.get("ppid", 0),
                data=bytes.fromhex(spec.get("data", "")),
                flags=spec.get("flags", 0x03),
            )
        if chunk_type in ("init", "init_ack"):
            cls = SCTPInitChunk if chunk_type == "init" else SCTPInitAckChunk
            return cls(
                initiate_tag=spec.get("initiate_tag", 0),
                a_rwnd=spec.get("a_rwnd", 131072),
                outbound_streams=spec.get("outbound_streams", 1),
                inbound_streams=spec.get("inbound_streams", 1),
                initial_tsn=spec.get("initial_tsn", 0),
                params=bytes.fromhex(spec.get("params", "")),
            )
        if chunk_type == "sack":
            return SCTPSackChunk(
                cum_tsn_ack=spec.get("cum_tsn_ack", 0),
                a_rwnd=spec.get("a_rwnd", 131072),
                gap_ack_blocks=[tuple(b) for b in spec.get("gap_ack_blocks", [])],
                dup_tsns=list(spec.get("dup_tsns", [])),
            )
        if chunk_type in ("heartbeat", "heartbeat_ack"):
            cls = SCTPHeartbeatChunk if chunk_type == "heartbeat" else SCTPHeartbeatAckChunk
            return cls(info=bytes.fromhex(spec.get("info", "")))
        if chunk_type == "abort":
            return SCTPAbortChunk(
                causes=bytes.fromhex(spec.get("causes", "")),
                flags=spec.get("flags", 0),
            )
        if chunk_type == "shutdown":
            return SCTPShutdownChunk(cum_tsn_ack=spec.get("cum_tsn_ack", 0))
        if chunk_type == "shutdown_ack":
            return SCTPShutdownAckChunk()
        if chunk_type == "error":
            return SCTPErrorChunk(causes=bytes.fromhex(spec.get("causes", "")))
        if chunk_type == "cookie_echo":
            return SCTPCookieEchoChunk(cookie=bytes.fromhex(spec.get("cookie", "")))
        if chunk_type == "cookie_ack":
            return SCTPCookieAckChunk()
        if chunk_type == "shutdown_complete":
            return SCTPShutdownCompleteChunk(flags=spec.get("flags", 0))
        # generic
        return SCTPGenericChunk(
            chunk_type=spec.get("chunk_type", 0),
            flags=spec.get("flags", 0),
            value=bytes.fromhex(spec.get("value", "")),
        )
    except (ValueError, TypeError) as e:
        print(
            f"Error: packet {packet_num} SCTP chunk ({chunk_type!r}) decode error: {e}",
            file=sys.stderr,
        )
        sys.exit(1)


def _parse_tcp_options(spec: dict | None) -> TCPOptions | None:
    """Convert a JSON ``transport.options`` object to a :class:`TCPOptions`."""
    if not spec:
        return None
    sack_raw = spec.get("sack", [])
    return TCPOptions(
        mss=spec.get("mss"),
        window_scale=spec.get("window_scale"),
        sack_permitted=spec.get("sack_permitted", False),
        sack_blocks=[tuple(b) for b in sack_raw],
        timestamps=tuple(spec["timestamps"]) if "timestamps" in spec else None,
    )


def _build_ip_layer(b: "PacketBuilder", net: dict) -> "PacketBuilder":
    """Append an IP layer from a ``network`` spec dict to *b*."""
    return b.ip(
        src=net["src"], dst=net["dst"],
        ttl=net.get("ttl", 64),
        tos=net.get("tos", 0),
        identification=net.get("identification", 0),
        flags=net.get("flags", 0b010),
        fragment_offset=net.get("fragment_offset", 0),
        traffic_class=net.get("traffic_class", 0),
        flow_label=net.get("flow_label", 0),
    )


def _dispatch_transport(
    b: "PacketBuilder",
    proto_lower: str,
    transport: dict,
    packet_num: int,
    context: str = "",
) -> "PacketBuilder":
    """Append the transport layer for *proto_lower* to *b* and return it.

    *context* is a short prefix (e.g. ``"ipip inner "``) used in error messages.
    """
    if proto_lower == "tcp":
        return b.tcp(
            src_port=transport.get("src_port", 12345),
            dst_port=transport.get("dst_port", 80),
            seq=transport.get("seq", 0),
            ack=transport.get("ack", 0),
            flags=transport.get("flags", TCP_SYN),
            window=transport.get("window", 65535),
            urgent_ptr=transport.get("urgent_ptr", 0),
            reserved=transport.get("reserved", 0),
            options=_parse_tcp_options(transport.get("options")),
        )
    if proto_lower == "udp":
        return b.udp(
            src_port=transport.get("src_port", 12345),
            dst_port=transport.get("dst_port", 80),
        )
    if proto_lower == "icmp":
        return b.icmp(
            type=transport.get("type", 8),
            code=transport.get("code", 0),
            identifier=transport.get("identifier", 1),
            sequence=transport.get("sequence", 1),
        )
    if proto_lower == "icmpv6":
        return b.icmpv6(
            type=transport.get("type", 128),
            code=transport.get("code", 0),
            identifier=transport.get("identifier", 1),
            sequence=transport.get("sequence", 1),
        )
    if proto_lower == "sctp":
        chunks = [
            _parse_sctp_chunk(c, packet_num)
            for c in transport.get("chunks", [])
        ]
        return b.sctp(
            src_port=transport.get("src_port", 0),
            dst_port=transport.get("dst_port", 0),
            verification_tag=transport.get("verification_tag", 0),
            chunks=chunks or None,
        )
    print(
        f"Error: packet {packet_num} {context}unknown protocol '{proto_lower}'",
        file=sys.stderr,
    )
    sys.exit(1)


def _apply_payload_spec(
    b: "PacketBuilder",
    payload_spec: dict,
    packet_num: int,
    context: str = "",
) -> "PacketBuilder":
    """Append a payload layer from *payload_spec* to *b* (if any) and return it.

    *context* is a short prefix (e.g. ``"ipip inner "``) used in error messages.
    """
    if "data" in payload_spec:
        encoding = payload_spec.get("encoding", "hex")
        try:
            if encoding == "utf8":
                data = payload_spec["data"].encode("utf-8")
            elif encoding == "hex":
                data = bytes.fromhex(payload_spec["data"])
            else:
                print(
                    f"Error: packet {packet_num} {context}payload.encoding "
                    f"'{encoding}' is not supported (use 'hex' or 'utf8')",
                    file=sys.stderr,
                )
                sys.exit(1)
        except (ValueError, UnicodeEncodeError) as e:
            print(
                f"Error: packet {packet_num} {context}payload.data decode error: {e}",
                file=sys.stderr,
            )
            sys.exit(1)
        return b.payload(data=data)
    if payload_spec.get("size", 0):
        return b.payload(size=payload_spec["size"])
    return b


def _build_pppoe(
    b: "PacketBuilder",
    pppoe_spec: dict,
    packet_num: int,
) -> "PacketBuilder":
    """Append a PPPoE layer from *pppoe_spec* to *b* and return it."""
    try:
        tags = [
            PPPoETag(type=t["type"], data=bytes.fromhex(t.get("data", "")))
            for t in pppoe_spec.get("tags", [])
        ]
    except (KeyError, ValueError) as e:
        print(f"Error: packet {packet_num} pppoe tag error: {e}", file=sys.stderr)
        sys.exit(1)
    return b.pppoe(
        code=pppoe_spec.get("code", PPPOE_CODE_SESSION),
        session_id=pppoe_spec.get("session_id", 0),
        tags=tags,
    )


def _apply_ip_chain(
    b: "PacketBuilder",
    spec: dict,
    packet_num: int,
) -> "PacketBuilder":
    """Append IP + transport layers from an IP-in-IP inner spec to *b*.

    No ethernet/VLAN/MPLS/PPPoE — the inner spec contains only
    ``network``, ``transport``, ``payload``, and optionally a nested
    ``ipip`` key for double-tunnelled packets.  Called recursively.
    """
    net          = spec.get("network", {})
    protocol_str = net.get("protocol")

    if not net.get("src") or not net.get("dst") or not protocol_str:
        print(
            f"Error: packet {packet_num} ipip inner spec missing "
            "network.src, network.dst, or network.protocol",
            file=sys.stderr,
        )
        sys.exit(1)

    b = _build_ip_layer(b, net)
    proto_lower = protocol_str.lower()

    if proto_lower == "ipip":
        ipip_inner = spec.get("ipip")
        if ipip_inner is None:
            print(
                f"Error: packet {packet_num} ipip inner protocol is "
                "'ipip' but nested 'ipip' spec is missing",
                file=sys.stderr,
            )
            sys.exit(1)
        return _apply_ip_chain(b, ipip_inner, packet_num)

    if proto_lower == "gre":
        gre_inner = spec.get("gre")
        if gre_inner is None:
            print(
                f"Error: packet {packet_num} inner protocol is "
                "'gre' but nested 'gre' spec is missing",
                file=sys.stderr,
            )
            sys.exit(1)
        b = b.gre(
            key=gre_inner.get("key"),
            seq=gre_inner.get("seq"),
            checksum=gre_inner.get("checksum", False),
        )
        return _apply_ip_chain(b, gre_inner, packet_num)

    b = _dispatch_transport(b, proto_lower, spec.get("transport", {}), packet_num, "ipip inner ")
    if "dns" in spec:
        return b.dns(_build_dns_from_spec(spec["dns"]), tcp=(proto_lower == "tcp"))
    if "dhcp" in spec:
        return b.dhcp(_build_dhcp_from_spec(spec["dhcp"]))
    if "http" in spec:
        return b.http(_build_http_from_spec(spec["http"]))
    return _apply_payload_spec(b, spec.get("payload", {}), packet_num, "ipip inner ")


def _apply_spec_to_builder(
    b: "PacketBuilder",
    spec: dict,
    packet_num: int,
) -> tuple["PacketBuilder", bool]:
    """Append all protocol layers from *spec* to *b*.

    Returns ``(b, is_terminal)`` where ``is_terminal`` is ``True`` for
    packets that end without an IP/transport layer (e.g. PPPoE discovery).
    Called recursively for the inner frame when ``protocol`` is ``"etherip"``.
    """
    eth          = spec.get("ethernet", {})
    mpls_labels  = spec.get("mpls", [])
    pppoe_spec   = spec.get("pppoe")
    net          = spec.get("network", {})

    src          = net.get("src")
    dst          = net.get("dst")
    protocol_str = net.get("protocol")

    is_pppoe_discovery = (
        pppoe_spec is not None
        and pppoe_spec.get("code", PPPOE_CODE_SESSION) != PPPOE_CODE_SESSION
    )
    is_etherip    = bool(protocol_str) and protocol_str.lower() == "etherip"
    is_ipip       = bool(protocol_str) and protocol_str.lower() == "ipip"
    is_gre        = bool(protocol_str) and protocol_str.lower() == "gre"
    is_pseudowire = "pseudowire" in spec

    if not is_pppoe_discovery and not is_etherip and not is_ipip and not is_gre and \
            not is_pseudowire and (not src or not dst or not protocol_str):
        print(
            f"Error: packet {packet_num} missing network.src, network.dst, or network.protocol",
            file=sys.stderr,
        )
        sys.exit(1)

    if is_ipip and spec.get("ipip") is None:
        print(
            f"Error: packet {packet_num} protocol is 'ipip' but 'ipip' spec is missing",
            file=sys.stderr,
        )
        sys.exit(1)

    if is_etherip and spec.get("etherip") is None:
        print(
            f"Error: packet {packet_num} protocol is 'etherip' but 'etherip' spec is missing",
            file=sys.stderr,
        )
        sys.exit(1)

    if is_gre and spec.get("gre") is None:
        print(
            f"Error: packet {packet_num} protocol is 'gre' but 'gre' spec is missing",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Ethernet ─────────────────────────────────────────────────────────────
    if eth.get("enabled", True):
        b = b.ethernet(
            src_mac=eth.get("src_mac", "00:00:00:00:00:01"),
            dst_mac=eth.get("dst_mac", "00:00:00:00:00:02"),
            pad=eth.get("pad", True),
        )
        vlan = eth.get("vlan", {})
        if vlan:
            b = b.vlan(vid=vlan["id"], pcp=vlan.get("pcp", 0), dei=vlan.get("dei", 0))
        inner_vlan = eth.get("inner_vlan", {})
        if inner_vlan:
            b = b.vlan(
                vid=inner_vlan["id"], pcp=inner_vlan.get("pcp", 0), dei=inner_vlan.get("dei", 0)
            )

    # ── MPLS ─────────────────────────────────────────────────────────────────
    for mpls_entry in mpls_labels:
        b = b.mpls(
            label=mpls_entry["label"],
            tc=mpls_entry.get("tc", 0),
            ttl=mpls_entry.get("ttl", 64),
        )

    # ── Pseudowire ───────────────────────────────────────────────────────────
    pw_spec = spec.get("pseudowire")
    if pw_spec is not None:
        b = b.pseudowire(
            flags=pw_spec.get("flags", 0),
            frag=pw_spec.get("frag", 0),
            length=pw_spec.get("length", 0),
            sequence=pw_spec.get("sequence", 0),
        )
        b, _ = _apply_spec_to_builder(b, pw_spec, packet_num)
        return b, False

    # ── PPPoE ────────────────────────────────────────────────────────────────
    if pppoe_spec is not None:
        b = _build_pppoe(b, pppoe_spec, packet_num)

    if is_pppoe_discovery:
        return b, True

    # ── IP ───────────────────────────────────────────────────────────────────
    b = _build_ip_layer(b, net)

    # ── Protocol dispatch ────────────────────────────────────────────────────
    proto_lower = protocol_str.lower()

    if proto_lower == "etherip":
        b = b.etherip()
        b, _ = _apply_spec_to_builder(b, spec["etherip"], packet_num)
        return b, False

    if proto_lower == "ipip":
        b = _apply_ip_chain(b, spec["ipip"], packet_num)
        return b, False

    if proto_lower == "gre":
        gre_spec = spec["gre"]
        b = b.gre(
            key=gre_spec.get("key"),
            seq=gre_spec.get("seq"),
            checksum=gre_spec.get("checksum", False),
        )
        if "ethernet" in gre_spec:
            # TEB: inner spec includes an Ethernet layer
            b, _ = _apply_spec_to_builder(b, gre_spec, packet_num)
        else:
            # IP-in-GRE or nested GRE: no inner Ethernet
            b = _apply_ip_chain(b, gre_spec, packet_num)
        return b, False

    b = _dispatch_transport(b, proto_lower, spec.get("transport", {}), packet_num)
    if "dns" in spec:
        b = b.dns(_build_dns_from_spec(spec["dns"]), tcp=(proto_lower == "tcp"))
    elif "dhcp" in spec:
        b = b.dhcp(_build_dhcp_from_spec(spec["dhcp"]))
    elif "http" in spec:
        b = b.http(_build_http_from_spec(spec["http"]))
    else:
        b = _apply_payload_spec(b, spec.get("payload", {}), packet_num)
    return b, False


def _run_multi_packet(
    cfg: dict, pcap_path: str | None = None, pcapng_path: str | None = None
) -> None:
    """Build and output all packets defined in a packet spec."""
    top_metadata = cfg.get("metadata", {})
    nanoseconds: bool = top_metadata.get("nanoseconds", False)

    if "packets" not in cfg:
        print("Error: config file must have a top-level 'packets' array", file=sys.stderr)
        sys.exit(1)

    specs = cfg["packets"]
    if not specs:
        print("Error: 'packets' array is empty", file=sys.stderr)
        sys.exit(1)

    # Use link_type from metadata when present; otherwise infer from packet contents.
    if "link_type" in top_metadata:
        link_type = int(top_metadata["link_type"])
    else:
        all_no_eth = all(not spec.get("ethernet", {}).get("enabled", True) for spec in specs)
        link_type = LINKTYPE_RAW if all_no_eth else LINKTYPE_ETHERNET

    # collected: list of (pkt_bytes, ts_sec, ts_frac)
    collected: list[tuple[bytes, int, int]] = []

    for i, spec in enumerate(specs, 1):
        out = spec.get("packet_metadata", {})
        try:
            b, is_terminal = _apply_spec_to_builder(PacketBuilder(), spec, i)
            if is_terminal:
                pkts = [b.build()]
            else:
                mtu = out.get("mtu")
                pkts = b.fragment(mtu=mtu) if mtu is not None else [b.build()]
        except (OSError, ValueError) as e:
            print(f"Error building packet {i}: {e}", file=sys.stderr)
            sys.exit(1)

        ts_sec: int = out.get("timestamp_s", 0)
        ts_frac: int = out.get("timestamp_ns" if nanoseconds else "timestamp_us", 0)
        for pkt in pkts:
            collected.append((pkt, ts_sec, ts_frac))

    if pcap_path:
        write_pcap(collected, path=pcap_path, link_type=link_type, nanoseconds=nanoseconds)
        print(f"Wrote {len(collected)} packet(s) to {pcap_path} (link type: {link_type})")
    else:
        write_pcapng(collected, path=pcapng_path, link_type=link_type, nanoseconds=nanoseconds)
        print(f"Wrote {len(collected)} packet(s) to {pcapng_path} (link type: {link_type})")


def _cmd_build(args: argparse.Namespace) -> None:
    try:
        with open(args.config) as f:
            raw_cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error loading config '{args.config}': {e}", file=sys.stderr)
        sys.exit(1)
    _run_multi_packet(raw_cfg, pcap_path=args.pcap, pcapng_path=args.pcapng)


def _build_packet_filter(args: argparse.Namespace) -> PacketFilter | None:
    """Build a PacketFilter from parsed CLI args, or None if no filter flags set."""
    def _split(val: str | None) -> list[str]:
        return [v.strip() for v in val.split(",")] if val else []

    f = PacketFilter(
        proto    = getattr(args, "proto", None) or None,
        port     = _split(getattr(args, "port", None)),
        src_port = _split(getattr(args, "src_port", None)),
        dst_port = _split(getattr(args, "dst_port", None)),
        src      = _split(getattr(args, "src", None)),
        dst      = _split(getattr(args, "dst", None)),
        host     = _split(getattr(args, "host", None)),
        app      = getattr(args, "app", None) or None,
    )
    return None if f.is_empty() else f


def _link_type(value: str) -> int:
    """Convert a ``--link-type`` argument to a link-layer type integer.

    Accepts the names ``ethernet`` and ``raw`` (case-insensitive) or any
    integer literal (e.g. ``1``, ``101``).
    """
    names = {"ethernet": LINKTYPE_ETHERNET, "raw": LINKTYPE_RAW}
    key = value.strip().lower()
    if key in names:
        return names[key]
    try:
        return int(value, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid link type {value!r}: use 'ethernet', 'raw', or an integer"
        ) from None


def _cmd_parse(args: argparse.Namespace) -> None:
    try:
        pf = _build_packet_filter(args)
    except ValueError as e:
        print(f"Error in filter: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        json_str = parse_pcap_file(
            path=args.pcap, packet_filter=pf,
            link_type=getattr(args, "link_type", None),
        )
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(json_str)
                f.write("\n")
        except OSError as e:
            print(f"Error writing '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Wrote packet spec to {args.output}")
    else:
        print(json_str)


def _cmd_file_info(args: argparse.Namespace) -> None:
    try:
        info = pcap_info(
            path=args.pcap,
            link_type=getattr(args, "link_type", None),
            auto_link_type=not args.no_auto_link_type,
        )
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(info.to_dict(), indent=2))
    else:
        print(format_pcap_info(info))


def _cmd_sanitise(args: argparse.Namespace) -> None:
    is_pcap_input = is_pcap_or_pcapng(args.input)

    if is_pcap_input:
        try:
            json_str = parse_pcap_file(
                path=args.input, link_type=getattr(args, "link_type", None),
            )
            config = json.loads(json_str)
        except (OSError, ValueError) as e:
            print(f"Error parsing '{args.input}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            with open(args.input) as f:
                config = json.load(f)
        except OSError as e:
            print(f"Error reading '{args.input}': {e}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in '{args.input}': {e}", file=sys.stderr)
            sys.exit(1)

    opts = SanitiseOptions(
        ips=not args.no_ips,
        macs=not args.no_macs,
        ports=args.ports,
        payload=args.payload,
        timestamps=args.timestamps,
        dns_ids=getattr(args, "dns_ids", False),
        dhcp_xids=getattr(args, "dhcp_xids", False),
        http_headers=getattr(args, "http_headers", False),
        scan_pii=getattr(args, "scan_pii", True),
    )

    try:
        result = sanitise(config, opts)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    pcap_out   = getattr(args, "pcap",   None)
    pcapng_out = getattr(args, "pcapng", None)

    if pcap_out or pcapng_out:
        _run_multi_packet(result, pcap_path=pcap_out, pcapng_path=pcapng_out)

    if args.output:
        output_str = json.dumps(result, indent=2)
        try:
            with open(args.output, "w") as f:
                f.write(output_str)
                f.write("\n")
        except OSError as e:
            print(f"Error writing '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Wrote sanitised packet spec to {args.output}")
    elif not pcap_out and not pcapng_out:
        print(json.dumps(result, indent=2))


# ── fuzz subcommand ───────────────────────────────────────────────────────────


def _fuzz_json_str(variants: list[FuzzVariant], source_config: dict) -> str:
    """Serialise spec-level *variants* as a packet spec JSON string."""
    top_meta = source_config.get("metadata", {})
    packets = []
    for var in variants:
        meta = {
            **var.spec.get("packet_metadata", {}),
            "fuzz_mutation": var.mutation,
            "fuzz_label":    var.label,
            "fuzz_source":   var.source_idx,
        }
        packets.append({**var.spec, "packet_metadata": meta})
    return json.dumps({"metadata": {**top_meta, "fuzz": True}, "packets": packets}, indent=2)


def _write_fuzz_json(variants: list[FuzzVariant], source_config: dict, path: str) -> None:
    """Write spec-level *variants* as a packet spec JSON file to *path*."""
    try:
        with open(path, "w") as f:
            f.write(_fuzz_json_str(variants, source_config))
            f.write("\n")
    except OSError as e:
        print(f"Error writing '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Wrote {len(variants)} fuzz variant(s) to {path}")


def _cmd_fuzz(args: argparse.Namespace) -> None:
    is_pcap_input = is_pcap_or_pcapng(args.input)
    if is_pcap_input:
        try:
            config = json.loads(parse_pcap_file(path=args.input))
        except (OSError, ValueError) as e:
            print(f"Error parsing '{args.input}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            with open(args.input) as f:
                config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Error reading '{args.input}': {e}", file=sys.stderr)
            sys.exit(1)

    requested: list[str] = args.mutations or list(ALL_MUTATION_NAMES)
    opts = FuzzOptions(mutations=requested, count=args.count, seed=args.seed)
    try:
        variants = fuzz(config, opts)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    pcap_out   = getattr(args, "pcap",   None)
    pcapng_out = getattr(args, "pcapng", None)

    if pcap_out or pcapng_out:
        top_meta = config.get("metadata", {})
        nanoseconds: bool = top_meta.get("nanoseconds", False)
        ts_key = "timestamp_ns" if nanoseconds else "timestamp_us"
        src_ts = [
            (p.get("packet_metadata", {}).get("timestamp_s", 0),
             p.get("packet_metadata", {}).get(ts_key, 0))
            for p in config["packets"]
        ]
        all_no_eth = all(
            not spec.get("ethernet", {}).get("enabled", True) for spec in config["packets"]
        )
        link_type  = LINKTYPE_RAW if all_no_eth else LINKTYPE_ETHERNET
        collected: list[tuple[bytes, int, int]] = []

        # Build source packets once for byte-level mutations
        src_raw: list[bytes] = []
        for i, spec in enumerate(config["packets"], 1):
            try:
                b_bld, _ = _apply_spec_to_builder(PacketBuilder(), spec, i)
                src_raw.append(b_bld.build())
            except (OSError, ValueError):
                src_raw.append(b"")

        # Spec-level variants
        for var in variants:
            ts_sec, ts_frac = src_ts[var.source_idx]
            try:
                b_bld, _ = _apply_spec_to_builder(PacketBuilder(), var.spec, 0)
                collected.append((b_bld.build(), ts_sec, ts_frac))
            except (OSError, ValueError):
                pass  # skip variants that cannot be serialised

        # Byte-level variants
        for raw, (ts_sec, ts_frac) in zip(src_raw, src_ts, strict=True):
            if raw:
                for _, corrupted in fuzz_bytes(raw, opts):
                    collected.append((corrupted, ts_sec, ts_frac))

        try:
            if pcap_out:
                write_pcap(collected, path=pcap_out, link_type=link_type, nanoseconds=nanoseconds)
                print(f"Wrote {len(collected)} variant packet(s) to {pcap_out}")
            else:
                write_pcapng(
                    collected, path=pcapng_out, link_type=link_type, nanoseconds=nanoseconds,
                )
                print(f"Wrote {len(collected)} variant packet(s) to {pcapng_out}")
        except OSError as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            sys.exit(1)

    if not pcap_out and not pcapng_out and any(m in set(BYTE_MUTATION_NAMES) for m in requested):
        print(
            "Warning: byte-level mutations (bit-flip, wrong-checksum, wrong-length) "
            "are omitted from JSON output; use --pcap or --pcapng to include them.",
            file=sys.stderr,
        )

    if args.output:
        _write_fuzz_json(variants, config, args.output)
    elif not pcap_out and not pcapng_out:
        print(_fuzz_json_str(variants, config))


# ── stream config-file support ────────────────────────────────────────────────

# Maps INI config key → (argparse dest attr, type converter, default value).
# Keys use underscores (matching INI file convention).  The converter is called
# on the raw string value; use `bool` to trigger configparser's boolean parsing.
# `None` as a default means the field has no built-in fallback (it must be
# supplied on the CLI or in a config file).
_STREAM_PARAMS: dict[str, tuple[str, object, object]] = {
    "protocol":           ("protocol",                        str,   "tcp"),
    "client_ip":          ("client_ip",                       str,   None),
    "server_ip":          ("server_ip",                       str,   None),
    "client_port":        ("client_port",                     int,   54321),
    "server_port":        ("server_port",                     int,   80),
    "client_mac":         ("client_mac",                      str,   "00:00:00:00:00:01"),
    "server_mac":         ("server_mac",                      str,   "00:00:00:00:00:02"),
    "packets":            ("packets",                         int,   10),
    "min_payload":        ("min_payload",                     int,   40),
    "max_payload":        ("max_payload",                     int,   1460),
    "distribution":       ("distribution",                    str,   "uniform"),
    "ttl":                ("ttl",                             int,   64),
    "window":             ("window",                          int,   65535),
    "gap":                ("gap",                             float, 0.001),
    "gap_jitter":         ("gap_jitter",                      float, 0.0),
    "psh_probability":    ("psh_probability",                 float, 0.5),
    "packet_loss":        ("packet_loss_probability",         float, 0.0),
    "retransmission_probability":     ("retransmission_probability",     float, 0.0),
    "retransmission_timeout":         ("retransmission_timeout",         float, 0.2),
    "payload_corruption_probability": ("payload_corruption_probability", float, 0.0),
    "server_rst_probability":         ("server_rst_probability",         float, 0.0),
    "rst_propagation_delay":          ("rst_propagation_delay",          float, 0.0),
    "mtu":      ("mtu",                   int,   None),
    "stray_packet_count": ("stray_packet_count",              int,   0),
    "stray_timing_window":("stray_timing_window",             int,   None),
    "no_ethernet":        ("no_ethernet",                     bool,  False),
    "seed":               ("seed",                            int,   None),
    "pcap":               ("pcap",                            str,   None),
    "pcapng":             ("pcapng",                          str,   None),
    "json":               ("json",                            str,   None),
    # Encapsulation — all default to None (= not set)
    "vlan":           ("vlan",           int,                                    None),
    "vlan_pcp":       ("vlan_pcp",       int,                                    None),
    "vlan_dei":       ("vlan_dei",       int,                                    None),
    "qinq":           ("qinq",           lambda s: [int(x) for x in s.split()], None),
    "qinq_outer_pcp": ("qinq_outer_pcp", int,                                    None),
    "qinq_outer_dei": ("qinq_outer_dei", int,                                    None),
    "qinq_inner_pcp": ("qinq_inner_pcp", int,                                    None),
    "qinq_inner_dei": ("qinq_inner_dei", int,                                    None),
    "mpls":           ("mpls",           lambda s: [int(x) for x in s.split()], None),
    "mpls_tc":        ("mpls_tc",        int,                                    None),
    "mpls_ttl":       ("mpls_ttl",       int,                                    None),
    "pppoe":          ("pppoe",          int,                                    None),
    "gre":            ("gre",            lambda s: s.split(),                    None),
    "gre_key":        ("gre_key",        int,                                    None),
    "gre_ttl":        ("gre_ttl",        int,                                    None),
    "etherip":        ("etherip",        lambda s: s.split(),                    None),
    "etherip_ttl":    ("etherip_ttl",    int,                                    None),
    "ipip":           ("ipip",           lambda s: s.split(),                    None),
    "ipip_ttl":       ("ipip_ttl",       int,                                    None),
}


def _load_stream_config(path: str) -> dict:
    """Parse *path* as a configparser INI file and return a dict of stream args.

    Raises ``SystemExit`` on any error (file not found, missing section,
    unknown key, or bad value type).
    """
    cp = configparser.ConfigParser()
    try:
        with open(path) as f:
            cp.read_file(f)
    except OSError as e:
        print(f"Error reading config file '{path}': {e}", file=sys.stderr)
        sys.exit(1)

    if "stream" not in cp:
        print(f"Error: config file '{path}' has no [stream] section", file=sys.stderr)
        sys.exit(1)

    section = cp["stream"]
    result = {}
    for key, raw in section.items():
        if key not in _STREAM_PARAMS:
            print(f"Warning: unknown key '{key}' in config file '{path}' — ignored",
                  file=sys.stderr)
            continue
        dest, cast, _ = _STREAM_PARAMS[key]
        try:
            value = cp.getboolean("stream", key) if cast is bool else cast(raw)  # type: ignore[operator]
        except (ValueError, configparser.Error):
            print(
                f"Error: invalid value for '{key}' in config file '{path}': {raw!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        result[dest] = value
    return result


def _apply_stream_defaults(args: argparse.Namespace) -> None:
    """Fill *args* from config file (if given) then from built-in defaults.

    Called after ``parse_args()``.  Modifies *args* in place.
    """
    config: dict = {}
    if args.config:
        config = _load_stream_config(args.config)

    for dest, value in config.items():
        if getattr(args, dest, None) is None:
            setattr(args, dest, value)

    for dest, _, default in _STREAM_PARAMS.values():
        if getattr(args, dest, None) is None:
            setattr(args, dest, default)


def _parse_stream_encap(args: argparse.Namespace) -> "list[StreamEncap] | None":
    """Build an ordered list of encapsulation layers from CLI / config-file args.

    Multiple encapsulations may be combined (e.g. ``--mpls 100 --ipip ...``
    produces MPLS labels followed by an IP-in-IP tunnel).  The order of layers
    in the returned list is fixed: tag-based layers first (VLAN/QinQ → MPLS →
    PPPoE), then at most one tunnel layer (GRE / EtherIP / IPIP).

    Constraints enforced:
    - ``--vlan`` and ``--qinq`` are mutually exclusive (both are VLAN tags).
    - At most one tunnel type (``--gre``, ``--etherip``, ``--ipip``).

    Returns ``None`` when no encapsulation was requested.
    """
    def _int(attr: str, default: int) -> int:
        v = getattr(args, attr, None)
        return int(v) if v is not None else default

    layers: list[StreamEncap] = []

    # ── Layer-2 tag encaps (order: VLAN/QinQ → MPLS → PPPoE) ─────────────────
    vlan_set  = getattr(args, "vlan", None) is not None
    qinq_set  = getattr(args, "qinq", None) is not None
    if vlan_set and qinq_set:
        print("Error: --vlan and --qinq are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    if vlan_set:
        layers.append(VLANEncap(
            vid=int(args.vlan),
            pcp=_int("vlan_pcp", 0),
            dei=_int("vlan_dei", 0),
        ))
    if qinq_set:
        outer, inner = args.qinq
        layers.append(QinQEncap(
            outer_vid=int(outer),
            inner_vid=int(inner),
            outer_pcp=_int("qinq_outer_pcp", 0),
            outer_dei=_int("qinq_outer_dei", 0),
            inner_pcp=_int("qinq_inner_pcp", 0),
            inner_dei=_int("qinq_inner_dei", 0),
        ))
    if getattr(args, "mpls", None) is not None:
        layers.append(MPLSEncap(
            labels=[int(x) for x in args.mpls],
            tc=_int("mpls_tc", 0),
            ttl=_int("mpls_ttl", 64),
        ))
    if getattr(args, "pppoe", None) is not None:
        layers.append(PPPoEEncap(session_id=int(args.pppoe)))

    # ── Tunnel encap (at most one) ─────────────────────────────────────────────
    tunnel_names = [n for n in ("gre", "etherip", "ipip")
                    if getattr(args, n, None) is not None]
    if len(tunnel_names) > 1:
        print(
            "Error: tunnel encap options are mutually exclusive; got: "
            + ", ".join(f"--{n}" for n in tunnel_names),
            file=sys.stderr,
        )
        sys.exit(1)

    if "gre" in tunnel_names:
        src, dst = args.gre
        key = getattr(args, "gre_key", None)
        layers.append(GREEncap(
            src_ip=src, dst_ip=dst,
            key=int(key) if key is not None else None,
            ttl=_int("gre_ttl", 64),
        ))
    elif "etherip" in tunnel_names:
        src, dst = args.etherip
        layers.append(EtherIPEncap(src_ip=src, dst_ip=dst, ttl=_int("etherip_ttl", 64)))
    elif "ipip" in tunnel_names:
        src, dst = args.ipip
        layers.append(IPIPEncap(src_ip=src, dst_ip=dst, ttl=_int("ipip_ttl", 64)))

    return layers if layers else None


def _stream_to_json(packets: list, include_ethernet: bool) -> str:
    """Serialise *packets* (from any stream generator) as a packet spec string.

    Each packet's raw bytes are parsed with :func:`parse_packet` and converted
    to the same JSON format produced by ``packeteer parse``, so the output can
    be replayed with ``packeteer build``.

    The per-packet ``metadata`` block contains ``timestamp_s``,
    ``timestamp_us``, ``direction`` (``"c2s"`` / ``"s2c"``), and ``label``
    (e.g. ``"SYN"``, ``"DATA[0]"``).
    """
    link_type = LINKTYPE_ETHERNET if include_ethernet else LINKTYPE_RAW
    packet_configs: list[dict] = []
    for pkt_obj in packets:
        pkt = parse_packet(pkt_obj.raw, link_type=link_type)
        cfg: dict = {}
        if pkt.ethernet is not None:
            update_config(cfg, pkt.ethernet)
        for mpls_label in pkt.mpls:
            update_config(cfg, mpls_label)
        if pkt.pppoe is not None:
            update_config(cfg, pkt.pppoe)
        if pkt.ip is not None:
            update_config(cfg, pkt.ip)
        if pkt.ipip or pkt.gre is not None or pkt.etherip is not None or pkt.pseudowire is not None:
            apply_tunneled(cfg, pkt)
        elif pkt.transport is not None:
            update_config(cfg, pkt.transport)
            if pkt.payload:
                update_config(cfg, pkt.payload)
        cfg["packet_metadata"] = {
            "timestamp_s":  pkt_obj.ts_sec,
            "timestamp_us": pkt_obj.ts_usec,
            "direction":    pkt_obj.direction,
            "label":        pkt_obj.label,
        }
        packet_configs.append(cfg)
    return to_json_string(to_packet_spec(packet_configs))


def _validate_stream_args(args: argparse.Namespace) -> str:
    """Validate stream args after defaults are applied.  Returns the protocol string.

    Exits with an error message on any validation failure.
    """
    missing = [f for f in ("client_ip", "server_ip") if not getattr(args, f, None)]
    if missing:
        print(
            "Error: missing required option(s): "
            f"{', '.join('--' + f.replace('_', '-') for f in missing)}. "
            "Provide them on the command line or in the config file.",
            file=sys.stderr,
        )
        sys.exit(1)
    json_out = getattr(args, "json", None)
    if not json_out and not args.pcap and not args.pcapng:
        print(
            "Error: one of --pcap, --pcapng, or --json is required"
            " (on the command line or in the config file).",
            file=sys.stderr,
        )
        sys.exit(1)
    if json_out and (args.pcap or args.pcapng):
        print("Error: --json cannot be combined with --pcap or --pcapng.", file=sys.stderr)
        sys.exit(1)
    if args.pcap and args.pcapng:
        print("Error: --pcap and --pcapng are mutually exclusive.", file=sys.stderr)
        sys.exit(1)
    protocol = args.protocol.lower()
    if protocol not in ("tcp", "udp", "sctp"):
        print(f"Error: --protocol must be 'tcp', 'udp', or 'sctp', got '{args.protocol}'",
              file=sys.stderr)
        sys.exit(1)
    return protocol


def _cmd_stream(args: argparse.Namespace) -> None:
    _apply_stream_defaults(args)
    protocol = _validate_stream_args(args)

    encap = _parse_stream_encap(args)

    # Common keyword arguments shared by all protocol generators
    common = {
        "client_ip": args.client_ip,
        "server_ip": args.server_ip,
        "client_port": args.client_port,
        "server_port": args.server_port,
        "client_mac": args.client_mac,
        "server_mac": args.server_mac,
        "num_data_packets": args.packets,
        "min_payload": args.min_payload,
        "max_payload": args.max_payload,
        "payload_distribution": args.distribution,
        "include_ethernet": not args.no_ethernet,
        "ip_ttl": args.ttl,
        "inter_packet_gap": args.gap,
        "mtu": args.mtu,
        "encap": encap,
    }

    try:
        if protocol == "tcp":
            stream = generate_tcp_stream(
                **common,
                config=TCPStreamConfig(
                    gap_jitter=args.gap_jitter,
                    window=args.window,
                    psh_probability=args.psh_probability,
                    packet_loss_probability=args.packet_loss_probability,
                    retransmission_probability=args.retransmission_probability,
                    retransmission_timeout=args.retransmission_timeout,
                    payload_corruption_probability=args.payload_corruption_probability,
                    server_rst_probability=args.server_rst_probability,
                    rst_propagation_delay=args.rst_propagation_delay,
                    stray_packet_count=args.stray_packet_count,
                    stray_timing_window=args.stray_timing_window,
                    seed=args.seed,
                ),
            )
        elif protocol == "udp":
            stream = generate_udp_stream(
                **common,
                config=UDPStreamConfig(gap_jitter=args.gap_jitter, seed=args.seed),
            )
        else:  # sctp
            stream = generate_sctp_stream(
                **common,
                config=SCTPStreamConfig(gap_jitter=args.gap_jitter, seed=args.seed),
            )
    except (ValueError, OSError) as e:
        print(f"Error generating stream: {e}", file=sys.stderr)
        sys.exit(1)

    include_ethernet = not args.no_ethernet
    link_type = LINKTYPE_ETHERNET if include_ethernet else LINKTYPE_RAW

    if args.json:
        json_str = _stream_to_json(stream.packets, include_ethernet)
        try:
            with open(args.json, "w") as f:
                f.write(json_str)
                f.write("\n")
        except OSError as e:
            print(f"Error writing '{args.json}': {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Wrote {len(stream.packets)} packet(s) to {args.json} (packet spec)")
    else:
        tuples = stream.to_pcap_tuples()
        try:
            if args.pcap:
                write_pcap(tuples, path=args.pcap, link_type=link_type)
                print(f"Wrote {len(tuples)} packet(s) to {args.pcap} (link type: {link_type})")
            else:
                write_pcapng(tuples, path=args.pcapng, link_type=link_type)
                print(f"Wrote {len(tuples)} packet(s) to {args.pcapng} (link type: {link_type})")
        except OSError as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            sys.exit(1)


def main() -> None:
    """Entry point for the ``packeteer`` CLI command."""
    parser = argparse.ArgumentParser(
        description="Build and parse raw network packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    try:
        _version = _pkg_version("packeteer")
    except _PkgNotFoundError:
        _version = "unknown"
    parser.add_argument("--version", action="version", version=f"packeteer {_version}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── build subcommand ──────────────────────────────────────────────────────
    build_parser = subparsers.add_parser(
        "build",
        help="Build packets from a packet spec file",
        description="Build packets from a packet spec file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    build_parser.add_argument(
        "config", metavar="FILE",
        help="Packet spec file with a 'packets' array",
    )
    build_out = build_parser.add_mutually_exclusive_group(required=True)
    build_out.add_argument("--pcap", metavar="FILE", help="Write packets to a libpcap (.pcap) file")
    build_out.add_argument("--pcapng", metavar="FILE",
                           help="Write packets to a pcapng (.pcapng) file")
    build_parser.set_defaults(func=_cmd_build)

    # ── parse subcommand ──────────────────────────────────────────────────────
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse a pcap or pcapng file and produce a packet spec",
        description=(
            "Parse a pcap or pcapng file and produce a packet spec"
            " that can be replayed with 'packeteer build'"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parse_parser.add_argument(
        "pcap",
        metavar="FILE",
        help="Input .pcap or .pcapng file to parse",
    )
    parse_parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write packet spec to FILE instead of stdout",
    )
    parse_parser.add_argument(
        "--link-type",
        metavar="TYPE",
        type=_link_type,
        default=None,
        help=(
            "Override the link-layer type in the file header when it is wrong. "
            "Accepts 'ethernet', 'raw', or an integer (e.g. 1, 101)."
        ),
    )
    filter_group = parse_parser.add_argument_group(
        "filtering",
        "Keep only packets that match ALL of the given criteria.  Prefix a value "
        "with ! to negate it (e.g. --proto !tcp).  For comma-separated lists all "
        "values must be consistently positive or consistently negative.",
    )
    filter_group.add_argument(
        "--proto", metavar="PROTO",
        help="IP protocol: tcp, udp, sctp, icmp, icmpv6 (or negated, e.g. !tcp)",
    )
    filter_group.add_argument(
        "--port", metavar="PORTS",
        help="Source-or-destination port(s), comma-separated (e.g. 80,443 or !80,!443)",
    )
    filter_group.add_argument(
        "--src-port", metavar="PORTS", dest="src_port",
        help="Source port(s), comma-separated",
    )
    filter_group.add_argument(
        "--dst-port", metavar="PORTS", dest="dst_port",
        help="Destination port(s), comma-separated",
    )
    filter_group.add_argument(
        "--src", metavar="ADDR",
        help="Source IP address or CIDR (IPv4 or IPv6, e.g. 10.0.0.0/24 or !192.168.1.1)",
    )
    filter_group.add_argument(
        "--dst", metavar="ADDR",
        help="Destination IP address or CIDR",
    )
    filter_group.add_argument(
        "--host", metavar="ADDR",
        help="Source-or-destination IP address or CIDR",
    )
    filter_group.add_argument(
        "--app", metavar="APP",
        help="Application layer present: dns, dhcp, http (or negated, e.g. !http)",
    )

    parse_parser.set_defaults(func=_cmd_parse)

    # ── file-info subcommand ──────────────────────────────────────────────────
    info_parser = subparsers.add_parser(
        "file-info",
        help="Summarise a pcap/pcapng file: packets, sessions, and layer stats",
        description=(
            "Report on a pcap or pcapng capture: packet count, number of "
            "directional sessions (unique 5-tuples), and per-protocol-layer "
            "statistics.\n\n"
            "When the link-layer type recorded in the file header would produce "
            "garbage, the cleanest-parsing type is detected and used "
            "automatically.  Pass --link-type to force a type, or "
            "--no-auto-link-type to always trust the header."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    info_parser.add_argument(
        "pcap",
        metavar="FILE",
        help="Input .pcap or .pcapng file to inspect",
    )
    info_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON instead of human-readable text",
    )
    info_parser.add_argument(
        "--link-type",
        metavar="TYPE",
        type=_link_type,
        default=None,
        help=(
            "Force the link-layer type (disables auto-detection).  Accepts "
            "'ethernet', 'raw', or an integer (e.g. 1, 101)."
        ),
    )
    info_parser.add_argument(
        "--no-auto-link-type",
        action="store_true",
        help="Trust the file header's link-layer type instead of auto-detecting",
    )
    info_parser.set_defaults(func=_cmd_file_info)

    # ── sanitise subcommand ───────────────────────────────────────────────────
    san_parser = subparsers.add_parser(
        "sanitise",
        help="Replace sensitive fields in a packet spec or pcap with synthetic data",
        description=(
            "Replace sensitive fields (IP addresses, MACs, ports, payload, timestamps) "
            "with synthetic data drawn from IANA-reserved ranges. "
            "The same original value always maps to the same synthetic value, so the "
            "communication structure is preserved.\n\n"
            "FILE may be a JSON packet spec or a .pcap/.pcapng capture file. "
            "When a capture file is given, it is parsed automatically before sanitising."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    san_parser.add_argument(
        "input", metavar="FILE",
        help="Input packet spec (.json) or capture file (.pcap/.pcapng)",
    )
    san_parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write sanitised packet spec (JSON) to FILE instead of stdout",
    )
    san_parser.add_argument(
        "--link-type",
        metavar="TYPE",
        type=_link_type,
        default=None,
        help=(
            "Override the link-layer type when parsing a capture file whose "
            "header is wrong.  Accepts 'ethernet', 'raw', or an integer "
            "(e.g. 1, 101).  Ignored for JSON input."
        ),
    )
    san_parser.add_argument(
        "--pcap", metavar="FILE",
        help="Write sanitised packets to a libpcap (.pcap) file",
    )
    san_parser.add_argument(
        "--pcapng", metavar="FILE",
        help="Write sanitised packets to a pcapng (.pcapng) file",
    )
    san_parser.add_argument(
        "--no-ips", action="store_true",
        help="Do not replace IP addresses (default: replaced)",
    )
    san_parser.add_argument(
        "--no-macs", action="store_true",
        help="Do not replace MAC addresses (default: replaced)",
    )
    san_parser.add_argument(
        "--ports", action="store_true",
        help="Replace TCP/UDP port numbers (default: kept)",
    )
    san_parser.add_argument(
        "--payload", action="store_true",
        help="Zero out payload data (default: kept)",
    )
    san_parser.add_argument(
        "--timestamps", action="store_true",
        help="Zero out packet timestamps (default: kept)",
    )
    san_parser.add_argument(
        "--dns-ids", action="store_true",
        help="Zero out DNS transaction IDs (default: kept)",
    )
    san_parser.add_argument(
        "--dhcp-xids", action="store_true",
        help="Zero out DHCP transaction IDs (xid field) (default: kept)",
    )
    san_parser.add_argument(
        "--http-headers", action="store_true",
        help="Redact sensitive HTTP headers: Host, Cookie, Set-Cookie, "
             "Authorization, Location, Referer, Origin (default: kept)",
    )
    san_parser.add_argument(
        "--scan-pii", action=argparse.BooleanOptionalAction, default=True, dest="scan_pii",
        help="Scan UTF-8 payloads for email addresses and names; "
             "warn on findings (does not modify data) (default: enabled)",
    )
    san_parser.set_defaults(func=_cmd_sanitise)

    # ── fuzz subcommand ───────────────────────────────────────────────────────
    _mut_help = ", ".join(ALL_MUTATION_NAMES)
    fuzz_parser = subparsers.add_parser(
        "fuzz",
        help="Generate adversarial packet variants for decoder robustness testing",
        description=(
            "Read packets from a JSON spec or pcap/pcapng file and produce a set of\n"
            "deliberately broken variants for testing how decoders handle edge cases.\n\n"
            "Spec-level mutations (included in JSON and pcap output):\n"
            "  boundary      — numeric fields at min/near-min/near-max/max values\n"
            "  reserved-bits — reserved IPv4/TCP flag bits set\n"
            "  tcp-flags     — pathological TCP flag combinations\n"
            "  truncate      — payload shortened or removed\n"
            "  extend        — extra zero or random bytes appended\n\n"
            "Byte-level mutations (pcap/pcapng output only):\n"
            "  bit-flip      — one random bit flipped per variant\n"
            "  wrong-checksum — IP/TCP/UDP checksums set to 0x0000, 0xffff, inverted\n"
            "  wrong-length  — IP total-length and UDP length fields corrupted"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fuzz_parser.add_argument(
        "input", metavar="FILE",
        help="Input packet spec (.json) or capture file (.pcap/.pcapng)",
    )
    fuzz_parser.add_argument(
        "--output", "-o", metavar="FILE",
        help=(
            "Write fuzz variant spec (JSON) to FILE instead of stdout.  "
            "Only spec-level mutations are included; use --pcap/--pcapng for byte-level."
        ),
    )
    fuzz_parser.add_argument(
        "--pcap", metavar="FILE",
        help="Write all variants (including byte-level) to a libpcap (.pcap) file",
    )
    fuzz_parser.add_argument(
        "--pcapng", metavar="FILE",
        help="Write all variants (including byte-level) to a pcapng (.pcapng) file",
    )
    fuzz_parser.add_argument(
        "--mutations", metavar="MUTATION", nargs="+",
        help=f"Mutation types to apply (default: all). Available: {_mut_help}",
    )
    fuzz_parser.add_argument(
        "--count", type=int, default=10, metavar="N",
        help="Number of bit-flip variants per source packet (default: 10)",
    )
    fuzz_parser.add_argument(
        "--seed", type=int, default=None, metavar="N",
        help="RNG seed for reproducible random variants (default: non-deterministic)",
    )
    fuzz_parser.set_defaults(func=_cmd_fuzz)

    # ── stream subcommand ─────────────────────────────────────────────────────
    stream_parser = subparsers.add_parser(
        "stream",
        help="Generate a synthetic protocol stream",
        description=(
            "Generate a realistic protocol stream and write it to a pcap or pcapng file.\n\n"
            "  tcp   — three-way handshake, data transfer, four-way teardown; "
            "seq/ack numbers computed correctly.\n"
            "  udp   — sequence of datagrams with realistic inter-packet timestamps.\n"
            "  sctp  — four-way handshake (INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK), "
            "DATA+SACK pairs, graceful shutdown; CRC-32c checksums computed automatically."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Config file (optional — CLI flags take precedence over config values)
    stream_parser.add_argument(
        "--config", metavar="FILE",
        help="INI config file with a [stream] section; CLI flags override file values",
    )
    stream_parser.add_argument(
        "--protocol", default=None, choices=["tcp", "udp", "sctp"],
        help="Transport protocol to simulate (default: tcp)",
    )
    # Required endpoints (may also be provided via --config)
    stream_parser.add_argument(
        "--client-ip", default=None, metavar="IP",
        help="Client IP address (IPv4 or IPv6)",
    )
    stream_parser.add_argument(
        "--server-ip", default=None, metavar="IP",
        help="Server IP address (same family as --client-ip)",
    )
    # Optional endpoint fields
    stream_parser.add_argument(
        "--client-port", type=int, default=None, metavar="PORT",
        help="Client source port (default: 54321)",
    )
    stream_parser.add_argument(
        "--server-port", type=int, default=None, metavar="PORT",
        help="Server destination port (default: 80)",
    )
    stream_parser.add_argument(
        "--client-mac", default=None, metavar="MAC",
        help="Client MAC address (default: 00:00:00:00:00:01)",
    )
    stream_parser.add_argument(
        "--server-mac", default=None, metavar="MAC",
        help="Server MAC address (default: 00:00:00:00:00:02)",
    )
    # Stream shape
    stream_parser.add_argument(
        "--packets", type=int, default=None, metavar="N",
        help="Number of data packets sent by the client (default: 10)",
    )
    stream_parser.add_argument(
        "--min-payload", type=int, default=None, metavar="BYTES",
        help="Minimum payload size in bytes (default: 40)",
    )
    stream_parser.add_argument(
        "--max-payload", type=int, default=None, metavar="BYTES",
        help="Maximum payload size in bytes (default: 1460)",
    )
    stream_parser.add_argument(
        "--distribution", default=None, choices=["uniform", "bimodal", "fixed"],
        help="Payload size distribution (default: uniform)",
    )
    # IP / TCP tuning
    stream_parser.add_argument(
        "--ttl", type=int, default=None, metavar="N",
        help="IP TTL / hop limit (default: 64)",
    )
    stream_parser.add_argument(
        "--window", type=int, default=None, metavar="BYTES",
        help="TCP receive window size — TCP only (default: 65535)",
    )
    stream_parser.add_argument(
        "--gap", type=float, default=None, metavar="SECONDS",
        help="Inter-packet gap in seconds (default: 0.001)",
    )
    stream_parser.add_argument(
        "--gap-jitter", type=float, default=None, metavar="SECONDS",
        help=(
            "Max additional delay per gap; each gap is drawn from [gap, gap+jitter]"
            " and packets are re-sorted by timestamp (default: 0.0)"
        ),
    )
    stream_parser.add_argument(
        "--psh-probability", type=float, default=None, metavar="PROB",
        help="Probability (0.0-1.0) that PSH is set on each data segment (default: 0.5)",
    )
    stream_parser.add_argument(
        "--packet-loss", type=float, default=None, metavar="PROB",
        dest="packet_loss_probability",
        help=(
            "Probability (0.0-1.0) that any packet is dropped from the capture"
            " (default: 0.0)"
        ),
    )
    stream_parser.add_argument(
        "--retransmission-probability", type=float, default=None, metavar="PROB",
        help=(
            "Probability (0.0-1.0) that each data segment gets a spurious"
            " retransmission (default: 0.0)"
        ),
    )
    stream_parser.add_argument(
        "--retransmission-timeout", type=float, default=None, metavar="SECONDS",
        help=(
            "Seconds after original send that the retransmission timer fires"
            " (default: 0.2)"
        ),
    )
    stream_parser.add_argument(
        "--payload-corruption", type=float, default=None, metavar="PROB",
        dest="payload_corruption_probability",
        help=(
            "Probability (0.0-1.0) that each data segment's payload is corrupted"
            " in transit (default: 0.0)"
        ),
    )
    stream_parser.add_argument(
        "--server-rst", type=float, default=None, metavar="PROB",
        dest="server_rst_probability",
        help=(
            "Probability (0.0-1.0) that the server terminates mid-stream with"
            " a RST (default: 0.0)"
        ),
    )
    stream_parser.add_argument(
        "--rst-propagation-delay", type=float, default=None, metavar="SECONDS",
        help=(
            "Seconds for the RST to reach the client; client sends data"
            " during this window (default: 0.0)"
        ),
    )
    stream_parser.add_argument(
        "--mtu", type=int, default=None, metavar="BYTES",
        help=(
            "Fragment packets as if they passed through a middlebox with this"
            " IP MTU (e.g. 576, 1280, 1400). Default: no fragmentation"
        ),
    )
    stream_parser.add_argument(
        "--stray-packets", type=int, default=None, metavar="N",
        dest="stray_packet_count",
        help="Number of forged TCP hijack packets to inject (default: 0)",
    )
    stream_parser.add_argument(
        "--stray-timing-window", type=int, default=None, metavar="N",
        dest="stray_timing_window",
        help=(
            "Constrain each stray packet timestamp to within N packets of its"
            " reference DATA packet (default: full data-transfer window)"
        ),
    )
    stream_parser.add_argument(
        "--no-ethernet", action="store_true", default=False,
        help="Omit Ethernet headers (write raw IP packets)",
    )
    # ── Encapsulation (mutually exclusive primary flags + optional detail flags) ─
    encap_group = stream_parser.add_argument_group(
        "encapsulation",
        "Wrap each packet in an additional protocol layer.  Exactly one primary "
        "encap flag may be used per stream.  Detail flags refine the selected encap.",
    )
    encap_group.add_argument(
        "--vlan", type=int, default=None, metavar="VID",
        help="Single 802.1Q VLAN tag with the given VLAN ID (1–4094)",
    )
    encap_group.add_argument(
        "--vlan-pcp", type=int, default=None, metavar="N",
        dest="vlan_pcp",
        help="VLAN Priority Code Point (0–7, default 0); used with --vlan",
    )
    encap_group.add_argument(
        "--vlan-dei", type=int, default=None, metavar="N",
        dest="vlan_dei",
        help="VLAN Drop Eligible Indicator (0 or 1, default 0); used with --vlan",
    )
    encap_group.add_argument(
        "--qinq", nargs=2, type=int, default=None,
        metavar=("OUTER_VID", "INNER_VID"),
        help="QinQ double VLAN tag (outer VID then inner VID)",
    )
    encap_group.add_argument(
        "--qinq-outer-pcp", type=int, default=None, metavar="N",
        dest="qinq_outer_pcp",
        help="Outer VLAN PCP (0–7, default 0); used with --qinq",
    )
    encap_group.add_argument(
        "--qinq-outer-dei", type=int, default=None, metavar="N",
        dest="qinq_outer_dei",
        help="Outer VLAN DEI (0 or 1, default 0); used with --qinq",
    )
    encap_group.add_argument(
        "--qinq-inner-pcp", type=int, default=None, metavar="N",
        dest="qinq_inner_pcp",
        help="Inner VLAN PCP (0–7, default 0); used with --qinq",
    )
    encap_group.add_argument(
        "--qinq-inner-dei", type=int, default=None, metavar="N",
        dest="qinq_inner_dei",
        help="Inner VLAN DEI (0 or 1, default 0); used with --qinq",
    )
    encap_group.add_argument(
        "--mpls", nargs="+", type=int, default=None, metavar="LABEL",
        help="MPLS label stack (one or more 20-bit labels, outermost first)",
    )
    encap_group.add_argument(
        "--mpls-tc", type=int, default=None, metavar="N",
        dest="mpls_tc",
        help="MPLS Traffic Class for all labels (0–7, default 0)",
    )
    encap_group.add_argument(
        "--mpls-ttl", type=int, default=None, metavar="N",
        dest="mpls_ttl",
        help="MPLS TTL for all labels (0–255, default 64)",
    )
    encap_group.add_argument(
        "--pppoe", type=int, default=None, metavar="SESSION_ID",
        help="PPPoE session frame with the given 16-bit session ID",
    )
    encap_group.add_argument(
        "--gre", nargs=2, default=None,
        metavar=("OUTER_SRC", "OUTER_DST"),
        help="GRE tunnel; specify outer IP source and destination",
    )
    encap_group.add_argument(
        "--gre-key", type=int, default=None, metavar="KEY",
        dest="gre_key",
        help="RFC 2890 32-bit GRE Key field; used with --gre",
    )
    encap_group.add_argument(
        "--gre-ttl", type=int, default=None, metavar="N",
        dest="gre_ttl",
        help="Outer IP TTL for GRE tunnel (default 64)",
    )
    encap_group.add_argument(
        "--etherip", nargs=2, default=None,
        metavar=("OUTER_SRC", "OUTER_DST"),
        help="EtherIP tunnel (RFC 3378); specify outer IP source and destination",
    )
    encap_group.add_argument(
        "--etherip-ttl", type=int, default=None, metavar="N",
        dest="etherip_ttl",
        help="Outer IP TTL for EtherIP tunnel (default 64)",
    )
    encap_group.add_argument(
        "--ipip", nargs=2, default=None,
        metavar=("OUTER_SRC", "OUTER_DST"),
        help="IP-in-IP tunnel (RFC 2003/4213); specify outer IP source and destination",
    )
    encap_group.add_argument(
        "--ipip-ttl", type=int, default=None, metavar="N",
        dest="ipip_ttl",
        help="Outer IP TTL for IP-in-IP tunnel (default 64)",
    )
    # Output (may also be provided via --config; mutual exclusivity enforced in _cmd_stream)
    stream_parser.add_argument("--pcap", default=None, metavar="FILE",
                               help="Write to a libpcap (.pcap) file")
    stream_parser.add_argument("--pcapng", default=None, metavar="FILE",
                               help="Write to a pcapng (.pcapng) file")
    stream_parser.add_argument(
        "--json", default=None, metavar="FILE",
        help=(
            "Write packets as a packet spec file (same format produced by"
            " 'packeteer parse', replayable with 'packeteer build')"
        ),
    )
    stream_parser.add_argument(
        "--seed", type=int, default=None, metavar="N",
        help="RNG seed for reproducible stream generation (default: non-deterministic)",
    )
    stream_parser.set_defaults(func=_cmd_stream)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
