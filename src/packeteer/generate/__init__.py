"""packeteer.generate — build complete raw network packets in pure Python.

This package constructs byte-accurate network packets at all layers:

* **Layer 2** — Ethernet II frames (:class:`EthernetHeader`), IEEE 802.1Q
  VLAN tags (:class:`VLANTag`), PPPoE session and discovery frames
  (:class:`PPPoEHeader`, :class:`PPPoETag`)
* **Layer 2.5** — MPLS label stacks (:class:`MPLSLabel`, RFC 3032)
* **Layer 3** — IPv4 (:class:`IPHeader`) and IPv6 (:class:`IPv6Header`);
  IP-in-IP tunnels (RFC 2003 / RFC 4213);
  EtherIP tunnels (:class:`EtherIPHeader`, RFC 3378);
  GRE tunnels (:class:`GREHeader`, RFC 2784 / RFC 2890);
  VXLAN tunnels (:class:`VXLANHeader`, RFC 7348);
  GENEVE tunnels (:class:`GeneveHeader`, RFC 8926)
* **Layer 4** — TCP (:class:`TCPHeader`), UDP (:class:`UDPHeader`),
  SCTP (:class:`SCTPHeader`, RFC 9260), ICMPv4 (:class:`ICMPHeader`),
  ICMPv6 (:class:`ICMPv6Header`)

All IP and transport-layer checksums are computed automatically per their
respective RFCs (RFC 791, RFC 8200, RFC 768, RFC 793, RFC 792, RFC 4443).

Fragmentation is supported via :meth:`PacketBuilder.fragment` (high-level)
or the low-level :func:`fragment_ipv4` and :func:`fragment_ipv6` functions.

The recommended entry point is :class:`PacketBuilder`, which wires all
layers together and exposes a clean, high-level API.  Each fluent method
**appends** a layer to an ordered stack, so the same method can be called
multiple times to produce advanced encapsulations.

.. code-block:: python

    from packeteer.generate import PacketBuilder

    # IPv4 TCP packet (Ethernet + IP + TCP + 64 random payload bytes)
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="192.168.1.1", dst="8.8.8.8")
        .tcp(dst_port=443)
        .payload(size=64)
        .build()
    )

    # IPv6 UDP packet without Ethernet header
    pkt = (PacketBuilder()
        .ip(src="fe80::1", dst="fe80::2")
        .udp()
        .payload(size=20)
        .build()
    )

    # ICMPv6 Echo Request with explicit payload
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="::1", dst="::2")
        .icmpv6()
        .payload(data=b"hello ipv6")
        .build()
    )

    # QinQ (802.1ad) double-tagged frame — call .vlan() twice
    pkt = (PacketBuilder()
        .ethernet()
        .vlan(vid=100)   # outer VLAN
        .vlan(vid=200)   # inner VLAN
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .build()
    )

    # MPLS label stack — call .mpls() for each label (RFC 3032)
    pkt = (PacketBuilder()
        .ethernet()
        .mpls(label=100)   # outer label (S=0)
        .mpls(label=200)   # inner label (S=1, bottom of stack)
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .build()
    )

    # IP-in-IP tunnel — call .ip() twice
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="203.0.113.1", dst="203.0.113.2")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .tcp(dst_port=80)
        .build()
    )

    # PPPoE session carrying IPv4 TCP (RFC 2516)
    pkt = (PacketBuilder()
        .ethernet()
        .pppoe(session_id=0x1234)
        .ip(src="10.0.0.1", dst="8.8.8.8")
        .tcp(dst_port=80)
        .build()
    )

    # EtherIP tunnel (RFC 3378) — outer IP carries an inner Ethernet frame
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .etherip()
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )

    # GRE tunnel (RFC 2784) — IPv4-in-GRE with Key (RFC 2890)
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .gre(key=1234)
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )

    # VXLAN tunnel (RFC 7348) — outer UDP:4789 + VXLAN + inner Ethernet frame
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp(dst_port=4789)
        .vxlan(vni=5000)
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )

    # GENEVE tunnel (RFC 8926) — outer UDP:6081 + GENEVE + inner Ethernet frame
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .geneve(vni=5000)
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )

    # PPPoE PADI discovery frame
    from packeteer.generate import PPPOE_CODE_PADI, PPPoETag, PPPOE_TAG_SERVICE_NAME
    pkt = (PacketBuilder()
        .ethernet(dst_mac="ff:ff:ff:ff:ff:ff")
        .pppoe(code=PPPOE_CODE_PADI, tags=[PPPoETag(PPPOE_TAG_SERVICE_NAME, b"")])
        .build()
    )

Public API:
    PacketBuilder: High-level packet assembly class.
    EthernetHeader: Dataclass for Ethernet II header fields
        (dst_mac, src_mac, ethertype, vlan_tag, pad).
    EtherIPHeader: Dataclass for the EtherIP tunnel header (RFC 3378). No user-configurable fields.
    IPPROTO_ETHERIP: IP protocol number 97 — EtherIP (RFC 3378).
    GREHeader: Dataclass for the GRE tunnel header (RFC 2784 / RFC 2890).
        Fields: key, seq, checksum, protocol_type.
    IPPROTO_GRE: IP protocol number 47 — GRE (RFC 2784).
    GRE_PROTO_IPV4: GRE Protocol Type 0x0800 — IPv4 payload.
    GRE_PROTO_IPV6: GRE Protocol Type 0x86DD — IPv6 payload.
    GRE_PROTO_TEB: GRE Protocol Type 0x6558 — Transparent Ethernet Bridging (inner Ethernet frame).
    VXLANHeader: Dataclass for the VXLAN tunnel header (RFC 7348). Fields: vni, flags.
    VXLAN_PORT: IANA UDP destination port 4789 — VXLAN (RFC 7348).
    VXLAN_FLAG_VALID_VNI: VXLAN flags byte 0x08 — the I (VNI valid) bit.
    GeneveHeader: Dataclass for the GENEVE tunnel header (RFC 8926).
        Fields: vni, protocol_type, options, oam, version.
    GeneveOption: Dataclass for one GENEVE TLV option (option_class, type, critical, data).
    GENEVE_PORT: IANA UDP destination port 6081 — GENEVE (RFC 8926).
    GENEVE_PROTO_IPV4: GENEVE Protocol Type 0x0800 — IPv4 payload.
    GENEVE_PROTO_IPV6: GENEVE Protocol Type 0x86DD — IPv6 payload.
    GENEVE_PROTO_TEB: GENEVE Protocol Type 0x6558 — inner Ethernet frame.
    VLANTag: Dataclass for IEEE 802.1Q VLAN tag fields.
    MPLSLabel: Dataclass for one MPLS label stack entry (RFC 3032).
    ETHERTYPE_MPLS_UNICAST: EtherType 0x8847 — MPLS unicast.
    ETHERTYPE_MPLS_MULTICAST: EtherType 0x8848 — MPLS multicast.
    PPPoEHeader: Dataclass for a PPPoE frame header (RFC 2516).
    PPPoETag: Dataclass for one PPPoE TLV tag.
    ETHERTYPE_PPPOE_DISCOVERY: EtherType 0x8863 — PPPoE discovery.
    ETHERTYPE_PPPOE_SESSION: EtherType 0x8864 — PPPoE session.
    PPP_IPV4: PPP protocol number 0x0021 — IPv4.
    PPP_IPV6: PPP protocol number 0x0057 — IPv6.
    PPPOE_CODE_SESSION, PPPOE_CODE_PADI, PPPOE_CODE_PADO, PPPOE_CODE_PADR,
        PPPOE_CODE_PADS, PPPOE_CODE_PADT: PPPoE message code constants.
    PPPOE_TAG_SERVICE_NAME, PPPOE_TAG_AC_NAME, PPPOE_TAG_HOST_UNIQ,
        PPPOE_TAG_AC_COOKIE, PPPOE_TAG_GENERIC_ERROR: PPPoE tag type constants.
    IPHeader: Dataclass for IPv4 header fields.
    IPv6Header: Dataclass for IPv6 header fields.
    TCPHeader: Dataclass for TCP header fields.
    TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR:
        TCP flag bit-mask constants.
    TCPOptions: Dataclass for TCP header options (MSS, Window Scale, SACK, Timestamps).
    UDPHeader: Dataclass for UDP header fields.
    ICMPHeader: Dataclass for ICMPv4 header fields.
    ICMPv6Header: Dataclass for ICMPv6 header fields.
    write_pcap: Write raw packet bytes to a libpcap (.pcap) file.
    write_pcapng: Write raw packet bytes to a pcapng (.pcapng) file.
    LINKTYPE_ETHERNET: pcap/pcapng link-layer type 1 — Ethernet II.
    LINKTYPE_RAW: pcap/pcapng link-layer type 101 — raw IP (no Ethernet header).
"""
from __future__ import annotations

from .builder import PacketBuilder
from .dhcp import (
    DHCP_MSG_ACK,
    DHCP_MSG_DECLINE,
    DHCP_MSG_DISCOVER,
    DHCP_MSG_INFORM,
    DHCP_MSG_NAK,
    DHCP_MSG_OFFER,
    DHCP_MSG_RELEASE,
    DHCP_MSG_REQUEST,
    DHCP_OP_REPLY,
    DHCP_OP_REQUEST,
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
    DHCP_PORT_CLIENT,
    DHCP_PORT_SERVER,
    DHCPMessage,
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
from .dns import (
    DNS_CLASS_IN,
    DNS_RCODE_FORMERR,
    DNS_RCODE_NOERROR,
    DNS_RCODE_NOTIMP,
    DNS_RCODE_NXDOMAIN,
    DNS_RCODE_REFUSED,
    DNS_RCODE_SERVFAIL,
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    DNS_TYPE_MX,
    DNS_TYPE_NS,
    DNS_TYPE_PTR,
    DNS_TYPE_SOA,
    DNS_TYPE_TXT,
    MDNS_ADDR_IPV4,
    MDNS_ADDR_IPV6,
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
)
from .etherip import IPPROTO_ETHERIP, EtherIPHeader
from .ethernet import (
    ETHERNET_MIN_FRAME_SIZE,
    ETHERTYPE_8021Q,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    EthernetHeader,
    VLANTag,
)
from .fragmentation import fragment_ipv4, fragment_ipv6
from .geneve import (
    GENEVE_PORT,
    GENEVE_PROTO_IPV4,
    GENEVE_PROTO_IPV6,
    GENEVE_PROTO_TEB,
    GeneveHeader,
    GeneveOption,
)
from .gre import GRE_PROTO_IPV4, GRE_PROTO_IPV6, GRE_PROTO_TEB, IPPROTO_GRE, GREHeader
from .http import HTTP_ALT_PORT, HTTP_PORT, HTTPRequest, HTTPResponse
from .icmp import ICMPHeader
from .icmpv6 import ICMPv6Header
from .ip import IPHeader
from .ipv6 import (
    HBH_NEXT_HEADER,
    HBH_OPT_JUMBO_PAYLOAD,
    HBH_OPT_ROUTER_ALERT,
    HopByHopOptions,
    IPv6Header,
    JumboPayloadOption,
    RawOption,
    RouterAlertOption,
)
from .mpls import ETHERTYPE_MPLS_MULTICAST, ETHERTYPE_MPLS_UNICAST, MPLSLabel
from .payloads import (
    PAYLOAD_TYPES,
    AppMessage,
    HTTPRestConfig,
    VPNConfig,
    generate_http_conversation,
    generate_http_stream,
    generate_vpn_stream,
    render_tcp_session,
    render_udp_session,
)
from .pppoe import (
    ETHERTYPE_PPPOE_DISCOVERY,
    ETHERTYPE_PPPOE_SESSION,
    PPP_IPV4,
    PPP_IPV6,
    PPPOE_CODE_PADI,
    PPPOE_CODE_PADO,
    PPPOE_CODE_PADR,
    PPPOE_CODE_PADS,
    PPPOE_CODE_PADT,
    PPPOE_CODE_SESSION,
    PPPOE_TAG_AC_COOKIE,
    PPPOE_TAG_AC_NAME,
    PPPOE_TAG_GENERIC_ERROR,
    PPPOE_TAG_HOST_UNIQ,
    PPPOE_TAG_SERVICE_NAME,
    PPPoEHeader,
    PPPoETag,
)
from .sctp import (
    IPPROTO_SCTP,
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
    SCTP_DATA_FLAG_BEGINNING,
    SCTP_DATA_FLAG_ENDING,
    SCTP_DATA_FLAG_IMMEDIATE,
    SCTP_DATA_FLAG_UNORDERED,
    SCTPAbortChunk,
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
)
from .sctp_stream import SCTPStream, SCTPStreamConfig, SCTPStreamPacket, generate_sctp_stream
from .session import (
    SCTPSession,
    TCPSession,
    UDPSession,
    sctp_handshake,
    tcp_handshake,
    tcp_teardown,
)
from .session_mix import CombinedStream, generate_session_mix, merge_streams
from .stream_encap import (
    EncapSpec,
    EtherIPEncap,
    GeneveEncap,
    GREEncap,
    IPIPEncap,
    MPLSEncap,
    PPPoEEncap,
    QinQEncap,
    StreamEncap,
    VLANEncap,
    VXLANEncap,
)
from .tcp import (
    TCP_ACK,
    TCP_CWR,
    TCP_ECE,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_URG,
    TCPHeader,
    TCPOptions,
)
from .tcp_stream import TCPStream, TCPStreamConfig, TCPStreamPacket, generate_tcp_stream
from .udp import UDPHeader
from .udp_stream import UDPStream, UDPStreamConfig, UDPStreamPacket, generate_udp_stream
from .vxlan import VXLAN_FLAG_VALID_VNI, VXLAN_PORT, VXLANHeader

__all__ = [
    "PacketBuilder",
    "EthernetHeader",
    "VLANTag",
    "ETHERNET_MIN_FRAME_SIZE",
    "ETHERTYPE_IPV4",
    "ETHERTYPE_IPV6",
    "ETHERTYPE_8021Q",
    "EtherIPHeader",
    "IPPROTO_ETHERIP",
    "GREHeader",
    "IPPROTO_GRE",
    "GRE_PROTO_IPV4",
    "GRE_PROTO_IPV6",
    "GRE_PROTO_TEB",
    "VXLANHeader",
    "VXLAN_PORT",
    "VXLAN_FLAG_VALID_VNI",
    "GeneveHeader",
    "GeneveOption",
    "GENEVE_PORT",
    "GENEVE_PROTO_IPV4",
    "GENEVE_PROTO_IPV6",
    "GENEVE_PROTO_TEB",
    "IPHeader",
    "IPv6Header",
    "HopByHopOptions",
    "RouterAlertOption",
    "JumboPayloadOption",
    "RawOption",
    "HBH_NEXT_HEADER",
    "HBH_OPT_ROUTER_ALERT",
    "HBH_OPT_JUMBO_PAYLOAD",
    "TCPHeader",
    "TCPOptions",
    "TCP_FIN",
    "TCP_SYN",
    "TCP_RST",
    "TCP_PSH",
    "TCP_ACK",
    "TCP_URG",
    "TCP_ECE",
    "TCP_CWR",
    "UDPHeader",
    "ICMPHeader",
    "ICMPv6Header",
    "MPLSLabel",
    "ETHERTYPE_MPLS_UNICAST",
    "ETHERTYPE_MPLS_MULTICAST",
    "PPPoEHeader",
    "PPPoETag",
    "ETHERTYPE_PPPOE_DISCOVERY",
    "ETHERTYPE_PPPOE_SESSION",
    "PPP_IPV4",
    "PPP_IPV6",
    "PPPOE_CODE_SESSION",
    "PPPOE_CODE_PADI",
    "PPPOE_CODE_PADO",
    "PPPOE_CODE_PADR",
    "PPPOE_CODE_PADS",
    "PPPOE_CODE_PADT",
    "PPPOE_TAG_SERVICE_NAME",
    "PPPOE_TAG_AC_NAME",
    "PPPOE_TAG_HOST_UNIQ",
    "PPPOE_TAG_AC_COOKIE",
    "PPPOE_TAG_GENERIC_ERROR",
    "SCTPHeader",
    "SCTPDataChunk",
    "SCTPInitChunk",
    "SCTPInitAckChunk",
    "SCTPSackChunk",
    "SCTPHeartbeatChunk",
    "SCTPHeartbeatAckChunk",
    "SCTPAbortChunk",
    "SCTPShutdownChunk",
    "SCTPShutdownAckChunk",
    "SCTPErrorChunk",
    "SCTPCookieEchoChunk",
    "SCTPCookieAckChunk",
    "SCTPShutdownCompleteChunk",
    "SCTPGenericChunk",
    "IPPROTO_SCTP",
    "SCTP_CHUNK_DATA",
    "SCTP_CHUNK_INIT",
    "SCTP_CHUNK_INIT_ACK",
    "SCTP_CHUNK_SACK",
    "SCTP_CHUNK_HEARTBEAT",
    "SCTP_CHUNK_HEARTBEAT_ACK",
    "SCTP_CHUNK_ABORT",
    "SCTP_CHUNK_SHUTDOWN",
    "SCTP_CHUNK_SHUTDOWN_ACK",
    "SCTP_CHUNK_ERROR",
    "SCTP_CHUNK_COOKIE_ECHO",
    "SCTP_CHUNK_COOKIE_ACK",
    "SCTP_CHUNK_SHUTDOWN_COMPLETE",
    "SCTP_DATA_FLAG_BEGINNING",
    "SCTP_DATA_FLAG_ENDING",
    "SCTP_DATA_FLAG_UNORDERED",
    "SCTP_DATA_FLAG_IMMEDIATE",
    "generate_tcp_stream",
    "TCPStream",
    "TCPStreamConfig",
    "TCPStreamPacket",
    "generate_udp_stream",
    "UDPStream",
    "UDPStreamConfig",
    "UDPStreamPacket",
    "generate_sctp_stream",
    "SCTPStream",
    "SCTPStreamConfig",
    "SCTPStreamPacket",
    "generate_session_mix",
    "merge_streams",
    "CombinedStream",
    "generate_http_stream",
    "generate_http_conversation",
    "HTTPRestConfig",
    "generate_vpn_stream",
    "VPNConfig",
    "AppMessage",
    "render_tcp_session",
    "render_udp_session",
    "PAYLOAD_TYPES",
    "TCPSession",
    "UDPSession",
    "SCTPSession",
    "tcp_handshake",
    "tcp_teardown",
    "sctp_handshake",
    "StreamEncap",
    "EncapSpec",
    "VLANEncap",
    "QinQEncap",
    "MPLSEncap",
    "PPPoEEncap",
    "GREEncap",
    "EtherIPEncap",
    "IPIPEncap",
    "VXLANEncap",
    "GeneveEncap",
    "fragment_ipv4",
    "fragment_ipv6",
    "DNSFlags",
    "DNSMessage",
    "DNSQuestion",
    "DNSResourceRecord",
    "DNSRDataA",
    "DNSRDataAAAA",
    "DNSRDataCNAME",
    "DNSRDataNS",
    "DNSRDataPTR",
    "DNSRDataMX",
    "DNSRDataSOA",
    "DNSRDataTXT",
    "DNSRDataRaw",
    "DNS_TYPE_A",
    "DNS_TYPE_NS",
    "DNS_TYPE_CNAME",
    "DNS_TYPE_SOA",
    "DNS_TYPE_PTR",
    "DNS_TYPE_MX",
    "DNS_TYPE_TXT",
    "DNS_TYPE_AAAA",
    "DNS_CLASS_IN",
    "DNS_RCODE_NOERROR",
    "DNS_RCODE_FORMERR",
    "DNS_RCODE_SERVFAIL",
    "DNS_RCODE_NXDOMAIN",
    "DNS_RCODE_NOTIMP",
    "DNS_RCODE_REFUSED",
    "MDNS_PORT",
    "MDNS_ADDR_IPV4",
    "MDNS_ADDR_IPV6",
    "DHCPMessage",
    "DHCPOptMessageType",
    "DHCPOptSubnetMask",
    "DHCPOptRouter",
    "DHCPOptDNSServer",
    "DHCPOptHostname",
    "DHCPOptDomainName",
    "DHCPOptRequestedIP",
    "DHCPOptLeaseTime",
    "DHCPOptServerID",
    "DHCPOptParamRequestList",
    "DHCPOptVendorClassID",
    "DHCPOptClientID",
    "DHCPOptRaw",
    "DHCP_PORT_SERVER",
    "DHCP_PORT_CLIENT",
    "DHCP_OP_REQUEST",
    "DHCP_OP_REPLY",
    "DHCP_MSG_DISCOVER",
    "DHCP_MSG_OFFER",
    "DHCP_MSG_REQUEST",
    "DHCP_MSG_DECLINE",
    "DHCP_MSG_ACK",
    "DHCP_MSG_NAK",
    "DHCP_MSG_RELEASE",
    "DHCP_MSG_INFORM",
    "DHCP_OPT_SUBNET_MASK",
    "DHCP_OPT_ROUTER",
    "DHCP_OPT_DNS_SERVER",
    "DHCP_OPT_HOSTNAME",
    "DHCP_OPT_DOMAIN_NAME",
    "DHCP_OPT_REQUESTED_IP",
    "DHCP_OPT_LEASE_TIME",
    "DHCP_OPT_MESSAGE_TYPE",
    "DHCP_OPT_SERVER_ID",
    "DHCP_OPT_PARAM_REQUEST_LIST",
    "DHCP_OPT_VENDOR_CLASS_ID",
    "DHCP_OPT_CLIENT_ID",
    "HTTPRequest",
    "HTTPResponse",
    "HTTP_PORT",
    "HTTP_ALT_PORT",
]
