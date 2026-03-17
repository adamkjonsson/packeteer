import os
import socket
from enum import Enum

from .ethernet import EthernetHeader, ETHERTYPE_IPV4, ETHERTYPE_IPV6, build_ethernet_header
from .ip import IPHeader, build_ip_header
from .ipv6 import IPv6Header, build_ipv6_header
from .tcp import TCPHeader, build_tcp_header
from .udp import UDPHeader, build_udp_header
from .icmp import ICMPHeader, build_icmp_header
from .icmpv6 import ICMPv6Header, build_icmpv6_header


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"       # ICMPv4, requires IPv4 addresses
    ICMPv6 = "ICMPv6"   # ICMPv6, requires IPv6 addresses


def _detect_ip_version(addr: str) -> int:
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return 6
    except OSError:
        socket.inet_aton(addr)  # raises OSError if invalid IPv4
        return 4


class PacketBuilder:
    """Builds complete raw network packets (Ethernet + IP + transport + payload)."""

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: Protocol,
        payload_size: int = 0,
        *,
        src_mac: str = "00:00:00:00:00:01",
        dst_mac: str = "00:00:00:00:00:02",
        src_port: int = 12345,
        dst_port: int = 80,
        ttl: int = 64,
        payload: bytes | None = None,
        include_ethernet: bool = True,
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.payload_size = payload_size
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_port = src_port
        self.dst_port = dst_port
        self.ttl = ttl
        self.include_ethernet = include_ethernet
        self._explicit_payload = payload
        self._payload: bytes | None = None

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = (
                self._explicit_payload
                if self._explicit_payload is not None
                else os.urandom(self.payload_size)
            )
        return self._payload

    def build(self) -> bytes:
        """Assemble and return the complete packet bytes."""
        data = self.payload
        ip_version = _detect_ip_version(self.src_ip)

        # Build transport layer
        if self.protocol == Protocol.TCP:
            transport = build_tcp_header(
                TCPHeader(self.src_port, self.dst_port),
                data, self.src_ip, self.dst_ip, ip_version,
            )
        elif self.protocol == Protocol.UDP:
            transport = build_udp_header(
                UDPHeader(self.src_port, self.dst_port),
                data, self.src_ip, self.dst_ip, ip_version,
            )
        elif self.protocol == Protocol.ICMP:
            transport = build_icmp_header(ICMPHeader(), data)
        elif self.protocol == Protocol.ICMPv6:
            transport = build_icmpv6_header(ICMPv6Header(), data, self.src_ip, self.dst_ip)
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

        ip_payload = transport + data

        # Build network layer
        if ip_version == 6:
            next_header = {
                Protocol.TCP: 6,
                Protocol.UDP: 17,
                Protocol.ICMPv6: 58,
            }[self.protocol]
            network = build_ipv6_header(
                IPv6Header(self.src_ip, self.dst_ip, next_header, hop_limit=self.ttl),
                ip_payload,
            )
            ethertype = ETHERTYPE_IPV6
        else:
            import socket as _socket
            proto_num = {
                Protocol.TCP: _socket.IPPROTO_TCP,
                Protocol.UDP: _socket.IPPROTO_UDP,
                Protocol.ICMP: _socket.IPPROTO_ICMP,
            }[self.protocol]
            network = build_ip_header(
                IPHeader(self.src_ip, self.dst_ip, proto_num, ttl=self.ttl),
                ip_payload,
            )
            ethertype = ETHERTYPE_IPV4

        packet = network + ip_payload

        if self.include_ethernet:
            eth = build_ethernet_header(
                EthernetHeader(self.dst_mac, self.src_mac, ethertype)
            )
            packet = eth + packet

        return packet
