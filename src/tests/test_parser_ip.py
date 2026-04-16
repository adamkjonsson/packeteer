from __future__ import annotations

import socket
import unittest

from packeteer.generate.ip import IPHeader, build_ip_header
from packeteer.generate.ipv6 import IPv6Header, build_ipv6_header
from packeteer.parse.ip import packet_parser

PROTO_TCP = socket.IPPROTO_TCP    # 6
PROTO_UDP = socket.IPPROTO_UDP    # 17
PROTO_ICMP = socket.IPPROTO_ICMP  # 1
PROTO_ICMPv6 = 58


def _ipv4(
    src: str = "10.0.0.1", dst: str = "10.0.0.2",
    protocol: int = PROTO_TCP, payload: bytes = b"",
) -> bytes:
    return build_ip_header(IPHeader(src, dst, protocol), payload)


def _ipv6(
    src: str = "::1", dst: str = "::2",
    next_header: int = PROTO_TCP, payload: bytes = b"",
) -> bytes:
    return build_ipv6_header(IPv6Header(src, dst, next_header), payload)


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

class TestParserIPv4(unittest.TestCase):
    def test_header_size_no_options(self):
        size, _, hdr = packet_parser(_ipv4())
        self.assertEqual(size, 20)

    def test_protocol_tcp(self):
        _, proto, hdr = packet_parser(_ipv4(protocol=PROTO_TCP))
        self.assertEqual(proto, PROTO_TCP)

    def test_protocol_udp(self):
        _, proto, hdr = packet_parser(_ipv4(protocol=PROTO_UDP))
        self.assertEqual(proto, PROTO_UDP)

    def test_protocol_icmp(self):
        _, proto, hdr = packet_parser(_ipv4(protocol=PROTO_ICMP))
        self.assertEqual(proto, PROTO_ICMP)

    def test_extra_payload_ignored(self):
        size, proto, hdr = packet_parser(_ipv4() + b"\xff" * 100)
        self.assertEqual(size, 20)
        self.assertEqual(proto, PROTO_TCP)

    def test_header_size_with_options(self):
        base = _ipv4()
        patched = bytes([0x46]) + base[1:] + b"\x00" * 4
        size, _, hdr = packet_parser(patched)
        self.assertEqual(size, 24)

    def test_header_is_ip_header_instance(self):
        _, _, hdr = packet_parser(_ipv4())
        self.assertIsInstance(hdr, IPHeader)

    def test_header_src(self):
        _, _, hdr = packet_parser(_ipv4(src="192.168.1.1"))
        self.assertEqual(hdr.src, "192.168.1.1")

    def test_header_dst(self):
        _, _, hdr = packet_parser(_ipv4(dst="10.20.30.40"))
        self.assertEqual(hdr.dst, "10.20.30.40")

    def test_header_protocol(self):
        _, _, hdr = packet_parser(_ipv4(protocol=PROTO_UDP))
        self.assertEqual(hdr.protocol, PROTO_UDP)

    def test_header_ttl(self):
        _, _, hdr = packet_parser(_ipv4())
        self.assertEqual(hdr.ttl, 64)  # default in IPHeader

    def test_header_tos(self):
        raw = build_ip_header(IPHeader("1.2.3.4", "5.6.7.8", PROTO_TCP, tos=16), b"")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.tos, 16)

    def test_header_identification(self):
        raw = build_ip_header(IPHeader("1.2.3.4", "5.6.7.8", PROTO_TCP, identification=0xABCD), b"")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.identification, 0xABCD)

    def test_header_flags(self):
        raw = build_ip_header(IPHeader("1.2.3.4", "5.6.7.8", PROTO_TCP, flags=0b010), b"")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.flags, 0b010)

    def test_header_fragment_offset(self):
        raw = build_ip_header(
            IPHeader("1.2.3.4", "5.6.7.8", PROTO_TCP, flags=0, fragment_offset=100), b""
        )
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.fragment_offset, 100)


class TestParserIPv4Failure(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(packet_parser(b""), (0, None, None))

    def test_too_short(self):
        self.assertEqual(packet_parser(_ipv4()[:19]), (0, None, None))

    def test_invalid_version(self):
        bad = bytes([0x00]) + _ipv4()[1:]
        self.assertEqual(packet_parser(bad), (0, None, None))

    def test_ihl_too_small(self):
        bad = bytes([(4 << 4) | 4]) + _ipv4()[1:]
        self.assertEqual(packet_parser(bad), (0, None, None))

    def test_ihl_beyond_data(self):
        bad = bytes([0x46]) + _ipv4()[1:]
        self.assertEqual(packet_parser(bad), (0, None, None))


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------

class TestParserIPv6(unittest.TestCase):
    def test_header_size(self):
        size, _, hdr = packet_parser(_ipv6())
        self.assertEqual(size, 40)

    def test_next_header_tcp(self):
        _, proto, hdr = packet_parser(_ipv6(next_header=PROTO_TCP))
        self.assertEqual(proto, PROTO_TCP)

    def test_next_header_udp(self):
        _, proto, hdr = packet_parser(_ipv6(next_header=PROTO_UDP))
        self.assertEqual(proto, PROTO_UDP)

    def test_next_header_icmpv6(self):
        _, proto, hdr = packet_parser(_ipv6(next_header=PROTO_ICMPv6))
        self.assertEqual(proto, PROTO_ICMPv6)

    def test_extra_payload_ignored(self):
        size, proto, hdr = packet_parser(_ipv6() + b"\xff" * 100)
        self.assertEqual(size, 40)
        self.assertEqual(proto, PROTO_TCP)

    def test_various_addresses(self):
        for src, dst in [
            ("::1", "::2"),
            ("fe80::1", "fe80::2"),
            ("2001:db8::1", "2001:db8::2"),
        ]:
            with self.subTest(src=src, dst=dst):
                size, _, hdr = packet_parser(_ipv6(src=src, dst=dst))
                self.assertEqual(size, 40)

    def test_header_is_ipv6_header_instance(self):
        _, _, hdr = packet_parser(_ipv6())
        self.assertIsInstance(hdr, IPv6Header)

    def test_header_src(self):
        _, _, hdr = packet_parser(_ipv6(src="fe80::1"))
        self.assertEqual(hdr.src, "fe80::1")

    def test_header_dst(self):
        _, _, hdr = packet_parser(_ipv6(dst="2001:db8::2"))
        self.assertEqual(hdr.dst, "2001:db8::2")

    def test_header_next_header(self):
        _, _, hdr = packet_parser(_ipv6(next_header=PROTO_UDP))
        self.assertEqual(hdr.next_header, PROTO_UDP)

    def test_header_hop_limit(self):
        _, _, hdr = packet_parser(_ipv6())
        self.assertEqual(hdr.hop_limit, 64)  # default in IPv6Header

    def test_header_traffic_class(self):
        raw = build_ipv6_header(IPv6Header("::1", "::2", PROTO_TCP, traffic_class=0xAB), b"")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.traffic_class, 0xAB)

    def test_header_flow_label(self):
        raw = build_ipv6_header(IPv6Header("::1", "::2", PROTO_TCP, flow_label=0x12345), b"")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.flow_label, 0x12345)


class TestParserIPv6Failure(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(packet_parser(b""), (0, None, None))

    def test_too_short(self):
        self.assertEqual(packet_parser(_ipv6()[:39]), (0, None, None))


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

class TestParserIPVersionDetection(unittest.TestCase):
    def test_detects_ipv4(self):
        size, _, hdr = packet_parser(_ipv4())
        self.assertEqual(size, 20)

    def test_detects_ipv6(self):
        size, _, hdr = packet_parser(_ipv6())
        self.assertEqual(size, 40)

    def test_rejects_version_5(self):
        bad = bytes([(5 << 4) | 5]) + b"\x00" * 19
        self.assertEqual(packet_parser(bad), (0, None, None))


# ---------------------------------------------------------------------------
# Roundtrip: packet_generator → packet_parser
# ---------------------------------------------------------------------------

class TestParserIPRoundtrip(unittest.TestCase):
    def test_ipv4_roundtrip(self):
        payload = b"hello"
        raw = _ipv4(payload=payload)
        size, proto, hdr = packet_parser(raw)
        self.assertEqual(size, 20)
        self.assertEqual(proto, PROTO_TCP)

    def test_ipv6_roundtrip(self):
        payload = b"hello"
        raw = _ipv6(payload=payload)
        size, proto, hdr = packet_parser(raw)
        self.assertEqual(size, 40)
        self.assertEqual(proto, PROTO_TCP)

    def test_ipv4_parser_consumes_exactly_header(self):
        payload = b"\xde\xad\xbe\xef" * 10
        raw = _ipv4() + payload
        size, _, hdr = packet_parser(raw)
        self.assertEqual(raw[size:], payload)

    def test_ipv6_parser_consumes_exactly_header(self):
        payload = b"\xca\xfe\xba\xbe" * 10
        raw = _ipv6() + payload
        size, _, hdr = packet_parser(raw)
        self.assertEqual(raw[size:], payload)

    def test_ipv4_protocol_field_matches_generator(self):
        for proto in (PROTO_TCP, PROTO_UDP, PROTO_ICMP):
            with self.subTest(proto=proto):
                raw = _ipv4(protocol=proto)
                _, parsed_proto, hdr = packet_parser(raw)
                self.assertEqual(parsed_proto, proto)

    def test_ipv6_next_header_matches_generator(self):
        for nh in (PROTO_TCP, PROTO_UDP, PROTO_ICMPv6):
            with self.subTest(next_header=nh):
                raw = _ipv6(next_header=nh)
                _, parsed_nh, hdr = packet_parser(raw)
                self.assertEqual(parsed_nh, nh)

    def test_ipv4_roundtrip_header_equals_original(self):
        orig = IPHeader("172.16.0.1", "172.16.0.2", PROTO_UDP, ttl=128, tos=8,
                        identification=0x1234, flags=0b010, fragment_offset=0)
        raw = build_ip_header(orig, b"")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.src, orig.src)
        self.assertEqual(hdr.dst, orig.dst)
        self.assertEqual(hdr.protocol, orig.protocol)
        self.assertEqual(hdr.ttl, orig.ttl)
        self.assertEqual(hdr.tos, orig.tos)
        self.assertEqual(hdr.identification, orig.identification)
        self.assertEqual(hdr.flags, orig.flags)
        self.assertEqual(hdr.fragment_offset, orig.fragment_offset)

    def test_ipv6_roundtrip_header_equals_original(self):
        orig = IPv6Header("2001:db8::1", "2001:db8::2", PROTO_TCP,
                          hop_limit=32, traffic_class=0x10, flow_label=0xABCDE)
        raw = build_ipv6_header(orig, b"")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.src, orig.src)
        self.assertEqual(hdr.dst, orig.dst)
        self.assertEqual(hdr.next_header, orig.next_header)
        self.assertEqual(hdr.hop_limit, orig.hop_limit)
        self.assertEqual(hdr.traffic_class, orig.traffic_class)
        self.assertEqual(hdr.flow_label, orig.flow_label)


if __name__ == "__main__":
    unittest.main()
