"""Tests for MPLS label stack support (RFC 3032)."""
from __future__ import annotations

import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.mpls import MPLSLabel, _build_mpls_label, ETHERTYPE_MPLS_UNICAST
from packeteer.parse.mpls import packet_parser as mpls_packet_parser
from packeteer.parse.core import parse_packet
from packeteer.pcap import LINKTYPE_ETHERNET


class TestMPLSLabelBuild(unittest.TestCase):
    """Unit tests for _build_mpls_label."""

    def test_size(self):
        raw = _build_mpls_label(MPLSLabel(label=100), bottom_of_stack=True)
        self.assertEqual(len(raw), 4)

    def test_label_field(self):
        raw = _build_mpls_label(MPLSLabel(label=0x12345), bottom_of_stack=True)
        word, = struct.unpack("!I", raw)
        self.assertEqual((word >> 12) & 0xFFFFF, 0x12345)

    def test_tc_field(self):
        raw = _build_mpls_label(MPLSLabel(label=0, tc=5), bottom_of_stack=False)
        word, = struct.unpack("!I", raw)
        self.assertEqual((word >> 9) & 0x7, 5)

    def test_ttl_field(self):
        raw = _build_mpls_label(MPLSLabel(label=0, ttl=200), bottom_of_stack=True)
        word, = struct.unpack("!I", raw)
        self.assertEqual(word & 0xFF, 200)

    def test_bos_set(self):
        raw = _build_mpls_label(MPLSLabel(label=0), bottom_of_stack=True)
        word, = struct.unpack("!I", raw)
        self.assertEqual((word >> 8) & 0x1, 1)

    def test_bos_clear(self):
        raw = _build_mpls_label(MPLSLabel(label=0), bottom_of_stack=False)
        word, = struct.unpack("!I", raw)
        self.assertEqual((word >> 8) & 0x1, 0)

    def test_invalid_label_raises(self):
        with self.assertRaises(ValueError):
            MPLSLabel(label=0x100000)

    def test_invalid_tc_raises(self):
        with self.assertRaises(ValueError):
            MPLSLabel(label=0, tc=8)


class TestPacketBuilderMPLS(unittest.TestCase):
    """Integration tests for PacketBuilder.mpls()."""

    def test_single_label_size(self):
        # Eth(14) + MPLS(4) + IPv4(20) + UDP(8) = 46
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        self.assertEqual(len(pkt), 14 + 4 + 20 + 8)

    def test_label_stack_size(self):
        # Eth(14) + MPLS(4) + MPLS(4) + IPv4(20) + UDP(8) = 50
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .mpls(label=200)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        self.assertEqual(len(pkt), 14 + 4 + 4 + 20 + 8)

    def test_eth_ethertype_is_mpls(self):
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        ethertype, = struct.unpack("!H", pkt[12:14])
        self.assertEqual(ethertype, ETHERTYPE_MPLS_UNICAST)

    def test_single_label_bos_is_set(self):
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        word, = struct.unpack("!I", pkt[14:18])
        self.assertEqual((word >> 8) & 0x1, 1)  # S=1

    def test_label_stack_bos_bits(self):
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .mpls(label=200)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        word0, = struct.unpack("!I", pkt[14:18])   # outer label
        word1, = struct.unpack("!I", pkt[18:22])   # inner label
        self.assertEqual((word0 >> 8) & 0x1, 0)    # S=0 (more labels follow)
        self.assertEqual((word1 >> 8) & 0x1, 1)    # S=1 (bottom of stack)

    def test_label_values_encoded(self):
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .mpls(label=200)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        word0, = struct.unpack("!I", pkt[14:18])
        word1, = struct.unpack("!I", pkt[18:22])
        self.assertEqual((word0 >> 12) & 0xFFFFF, 100)
        self.assertEqual((word1 >> 12) & 0xFFFFF, 200)

    def test_mpls_ipv6(self):
        # MPLS also works with an IPv6 payload
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=300)
               .ip(src="::1", dst="::2")
               .udp()
               .build())
        # Eth(14) + MPLS(4) + IPv6(40) + UDP(8) = 66
        self.assertEqual(len(pkt), 14 + 4 + 40 + 8)
        word, = struct.unpack("!I", pkt[14:18])
        self.assertEqual((word >> 8) & 0x1, 1)  # S=1


class TestMPLSParser(unittest.TestCase):
    """Unit tests for packeteer.parse.mpls.packet_parser."""

    def _make_label_bytes(self, label: int, tc: int = 0, ttl: int = 64, bos: bool = True) -> bytes:
        s = 1 if bos else 0
        word = (label << 12) | (tc << 9) | (s << 8) | ttl
        return struct.pack("!I", word)

    def test_parser_returns_correct_label(self):
        data = self._make_label_bytes(100, tc=3, ttl=128, bos=True)
        # Append an IPv4 header byte so the parser can peek at the version
        data += b"\x45" + b"\x00" * 19
        size, next_proto, label = mpls_packet_parser(data)
        self.assertEqual(size, 4)
        self.assertEqual(label.label, 100)
        self.assertEqual(label.tc, 3)
        self.assertEqual(label.ttl, 128)

    def test_parser_bos0_next_proto_is_mpls(self):
        data = self._make_label_bytes(100, bos=False)
        data += self._make_label_bytes(200, bos=True) + b"\x45" + b"\x00" * 19
        size, next_proto, label = mpls_packet_parser(data)
        self.assertEqual(next_proto, ETHERTYPE_MPLS_UNICAST)

    def test_parser_bos1_ipv4_next_proto(self):
        from packeteer.generate.ethernet import ETHERTYPE_IPV4
        data = self._make_label_bytes(100, bos=True) + b"\x45" + b"\x00" * 19
        _, next_proto, _ = mpls_packet_parser(data)
        self.assertEqual(next_proto, ETHERTYPE_IPV4)

    def test_parser_bos1_ipv6_next_proto(self):
        from packeteer.generate.ethernet import ETHERTYPE_IPV6
        data = self._make_label_bytes(100, bos=True) + b"\x60" + b"\x00" * 19
        _, next_proto, _ = mpls_packet_parser(data)
        self.assertEqual(next_proto, ETHERTYPE_IPV6)

    def test_parser_too_short(self):
        size, next_proto, label = mpls_packet_parser(b"\x00\x00")
        self.assertEqual(size, 0)
        self.assertIsNone(next_proto)
        self.assertIsNone(label)


class TestParsePacketMPLS(unittest.TestCase):
    """End-to-end parse_packet tests with MPLS layers."""

    def test_parse_single_label(self):
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp(src_port=1234, dst_port=5678)
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(len(parsed.mpls), 1)
        self.assertEqual(parsed.mpls[0].label, 100)
        self.assertIsNotNone(parsed.ip)
        self.assertIsNotNone(parsed.transport)

    def test_parse_label_stack(self):
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=100)
               .mpls(label=200)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(len(parsed.mpls), 2)
        self.assertEqual(parsed.mpls[0].label, 100)
        self.assertEqual(parsed.mpls[1].label, 200)

    def test_parse_no_mpls_gives_empty_list(self):
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(parsed.mpls, [])

    def test_parse_mpls_ip_dst(self):
        pkt = (PacketBuilder()
               .ethernet()
               .mpls(label=42)
               .ip(src="192.168.1.1", dst="192.168.1.2")
               .tcp(dst_port=443)
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(parsed.ip.dst, "192.168.1.2")
        self.assertEqual(parsed.transport.dst_port, 443)


if __name__ == "__main__":
    unittest.main()
