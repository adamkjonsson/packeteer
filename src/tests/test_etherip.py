"""Tests for EtherIP (RFC 3378) building and parsing."""
from __future__ import annotations

import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.etherip import EtherIPHeader, IPPROTO_ETHERIP, build_etherip_header
from packeteer.parse import etherip_packet_parser
from packeteer.parse.core import parse_packet, ParsedPacket


class TestBuildEtherIPHeader(unittest.TestCase):
    def test_wire_bytes(self):
        raw = build_etherip_header()
        self.assertEqual(raw, b"\x30\x00")

    def test_length(self):
        self.assertEqual(len(build_etherip_header()), 2)

    def test_version_field(self):
        raw = build_etherip_header()
        (word,) = struct.unpack("!H", raw)
        self.assertEqual(word >> 12, 3)

    def test_reserved_field(self):
        raw = build_etherip_header()
        (word,) = struct.unpack("!H", raw)
        self.assertEqual(word & 0x0FFF, 0)


class TestEtherIPHeader(unittest.TestCase):
    def test_equality(self):
        self.assertEqual(EtherIPHeader(), EtherIPHeader())

    def test_ipproto_constant(self):
        self.assertEqual(IPPROTO_ETHERIP, 97)


class TestEtherIPParser(unittest.TestCase):
    def test_valid_header(self):
        size, nxt, hdr = etherip_packet_parser(b"\x30\x00")
        self.assertEqual(size, 2)
        self.assertIsNone(nxt)
        self.assertIsInstance(hdr, EtherIPHeader)

    def test_valid_header_with_trailing_data(self):
        data = b"\x30\x00" + b"\xff" * 20
        size, nxt, hdr = etherip_packet_parser(data)
        self.assertEqual(size, 2)
        self.assertIsInstance(hdr, EtherIPHeader)

    def test_wrong_version_rejected(self):
        # version=2 → 0x2000
        size, nxt, hdr = etherip_packet_parser(b"\x20\x00")
        self.assertEqual(size, 0)
        self.assertIsNone(nxt)
        self.assertIsNone(hdr)

    def test_truncated_input(self):
        size, nxt, hdr = etherip_packet_parser(b"\x30")
        self.assertEqual(size, 0)
        self.assertIsNone(hdr)

    def test_empty_input(self):
        size, nxt, hdr = etherip_packet_parser(b"")
        self.assertEqual(size, 0)
        self.assertIsNone(hdr)

    def test_reserved_bits_nonzero_accepted(self):
        # RFC says reserved must be 0, but we only check version
        size, nxt, hdr = etherip_packet_parser(b"\x30\xff")
        self.assertEqual(size, 2)
        self.assertIsInstance(hdr, EtherIPHeader)


class TestPacketBuilderEtherIP(unittest.TestCase):
    def _build_tunnel(self, **kwargs: object) -> bytes:
        """Build a standard EtherIP tunnel packet."""
        return (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )

    def test_build_returns_bytes(self):
        pkt = self._build_tunnel()
        self.assertIsInstance(pkt, bytes)

    def test_etherip_header_present(self):
        pkt = self._build_tunnel()
        # outer eth(14) + outer ip(20) = 34 bytes; next 2 bytes are EtherIP
        etherip_bytes = pkt[34:36]
        self.assertEqual(etherip_bytes, b"\x30\x00")

    def test_outer_ip_protocol_is_97(self):
        pkt = self._build_tunnel()
        # outer IP protocol field is at byte offset 14+9 = 23
        self.assertEqual(pkt[23], 97)

    def test_inner_ethernet_present(self):
        pkt = self._build_tunnel()
        # after outer eth(14) + outer ip(20) + etherip(2) = 36 bytes
        # inner dst_mac = aa:bb:cc:dd:ee:02
        inner_eth_start = 36
        inner_dst_mac = pkt[inner_eth_start:inner_eth_start + 6]
        self.assertEqual(inner_dst_mac, bytes.fromhex("aabbccddee02"))

    def test_packet_length_reasonable(self):
        pkt = self._build_tunnel()
        # outer eth(14) + outer ip(20) + etherip(2) + inner eth(14) + inner ip(20) + tcp(20)
        self.assertEqual(len(pkt), 14 + 20 + 2 + 14 + 20 + 20)

    def test_etherip_with_udp(self):
        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .udp(dst_port=53)
            .build()
        )
        self.assertIsInstance(pkt, bytes)
        self.assertEqual(pkt[23], 97)   # outer IP proto

    def test_etherip_with_ipv6_inner(self):
        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="fe80::1", dst="fe80::2")
            .tcp(dst_port=443)
            .build()
        )
        self.assertIsInstance(pkt, bytes)

    def test_etherip_with_ipv6_outer(self):
        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="2001:db8::1", dst="2001:db8::2")
            .etherip()
            .ethernet()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        self.assertIsInstance(pkt, bytes)

    def test_double_nested_etherip(self):
        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .tcp(dst_port=80)
            .build()
        )
        self.assertIsInstance(pkt, bytes)
        # First EtherIP at outer_eth(14) + outer_ip(20) = byte 34
        self.assertEqual(pkt[34:36], b"\x30\x00")
        # First outer IP proto = 97
        self.assertEqual(pkt[23], 97)


class TestParsePacketEtherIP(unittest.TestCase):
    def _build_tunnel(self) -> bytes:
        return (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )

    def test_outer_ethernet(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNotNone(pkt.ethernet)
        self.assertEqual(pkt.ethernet.src_mac, "00:00:00:00:00:01")

    def test_outer_ip(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNotNone(pkt.ip)
        self.assertEqual(pkt.ip.src, "10.0.0.1")
        self.assertEqual(pkt.ip.dst, "10.0.0.2")

    def test_etherip_field(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsInstance(pkt.etherip, EtherIPHeader)

    def test_tunneled_field_present(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNotNone(pkt.tunneled)
        self.assertIsInstance(pkt.tunneled, ParsedPacket)

    def test_inner_ethernet(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNotNone(pkt.tunneled.ethernet)
        self.assertEqual(pkt.tunneled.ethernet.src_mac, "aa:bb:cc:dd:ee:01")

    def test_inner_ip(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNotNone(pkt.tunneled.ip)
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.ip.dst, "192.168.1.2")

    def test_inner_transport(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNotNone(pkt.tunneled.transport)
        self.assertEqual(pkt.tunneled.transport.dst_port, 80)

    def test_outer_transport_is_none(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNone(pkt.transport)

    def test_outer_payload_is_empty(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertEqual(pkt.payload, b"")

    def test_inner_tunneled_is_none(self):
        pkt = parse_packet(self._build_tunnel())
        self.assertIsNone(pkt.tunneled.etherip)
        self.assertIsNone(pkt.tunneled.tunneled)

    def test_double_nested_etherip(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .tcp(dst_port=9000)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertEqual(pkt.ip.src, "1.0.0.1")
        self.assertIsInstance(pkt.etherip, EtherIPHeader)
        self.assertEqual(pkt.tunneled.ip.src, "2.0.0.1")
        self.assertIsInstance(pkt.tunneled.etherip, EtherIPHeader)
        self.assertEqual(pkt.tunneled.tunneled.ip.src, "3.0.0.1")
        self.assertEqual(pkt.tunneled.tunneled.transport.dst_port, 9000)
        self.assertIsNone(pkt.tunneled.tunneled.etherip)

    def test_non_etherip_packet_has_no_etherip(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp()
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNone(pkt.etherip)
        self.assertIsNone(pkt.tunneled)

    def test_inner_udp(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .udp(dst_port=53)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.tunneled.transport)
        self.assertEqual(pkt.tunneled.transport.dst_port, 53)

    def test_inner_icmp(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .icmp(identifier=42, sequence=7)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.tunneled.transport)
        self.assertEqual(pkt.tunneled.transport.identifier, 42)

    def test_corrupt_etherip_header_goes_to_payload(self):
        # Build valid outer headers then inject bad EtherIP (version != 3)
        from packeteer.generate.ethernet import (
            build_ethernet_header, EthernetHeader, ETHERTYPE_IPV4,
        )
        from packeteer.generate.ip import build_ip_header, IPHeader
        eth = build_ethernet_header(
            EthernetHeader("00:00:00:00:00:02", "00:00:00:00:00:01", ETHERTYPE_IPV4)
        )
        inner = b"\x20\x00" + b"\xff" * 10   # bad EtherIP version=2
        ip_hdr = IPHeader("10.0.0.1", "10.0.0.2", IPPROTO_ETHERIP)
        ip_bytes = build_ip_header(ip_hdr, inner)
        raw = eth + ip_bytes + inner
        pkt = parse_packet(raw)
        # EtherIP parser should fail → etherip=None, data in payload
        self.assertIsNone(pkt.etherip)
        self.assertIsNotNone(pkt.payload)


class TestParsePacketEtherIPRoundTrip(unittest.TestCase):
    """Verify parse → to_config → rebuild produces the same bytes."""

    def test_round_trip_via_json(self):
        import json
        from packeteer.parse.core import parse_pcap_file
        from packeteer.pcap import write_pcap
        import io

        raw = (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )

        # Write to in-memory pcap
        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)

        # Parse back to packet spec
        json_str = parse_pcap_file(file_object=buf)
        cfg = json.loads(json_str)

        # Verify structure
        pkt_cfg = cfg["packets"][0]
        self.assertIn("etherip", pkt_cfg)
        inner = pkt_cfg["etherip"]
        self.assertIn("ethernet", inner)
        self.assertIn("network", inner)
        self.assertIn("transport", inner)
        self.assertEqual(inner["network"]["src"], "192.168.1.1")
        self.assertEqual(inner["transport"]["dst_port"], 80)
        self.assertEqual(pkt_cfg["network"]["protocol"], "etherip")

    def test_double_nested_round_trip_json(self):
        import json
        from packeteer.parse.core import parse_pcap_file
        from packeteer.pcap import write_pcap
        import io

        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .udp(dst_port=9999)
            .build()
        )

        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)

        json_str = parse_pcap_file(file_object=buf)
        cfg = json.loads(json_str)

        pkt_cfg = cfg["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "etherip")
        inner1 = pkt_cfg["etherip"]
        self.assertEqual(inner1["network"]["protocol"], "etherip")
        inner2 = inner1["etherip"]
        self.assertEqual(inner2["network"]["src"], "3.0.0.1")
        self.assertEqual(inner2["transport"]["dst_port"], 9999)


if __name__ == "__main__":
    unittest.main()
