"""Tests for PPPoE support (RFC 2516)."""
from __future__ import annotations

import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.pppoe import (
    PPPoEHeader, PPPoETag,
    ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION,
    PPP_IPV4, PPP_IPV6,
    PPPOE_CODE_SESSION, PPPOE_CODE_PADI, PPPOE_CODE_PADO,
    PPPOE_CODE_PADS, PPPOE_CODE_PADT,
    PPPOE_TAG_SERVICE_NAME, PPPOE_TAG_HOST_UNIQ,
    build_pppoe_header,
)
from packeteer.parse.pppoe import packet_parser as pppoe_packet_parser
from packeteer.parse.core import parse_packet
from packeteer.pcap import LINKTYPE_ETHERNET


# ── build_pppoe_header unit tests ─────────────────────────────────────────────

class TestBuildPPPoEHeader(unittest.TestCase):
    def test_size(self):
        raw = build_pppoe_header(PPPoEHeader(), b"\x00" * 10)
        self.assertEqual(len(raw), 6)

    def test_ver_type_byte(self):
        raw = build_pppoe_header(PPPoEHeader(), b"")
        self.assertEqual(raw[0], 0x11)  # Ver=1, Type=1

    def test_code_session(self):
        raw = build_pppoe_header(PPPoEHeader(code=PPPOE_CODE_SESSION), b"")
        self.assertEqual(raw[1], 0x00)

    def test_code_padi(self):
        raw = build_pppoe_header(PPPoEHeader(code=PPPOE_CODE_PADI), b"")
        self.assertEqual(raw[1], 0x09)

    def test_session_id_encoded(self):
        raw = build_pppoe_header(PPPoEHeader(session_id=0xABCD), b"")
        sid, = struct.unpack("!H", raw[2:4])
        self.assertEqual(sid, 0xABCD)

    def test_length_field(self):
        payload = b"\x00" * 22
        raw = build_pppoe_header(PPPoEHeader(), payload)
        length, = struct.unpack("!H", raw[4:6])
        self.assertEqual(length, 22)


# ── PacketBuilder session tests ───────────────────────────────────────────────

class TestPacketBuilderPPPoESession(unittest.TestCase):
    def _session_pkt(self, **ip_kwargs: object) -> bytes:
        return (PacketBuilder()
                .ethernet()
                .pppoe(session_id=0x1234)
                .ip(**ip_kwargs)
                .tcp(dst_port=80)
                .build())

    def test_session_size_ipv4(self):
        # Eth(14) + PPPoE(6) + PPP(2) + IPv4(20) + TCP(20) = 62
        pkt = self._session_pkt(src="10.0.0.1", dst="10.0.0.2")
        self.assertEqual(len(pkt), 14 + 6 + 2 + 20 + 20)

    def test_session_size_ipv6(self):
        # Eth(14) + PPPoE(6) + PPP(2) + IPv6(40) + TCP(20) = 82
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(session_id=0x0001)
               .ip(src="::1", dst="::2")
               .tcp()
               .build())
        self.assertEqual(len(pkt), 14 + 6 + 2 + 40 + 20)

    def test_eth_ethertype_is_session(self):
        pkt = self._session_pkt(src="10.0.0.1", dst="10.0.0.2")
        ethertype, = struct.unpack("!H", pkt[12:14])
        self.assertEqual(ethertype, ETHERTYPE_PPPOE_SESSION)

    def test_pppoe_ver_type(self):
        pkt = self._session_pkt(src="10.0.0.1", dst="10.0.0.2")
        self.assertEqual(pkt[14], 0x11)

    def test_pppoe_code_is_zero(self):
        pkt = self._session_pkt(src="10.0.0.1", dst="10.0.0.2")
        self.assertEqual(pkt[15], 0x00)

    def test_pppoe_session_id(self):
        pkt = self._session_pkt(src="10.0.0.1", dst="10.0.0.2")
        sid, = struct.unpack("!H", pkt[16:18])
        self.assertEqual(sid, 0x1234)

    def test_pppoe_length_field(self):
        pkt = self._session_pkt(src="10.0.0.1", dst="10.0.0.2")
        # PPPoE length = PPP(2) + IPv4(20) + TCP(20) = 42
        length, = struct.unpack("!H", pkt[18:20])
        self.assertEqual(length, 2 + 20 + 20)

    def test_ppp_protocol_ipv4(self):
        pkt = self._session_pkt(src="10.0.0.1", dst="10.0.0.2")
        ppp_proto, = struct.unpack("!H", pkt[20:22])
        self.assertEqual(ppp_proto, PPP_IPV4)

    def test_ppp_protocol_ipv6(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(session_id=0x0001)
               .ip(src="::1", dst="::2")
               .udp()
               .build())
        ppp_proto, = struct.unpack("!H", pkt[20:22])
        self.assertEqual(ppp_proto, PPP_IPV6)

    def test_tcp_checksum_correct(self):
        # Build the same TCP without PPPoE and verify the TCP header bytes match
        plain = (PacketBuilder()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .tcp(src_port=1234, dst_port=80)
                 .build())
        over_pppoe = (PacketBuilder()
                      .ethernet()
                      .pppoe(session_id=1)
                      .ip(src="10.0.0.1", dst="10.0.0.2")
                      .tcp(src_port=1234, dst_port=80)
                      .build())
        # TCP starts at byte 20 in plain, byte 14+6+2+20=42 in over_pppoe
        self.assertEqual(plain[20:40], over_pppoe[42:62])


# ── PacketBuilder discovery tests ─────────────────────────────────────────────

class TestPacketBuilderPPPoEDiscovery(unittest.TestCase):
    def test_padi_size_no_tags(self):
        # Eth(14) + PPPoE(6) = 20
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(code=PPPOE_CODE_PADI)
               .build())
        self.assertEqual(len(pkt), 14 + 6)

    def test_padi_size_with_service_name_tag(self):
        # Eth(14) + PPPoE(6) + tag_hdr(4) + tag_data(0) = 24
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(
                   code=PPPOE_CODE_PADI,
                   tags=[PPPoETag(PPPOE_TAG_SERVICE_NAME, b"")],
               )
               .build())
        self.assertEqual(len(pkt), 14 + 6 + 4)

    def test_padi_size_with_host_uniq_tag(self):
        # Eth(14) + PPPoE(6) + tag_hdr(4) + tag_data(4) = 28
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(
                   code=PPPOE_CODE_PADI,
                   tags=[PPPoETag(PPPOE_TAG_HOST_UNIQ, b"\xde\xad\xbe\xef")],
               )
               .build())
        self.assertEqual(len(pkt), 14 + 6 + 4 + 4)

    def test_discovery_eth_ethertype(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(code=PPPOE_CODE_PADI)
               .build())
        ethertype, = struct.unpack("!H", pkt[12:14])
        self.assertEqual(ethertype, ETHERTYPE_PPPOE_DISCOVERY)

    def test_discovery_code_in_header(self):
        for code in (PPPOE_CODE_PADI, PPPOE_CODE_PADO, PPPOE_CODE_PADS, PPPOE_CODE_PADT):
            with self.subTest(code=hex(code)):
                pkt = PacketBuilder().ethernet().pppoe(code=code).build()
                self.assertEqual(pkt[15], code)

    def test_tag_tlv_encoding(self):
        tag_data = b"\x01\x02\x03\x04"
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(
                   code=PPPOE_CODE_PADI,
                   tags=[PPPoETag(PPPOE_TAG_HOST_UNIQ, tag_data)],
               )
               .build())
        # TLV starts at byte 20 (after Eth + PPPoE header)
        tag_type, tag_len = struct.unpack("!HH", pkt[20:24])
        self.assertEqual(tag_type, PPPOE_TAG_HOST_UNIQ)
        self.assertEqual(tag_len, 4)
        self.assertEqual(pkt[24:28], tag_data)

    def test_pppoe_length_covers_tags(self):
        tag_data = b"\xAA\xBB"
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(
                   code=PPPOE_CODE_PADI,
                   tags=[PPPoETag(PPPOE_TAG_HOST_UNIQ, tag_data)],
               )
               .build())
        length, = struct.unpack("!H", pkt[18:20])
        # tag header (4) + tag data (2) = 6
        self.assertEqual(length, 4 + 2)

    def test_discovery_requires_ethernet(self):
        with self.assertRaises(ValueError):
            PacketBuilder().pppoe(code=PPPOE_CODE_PADI).build()

    def test_multi_tag(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(
                   code=PPPOE_CODE_PADI,
                   tags=[
                       PPPoETag(PPPOE_TAG_SERVICE_NAME, b""),
                       PPPoETag(PPPOE_TAG_HOST_UNIQ, b"\x00\x01\x02\x03"),
                   ],
               )
               .build())
        # Eth(14) + PPPoE(6) + svc-name TLV(4+0) + host-uniq TLV(4+4) = 32
        self.assertEqual(len(pkt), 14 + 6 + 4 + 4 + 4)


# ── PPPoE parser unit tests ───────────────────────────────────────────────────

class TestPPPoEParser(unittest.TestCase):
    def _make_session(self, session_id: int = 0x1234, ppp_proto: int = PPP_IPV4) -> bytes:
        header = struct.pack("!BBHH", 0x11, 0x00, session_id, 22)
        ppp = struct.pack("!H", ppp_proto)
        ip_stub = b"\x45" + b"\x00" * 19   # minimal IPv4 version nibble
        return header + ppp + ip_stub

    def _make_discovery(self, code: int = PPPOE_CODE_PADI, tags: bytes = b"") -> bytes:
        header = struct.pack("!BBHH", 0x11, code, 0x0000, len(tags))
        return header + tags

    def test_session_header_size(self):
        size, _, _ = pppoe_packet_parser(self._make_session())
        self.assertEqual(size, 8)

    def test_session_next_proto_ipv4(self):
        from packeteer.generate.ethernet import ETHERTYPE_IPV4
        _, next_proto, _ = pppoe_packet_parser(self._make_session(ppp_proto=PPP_IPV4))
        self.assertEqual(next_proto, ETHERTYPE_IPV4)

    def test_session_next_proto_ipv6(self):
        from packeteer.generate.ethernet import ETHERTYPE_IPV6
        header = struct.pack("!BBHH", 0x11, 0x00, 0, 42)
        ppp = struct.pack("!H", PPP_IPV6)
        ipv6_stub = b"\x60" + b"\x00" * 19
        _, next_proto, _ = pppoe_packet_parser(header + ppp + ipv6_stub)
        self.assertEqual(next_proto, ETHERTYPE_IPV6)

    def test_session_fields(self):
        _, _, hdr = pppoe_packet_parser(self._make_session(session_id=0xBEEF))
        self.assertEqual(hdr.code, 0x00)
        self.assertEqual(hdr.session_id, 0xBEEF)

    def test_discovery_header_size_no_tags(self):
        size, _, _ = pppoe_packet_parser(self._make_discovery())
        self.assertEqual(size, 6)

    def test_discovery_next_proto_is_none(self):
        _, next_proto, _ = pppoe_packet_parser(self._make_discovery())
        self.assertIsNone(next_proto)

    def test_discovery_tag_decoded(self):
        tag = struct.pack("!HH", PPPOE_TAG_HOST_UNIQ, 4) + b"\x01\x02\x03\x04"
        _, _, hdr = pppoe_packet_parser(self._make_discovery(tags=tag))
        self.assertEqual(len(hdr.tags), 1)
        self.assertEqual(hdr.tags[0].type, PPPOE_TAG_HOST_UNIQ)
        self.assertEqual(hdr.tags[0].data, b"\x01\x02\x03\x04")

    def test_too_short_returns_failure(self):
        size, next_proto, hdr = pppoe_packet_parser(b"\x11\x00")
        self.assertEqual(size, 0)
        self.assertIsNone(next_proto)
        self.assertIsNone(hdr)

    def test_session_too_short_for_ppp(self):
        # 6-byte PPPoE header only, no PPP field
        data = struct.pack("!BBHH", 0x11, 0x00, 0, 2)
        size, _, _ = pppoe_packet_parser(data)
        self.assertEqual(size, 0)


# ── parse_packet end-to-end tests ─────────────────────────────────────────────

class TestParsePacketPPPoE(unittest.TestCase):
    def test_session_pppoe_field_set(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(session_id=0x0042)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp(dst_port=53)
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNotNone(parsed.pppoe)
        self.assertEqual(parsed.pppoe.session_id, 0x0042)
        self.assertEqual(parsed.pppoe.code, 0x00)

    def test_session_ip_and_transport_parsed(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(session_id=1)
               .ip(src="192.168.1.1", dst="192.168.1.2")
               .tcp(dst_port=443)
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(parsed.ip.dst, "192.168.1.2")
        self.assertEqual(parsed.transport.dst_port, 443)

    def test_discovery_pppoe_field_set(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(
                   code=PPPOE_CODE_PADI,
                   tags=[PPPoETag(PPPOE_TAG_SERVICE_NAME, b"")],
               )
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNotNone(parsed.pppoe)
        self.assertEqual(parsed.pppoe.code, PPPOE_CODE_PADI)

    def test_discovery_no_ip(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(code=PPPOE_CODE_PADI)
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNone(parsed.ip)
        self.assertIsNone(parsed.transport)

    def test_discovery_tags_decoded(self):
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(
                   code=PPPOE_CODE_PADI,
                   tags=[PPPoETag(PPPOE_TAG_HOST_UNIQ, b"\xca\xfe")],
               )
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(len(parsed.pppoe.tags), 1)
        self.assertEqual(parsed.pppoe.tags[0].data, b"\xca\xfe")

    def test_no_pppoe_gives_none(self):
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp()
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNone(parsed.pppoe)


if __name__ == "__main__":
    unittest.main()
