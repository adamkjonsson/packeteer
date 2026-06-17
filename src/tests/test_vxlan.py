"""Tests for VXLAN (RFC 7348) building and parsing."""
from __future__ import annotations

import io
import json
import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.udp import UDPHeader
from packeteer.generate.vxlan import (
    VXLAN_FLAG_VALID_VNI,
    VXLAN_PORT,
    VXLANHeader,
    _build_vxlan_header,
)
from packeteer.parse import vxlan_packet_parser
from packeteer.parse.core import ParsedPacket, parse_packet, parse_pcap_file
from packeteer.pcap import write_pcap


class TestBuildVXLANHeader(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(_build_vxlan_header(VXLANHeader(vni=1))), 8)

    def test_flag_byte(self):
        raw = _build_vxlan_header(VXLANHeader(vni=1))
        self.assertEqual(raw[0], 0x08)

    def test_reserved_bytes_zero(self):
        raw = _build_vxlan_header(VXLANHeader(vni=1))
        self.assertEqual(raw[1:4], b"\x00\x00\x00")

    def test_vni_placement(self):
        raw = _build_vxlan_header(VXLANHeader(vni=0xABCDEF))
        word = struct.unpack("!I", raw[4:8])[0]
        self.assertEqual(word >> 8, 0xABCDEF)
        self.assertEqual(word & 0xFF, 0)   # low byte reserved

    def test_custom_flags(self):
        raw = _build_vxlan_header(VXLANHeader(vni=1, flags=0x88))
        self.assertEqual(raw[0], 0x88)

    def test_vni_zero(self):
        raw = _build_vxlan_header(VXLANHeader())
        self.assertEqual(raw, b"\x08\x00\x00\x00\x00\x00\x00\x00")


class TestVXLANHeaderDataclass(unittest.TestCase):
    def test_defaults(self):
        h = VXLANHeader()
        self.assertEqual(h.vni, 0)
        self.assertEqual(h.flags, VXLAN_FLAG_VALID_VNI)

    def test_port_constant(self):
        self.assertEqual(VXLAN_PORT, 4789)


class TestVXLANParser(unittest.TestCase):
    def test_valid_header(self):
        data = _build_vxlan_header(VXLANHeader(vni=5000))
        size, nxt, hdr = vxlan_packet_parser(data)
        self.assertEqual(size, 8)
        self.assertIsNone(nxt)
        self.assertIsInstance(hdr, VXLANHeader)
        self.assertEqual(hdr.vni, 5000)
        self.assertEqual(hdr.flags, 0x08)

    def test_trailing_data_ignored(self):
        data = _build_vxlan_header(VXLANHeader(vni=7)) + b"\xff" * 20
        size, _, hdr = vxlan_packet_parser(data)
        self.assertEqual(size, 8)
        self.assertEqual(hdr.vni, 7)

    def test_truncated(self):
        size, nxt, hdr = vxlan_packet_parser(b"\x08\x00\x00")
        self.assertEqual(size, 0)
        self.assertIsNone(hdr)

    def test_empty(self):
        size, _, hdr = vxlan_packet_parser(b"")
        self.assertEqual(size, 0)
        self.assertIsNone(hdr)


def _build_tunnel(**kw: object) -> bytes:
    vni = kw.get("vni", 5000)
    return (PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp(dst_port=VXLAN_PORT)
        .vxlan(vni=vni)
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )


class TestPacketBuilderVXLAN(unittest.TestCase):
    def test_returns_bytes(self):
        self.assertIsInstance(_build_tunnel(), bytes)

    def test_outer_ip_protocol_udp(self):
        # outer eth(14) + outer ip proto at +9 = 23
        self.assertEqual(_build_tunnel()[23], 17)

    def test_outer_udp_dst_port(self):
        pkt = _build_tunnel()
        # outer eth(14) + ip(20) = 34; UDP dst port at +2 = 36
        self.assertEqual(struct.unpack_from("!H", pkt, 36)[0], VXLAN_PORT)

    def test_vxlan_header_offset(self):
        pkt = _build_tunnel()
        # eth(14) + ip(20) + udp(8) = 42
        self.assertEqual(pkt[42], 0x08)
        self.assertEqual(struct.unpack_from("!I", pkt, 46)[0] >> 8, 5000)

    def test_inner_ethernet_present(self):
        pkt = _build_tunnel()
        # VXLAN header at 42, 8 bytes → inner Ethernet at 50
        inner_dst_mac = pkt[50:56]
        self.assertEqual(inner_dst_mac, bytes.fromhex("aabbccddee02"))

    def test_total_length(self):
        pkt = _build_tunnel()
        # eth14 + ip20 + udp8 + vxlan8 + inner eth14 + inner ip20 + tcp20
        self.assertEqual(len(pkt), 14 + 20 + 8 + 8 + 14 + 20 + 20)

    def test_udp_default_port_rewritten_to_vxlan(self):
        # .udp() with no port specified → .vxlan() rewrites it to 4789.
        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .udp()
            .vxlan(vni=7)
            .ethernet()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build())
        self.assertEqual(struct.unpack_from("!H", pkt, 36)[0], VXLAN_PORT)
        # Round-trips as VXLAN.
        p = parse_packet(pkt)
        self.assertIsInstance(p.vxlan, VXLANHeader)
        self.assertEqual(p.vxlan.vni, 7)

    def test_explicit_non_default_port_preserved(self):
        # An explicitly chosen (non-default) port is left untouched.
        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .udp(dst_port=8472)
            .vxlan(vni=7)
            .ethernet()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build())
        self.assertEqual(struct.unpack_from("!H", pkt, 36)[0], 8472)


class TestParsePacketVXLAN(unittest.TestCase):
    def test_outer_ip(self):
        pkt = parse_packet(_build_tunnel())
        self.assertEqual(pkt.ip.src, "10.0.0.1")

    def test_outer_transport_is_udp(self):
        pkt = parse_packet(_build_tunnel())
        self.assertIsInstance(pkt.transport, UDPHeader)
        self.assertEqual(pkt.transport.dst_port, VXLAN_PORT)

    def test_vxlan_field(self):
        pkt = parse_packet(_build_tunnel(vni=1234))
        self.assertIsInstance(pkt.vxlan, VXLANHeader)
        self.assertEqual(pkt.vxlan.vni, 1234)

    def test_tunneled_inner(self):
        pkt = parse_packet(_build_tunnel())
        self.assertIsInstance(pkt.tunneled, ParsedPacket)
        self.assertEqual(pkt.tunneled.ethernet.src_mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.transport.dst_port, 80)

    def test_outer_payload_empty(self):
        pkt = parse_packet(_build_tunnel())
        self.assertEqual(pkt.payload, b"")

    def test_non_vxlan_udp_unaffected(self):
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp(dst_port=1234).payload(size=10).build())
        pkt = parse_packet(raw)
        self.assertIsNone(pkt.vxlan)
        self.assertIsNone(pkt.tunneled)
        self.assertIsInstance(pkt.transport, UDPHeader)

    def test_inner_udp(self):
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp(dst_port=VXLAN_PORT).vxlan(vni=9)
               .ethernet()
               .ip(src="192.168.1.1", dst="192.168.1.2")
               .udp(dst_port=53).build())
        pkt = parse_packet(raw)
        self.assertEqual(pkt.tunneled.transport.dst_port, 53)


class TestVXLANRoundTrip(unittest.TestCase):
    """parse → to_config → rebuild produces an equivalent packet."""

    def _to_config(self, raw: bytes) -> dict:
        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)
        return json.loads(parse_pcap_file(file_object=buf))

    def test_config_structure(self):
        cfg = self._to_config(_build_tunnel(vni=5000))
        pkt_cfg = cfg["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "udp")
        self.assertEqual(pkt_cfg["transport"]["dst_port"], VXLAN_PORT)
        self.assertIn("vxlan", pkt_cfg)
        inner = pkt_cfg["vxlan"]
        self.assertEqual(inner["vni"], 5000)
        self.assertIn("ethernet", inner)
        self.assertEqual(inner["network"]["src"], "192.168.1.1")
        self.assertEqual(inner["transport"]["dst_port"], 80)

    def test_rebuild_from_config(self):
        from packeteer import __main__ as cli

        raw = _build_tunnel(vni=5000)
        cfg = self._to_config(raw)
        # Rebuild the single packet via the CLI builder and compare bytes.
        b, _ = cli._apply_spec_to_builder(PacketBuilder(), cfg["packets"][0], 1)
        self.assertEqual(b.build(), raw)


if __name__ == "__main__":
    unittest.main()
