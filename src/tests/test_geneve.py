"""Tests for GENEVE (RFC 8926) building and parsing."""
from __future__ import annotations

import io
import json
import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.geneve import (
    GENEVE_PORT,
    GENEVE_PROTO_IPV4,
    GENEVE_PROTO_TEB,
    GeneveHeader,
    GeneveOption,
    _build_geneve_header,
)
from packeteer.generate.udp import UDPHeader
from packeteer.parse import geneve_packet_parser
from packeteer.parse.core import ParsedPacket, parse_packet, parse_pcap_file
from packeteer.pcap import write_pcap


class TestBuildGeneveHeader(unittest.TestCase):
    def test_base_length_no_options(self):
        raw = _build_geneve_header(GeneveHeader(vni=1, protocol_type=GENEVE_PROTO_TEB))
        self.assertEqual(len(raw), 8)

    def test_version_and_optlen_no_options(self):
        raw = _build_geneve_header(GeneveHeader(vni=1))
        self.assertEqual(raw[0], 0)   # ver=0, opt_len=0

    def test_protocol_type_and_vni(self):
        raw = _build_geneve_header(GeneveHeader(vni=0xABCDEF, protocol_type=GENEVE_PROTO_TEB))
        self.assertEqual(struct.unpack_from("!H", raw, 2)[0], GENEVE_PROTO_TEB)
        self.assertEqual(struct.unpack_from("!I", raw, 4)[0] >> 8, 0xABCDEF)

    def test_oam_flag(self):
        raw = _build_geneve_header(GeneveHeader(vni=1, oam=True))
        self.assertEqual(raw[1] & 0x80, 0x80)

    def test_option_opt_len_and_critical_flag(self):
        opt = GeneveOption(option_class=0x0103, type=2, critical=True, data=b"\x00\x01\x02\x03")
        raw = _build_geneve_header(GeneveHeader(vni=1, options=[opt]))
        # opt_len in 4-byte units: 4-byte opt header + 4-byte data = 8 bytes = 2
        self.assertEqual(raw[0] & 0x3F, 2)
        self.assertEqual(len(raw), 8 + 8)
        # C flag set in base header because a critical option is present
        self.assertEqual(raw[1] & 0x40, 0x40)

    def test_option_data_not_multiple_of_4_raises(self):
        with self.assertRaises(ValueError):
            _build_geneve_header(GeneveHeader(options=[GeneveOption(1, 1, data=b"\x00")]))


class TestGeneveParser(unittest.TestCase):
    def test_roundtrip_header(self):
        opt = GeneveOption(option_class=0x0103, type=5, critical=True, data=b"\xaa\xbb\xcc\xdd")
        raw = _build_geneve_header(
            GeneveHeader(vni=1234, protocol_type=GENEVE_PROTO_TEB, options=[opt])
        )
        size, proto, hdr = geneve_packet_parser(raw)
        self.assertEqual(size, len(raw))
        self.assertEqual(proto, GENEVE_PROTO_TEB)
        self.assertEqual(hdr.vni, 1234)
        self.assertEqual(len(hdr.options), 1)
        o = hdr.options[0]
        self.assertEqual(
            (o.option_class, o.type, o.critical, o.data),
            (0x0103, 5, True, b"\xaa\xbb\xcc\xdd"),
        )

    def test_truncated_base(self):
        self.assertEqual(geneve_packet_parser(b"\x00" * 7), (0, None, None))

    def test_truncated_options(self):
        # opt_len says 1 word (4 bytes) of options but none present
        raw = struct.pack(">BBHI", 0x01, 0, GENEVE_PROTO_TEB, 0)
        self.assertEqual(geneve_packet_parser(raw), (0, None, None))


def _build_tunnel(**kw: object) -> bytes:
    vni = kw.get("vni", 5000)
    return (PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .geneve(vni=vni)
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )


class TestPacketBuilderGeneve(unittest.TestCase):
    def test_outer_udp_default_port(self):
        # .udp() with no port → .geneve() rewrites to 6081
        self.assertEqual(struct.unpack_from("!H", _build_tunnel(), 36)[0], GENEVE_PORT)

    def test_explicit_non_default_port_preserved(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
            .udp(dst_port=7777).geneve(vni=1)
            .ethernet().ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        self.assertEqual(struct.unpack_from("!H", pkt, 36)[0], 7777)

    def test_protocol_type_teb(self):
        pkt = _build_tunnel()
        # GENEVE base at eth(14)+ip(20)+udp(8)=42; protocol type at +2 = 44
        self.assertEqual(struct.unpack_from("!H", pkt, 44)[0], GENEVE_PROTO_TEB)

    def test_protocol_type_ipv4_for_ip_inner(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
            .udp().geneve(vni=1).ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        self.assertEqual(struct.unpack_from("!H", pkt, 44)[0], GENEVE_PROTO_IPV4)


class TestParsePacketGeneve(unittest.TestCase):
    def test_outer_transport_is_udp(self):
        pkt = parse_packet(_build_tunnel())
        self.assertIsInstance(pkt.transport, UDPHeader)
        self.assertEqual(pkt.transport.dst_port, GENEVE_PORT)

    def test_geneve_field_and_inner(self):
        pkt = parse_packet(_build_tunnel(vni=4321))
        self.assertIsInstance(pkt.geneve, GeneveHeader)
        self.assertEqual(pkt.geneve.vni, 4321)
        self.assertIsInstance(pkt.tunneled, ParsedPacket)
        self.assertEqual(pkt.tunneled.ethernet.src_mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(pkt.tunneled.transport.dst_port, 80)

    def test_ip_inner(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
            .udp().geneve(vni=9).ip(src="192.168.1.1", dst="192.168.1.2").udp(dst_port=53).build())
        pkt = parse_packet(raw)
        self.assertEqual(pkt.geneve.protocol_type, GENEVE_PROTO_IPV4)
        self.assertIsNone(pkt.tunneled.ethernet)
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.transport.dst_port, 53)

    def test_non_geneve_udp_unaffected(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .udp(dst_port=1234).payload(size=10).build())
        pkt = parse_packet(raw)
        self.assertIsNone(pkt.geneve)
        self.assertIsNone(pkt.tunneled)


class TestGeneveRoundTrip(unittest.TestCase):
    def _to_config(self, raw: bytes) -> dict:
        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)
        return json.loads(parse_pcap_file(file_object=buf))

    def test_config_structure_and_options(self):
        opt = GeneveOption(option_class=0x0103, type=2, critical=True, data=b"\x01\x02\x03\x04")
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
            .udp().geneve(vni=5000, options=[opt])
            .ethernet().ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        pkt_cfg = self._to_config(raw)["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "udp")
        self.assertEqual(pkt_cfg["transport"]["dst_port"], GENEVE_PORT)
        g = pkt_cfg["geneve"]
        self.assertEqual(g["vni"], 5000)
        self.assertEqual(g["options"][0]["class"], 0x0103)
        self.assertTrue(g["options"][0]["critical"])
        self.assertEqual(g["options"][0]["data"], "01020304")
        self.assertEqual(g["network"]["src"], "192.168.1.1")

    def test_rebuild_from_config(self):
        from packeteer import __main__ as cli

        opt = GeneveOption(option_class=0x0103, type=2, critical=True, data=b"\x01\x02\x03\x04")
        raw = (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .udp().geneve(vni=5000, options=[opt])
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        cfg = self._to_config(raw)
        b, _ = cli._apply_spec_to_builder(PacketBuilder(), cfg["packets"][0], 1)
        self.assertEqual(b.build(), raw)


if __name__ == "__main__":
    unittest.main()
