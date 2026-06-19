"""Tests for GTP-U (GTPv1-U, 3GPP TS 29.281) building and parsing."""
from __future__ import annotations

import io
import json
import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.gtpu import (
    GTPU_MSG_END_MARKER,
    GTPU_MSG_G_PDU,
    GTPU_PORT,
    GTPUExtensionHeader,
    GTPUHeader,
    _build_gtpu_header,
)
from packeteer.generate.udp import UDPHeader
from packeteer.parse import gtpu_packet_parser
from packeteer.parse.core import ParsedPacket, parse_packet, parse_pcap_file
from packeteer.pcap import write_pcap


class TestBuildGTPUHeader(unittest.TestCase):
    def test_base_length_and_flags(self):
        raw = _build_gtpu_header(GTPUHeader(teid=0x1234), b"abcd")
        self.assertEqual(len(raw), 8)
        self.assertEqual(raw[0], 0x30)            # version 1, PT 1, no flags
        self.assertEqual(raw[1], GTPU_MSG_G_PDU)  # message type 255
        self.assertEqual(struct.unpack_from("!H", raw, 2)[0], 4)   # length = len(payload)
        self.assertEqual(struct.unpack_from("!I", raw, 4)[0], 0x1234)

    def test_sequence_sets_s_flag_and_optional_block(self):
        raw = _build_gtpu_header(GTPUHeader(teid=1, sequence=0xBEEF), b"")
        self.assertEqual(raw[0] & 0x02, 0x02)     # S flag
        self.assertEqual(len(raw), 12)            # base + 4-byte optional block
        self.assertEqual(struct.unpack_from("!H", raw, 8)[0], 0xBEEF)
        self.assertEqual(struct.unpack_from("!H", raw, 2)[0], 4)   # length covers optional block

    def test_n_pdu_sets_pn_flag(self):
        raw = _build_gtpu_header(GTPUHeader(teid=1, n_pdu=0x42), b"")
        self.assertEqual(raw[0] & 0x01, 0x01)
        self.assertEqual(raw[10], 0x42)

    def test_extension_header_sets_e_flag_and_chain(self):
        eh = GTPUExtensionHeader(header_type=0x85, content=b"\x01\x00\x00\x00\x00\x00")
        raw = _build_gtpu_header(GTPUHeader(teid=1, extension_headers=[eh]), b"")
        self.assertEqual(raw[0] & 0x04, 0x04)        # E flag
        self.assertEqual(raw[11], 0x85)              # next-ext-type in optional block
        # extension header at offset 12: length units, content, next-type 0
        self.assertEqual(raw[12], 2)                 # 8 octets / 4
        self.assertEqual(raw[-1], 0)                 # end of chain

    def test_extension_header_bad_alignment_raises(self):
        with self.assertRaises(ValueError):
            _build_gtpu_header(
                GTPUHeader(extension_headers=[GTPUExtensionHeader(0x85, b"\x00")]), b"",
            )


class TestGTPUParser(unittest.TestCase):
    def test_roundtrip_with_seq_and_ext(self):
        eh = GTPUExtensionHeader(header_type=0x85, content=b"\xaa\xbb\xcc\xdd\xee\xff")
        raw = _build_gtpu_header(
            GTPUHeader(teid=0x99, sequence=5, extension_headers=[eh]), b"",
        )
        size, msg, hdr = gtpu_packet_parser(raw)
        self.assertEqual(size, len(raw))
        self.assertEqual(msg, GTPU_MSG_G_PDU)
        self.assertEqual(hdr.teid, 0x99)
        self.assertEqual(hdr.sequence, 5)
        self.assertEqual(len(hdr.extension_headers), 1)
        self.assertEqual(hdr.extension_headers[0].header_type, 0x85)
        self.assertEqual(hdr.extension_headers[0].content, b"\xaa\xbb\xcc\xdd\xee\xff")

    def test_truncated(self):
        self.assertEqual(gtpu_packet_parser(b"\x30\xff\x00"), (0, None, None))

    def test_wrong_version_rejected(self):
        # version 0 in the top 3 bits
        self.assertEqual(gtpu_packet_parser(b"\x00" * 8), (0, None, None))


def _build_tunnel(**kw: object) -> bytes:
    teid = kw.get("teid", 0x1234)
    return (PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .gtpu(teid=teid)
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )


class TestPacketBuilderGTPU(unittest.TestCase):
    def test_outer_udp_default_port(self):
        self.assertEqual(struct.unpack_from("!H", _build_tunnel(), 36)[0], GTPU_PORT)

    def test_explicit_non_default_port_preserved(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
            .udp(dst_port=3000).gtpu(teid=1)
            .ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        self.assertEqual(struct.unpack_from("!H", pkt, 36)[0], 3000)

    def test_inner_ip_directly_no_ethernet(self):
        pkt = _build_tunnel()
        # GTP-U base at eth(14)+ip(20)+udp(8)=42, 8 bytes → inner IP at 50
        self.assertEqual(pkt[50] >> 4, 4)   # IPv4 version nibble


class TestParsePacketGTPU(unittest.TestCase):
    def test_outer_transport_is_udp(self):
        pkt = parse_packet(_build_tunnel())
        self.assertIsInstance(pkt.transport, UDPHeader)
        self.assertEqual(pkt.transport.dst_port, GTPU_PORT)

    def test_gtpu_field_and_inner_ip(self):
        pkt = parse_packet(_build_tunnel(teid=0xABCD))
        self.assertIsInstance(pkt.gtpu, GTPUHeader)
        self.assertEqual(pkt.gtpu.teid, 0xABCD)
        self.assertIsInstance(pkt.tunneled, ParsedPacket)
        self.assertIsNone(pkt.tunneled.ethernet)   # GTP-U carries IP directly
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.transport.dst_port, 80)

    def test_non_gtpu_udp_unaffected(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .udp(dst_port=1234).payload(size=10).build())
        pkt = parse_packet(raw)
        self.assertIsNone(pkt.gtpu)
        self.assertIsNone(pkt.tunneled)

    def test_end_marker_has_no_inner(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .udp().gtpu(teid=9, message_type=GTPU_MSG_END_MARKER).build())
        pkt = parse_packet(raw)
        self.assertEqual(pkt.gtpu.message_type, GTPU_MSG_END_MARKER)
        self.assertIsNone(pkt.tunneled)


class TestGTPURoundTrip(unittest.TestCase):
    def _to_config(self, raw: bytes) -> dict:
        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)
        return json.loads(parse_pcap_file(file_object=buf))

    def test_config_structure(self):
        eh = GTPUExtensionHeader(header_type=0x85, content=b"\x01\x00\x00\x00\x00\x00")
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
            .udp().gtpu(teid=0x1234, sequence=7, extension_headers=[eh])
            .ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        pkt_cfg = self._to_config(raw)["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "udp")
        self.assertEqual(pkt_cfg["transport"]["dst_port"], GTPU_PORT)
        g = pkt_cfg["gtpu"]
        self.assertEqual(g["teid"], 0x1234)
        self.assertEqual(g["sequence"], 7)
        self.assertEqual(g["extension_headers"][0]["type"], 0x85)
        self.assertEqual(g["extension_headers"][0]["content"], "010000000000")
        self.assertEqual(g["network"]["src"], "192.168.1.1")
        self.assertNotIn("message_type", g)   # G-PDU omits it

    def test_rebuild_from_config(self):
        from packeteer import __main__ as cli

        eh = GTPUExtensionHeader(header_type=0x85, content=b"\x01\x00\x00\x00\x00\x00")
        raw = (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .udp().gtpu(teid=0x1234, sequence=7, extension_headers=[eh])
            .ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        cfg = self._to_config(raw)
        b, _ = cli._apply_spec_to_builder(PacketBuilder(), cfg["packets"][0], 1)
        self.assertEqual(b.build(), raw)


if __name__ == "__main__":
    unittest.main()
