"""Tests for Linux cooked-capture (SLL / SLL2) support."""
from __future__ import annotations

import io
import json
import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.sll import (
    SLL_OUTGOING,
    SLL2Header,
    SLLHeader,
    _build_sll2_header,
    _build_sll_header,
)
from packeteer.parse import sll2_packet_parser, sll_packet_parser
from packeteer.parse.core import parse_packet, parse_pcap_file
from packeteer.parse.info import format_pcap_info, pcap_info
from packeteer.pcap import (
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    write_pcap,
)
from packeteer.sanitise import SanitiseOptions, sanitise


class TestBuildSLLHeaders(unittest.TestCase):
    def test_sll_v1_layout(self):
        raw = _build_sll_header(
            SLLHeader(packet_type=SLL_OUTGOING, address="aa:bb:cc:00:00:01"), 0x0800)
        self.assertEqual(len(raw), 16)
        ptype, arphrd, alen, addr, proto = struct.unpack(">HHH8sH", raw)
        self.assertEqual((ptype, arphrd, alen, proto), (SLL_OUTGOING, 1, 6, 0x0800))
        self.assertEqual(addr[:6].hex(), "aabbcc000001")

    def test_sll2_layout(self):
        raw = _build_sll2_header(SLL2Header(address="aa:bb:cc:00:00:02", if_index=7), 0x86DD)
        self.assertEqual(len(raw), 20)
        proto, _resv, ifi, arphrd, ptype, alen, addr = struct.unpack(">HHIHBB8s", raw)
        self.assertEqual((proto, ifi, arphrd, alen), (0x86DD, 7, 1, 6))
        self.assertEqual(addr[:6].hex(), "aabbcc000002")

    def test_empty_address_zero_length(self):
        raw = _build_sll_header(SLLHeader(address=""), 0x0800)
        _, _, alen, addr, _ = struct.unpack(">HHH8sH", raw)
        self.assertEqual(alen, 0)
        self.assertEqual(addr, b"\x00" * 8)


class TestSLLParsers(unittest.TestCase):
    def test_sll_v1_roundtrip(self):
        raw = _build_sll_header(
            SLLHeader(packet_type=SLL_OUTGOING, address="aa:bb:cc:00:00:01"), 0x0800)
        size, proto, hdr = sll_packet_parser(raw)
        self.assertEqual((size, proto), (16, 0x0800))
        self.assertEqual(hdr.packet_type, SLL_OUTGOING)
        self.assertEqual(hdr.address, "aa:bb:cc:00:00:01")

    def test_sll2_roundtrip(self):
        raw = _build_sll2_header(SLL2Header(address="aa:bb:cc:00:00:02", if_index=7), 0x0800)
        size, proto, hdr = sll2_packet_parser(raw)
        self.assertEqual((size, proto), (20, 0x0800))
        self.assertEqual(hdr.if_index, 7)
        self.assertEqual(hdr.address, "aa:bb:cc:00:00:02")

    def test_truncated(self):
        self.assertEqual(sll_packet_parser(b"\x00" * 15), (0, None, None))
        self.assertEqual(sll2_packet_parser(b"\x00" * 19), (0, None, None))


class TestParsePacketSLL(unittest.TestCase):
    def test_sll_v1_inner_ip_tcp(self):
        raw = (PacketBuilder().sll(address="aa:bb:cc:00:00:01")
               .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80).build())
        pkt = parse_packet(raw, link_type=LINKTYPE_LINUX_SLL)
        self.assertIsInstance(pkt.sll, SLLHeader)
        self.assertIsNone(pkt.ethernet)
        self.assertEqual(pkt.ip.src, "10.0.0.1")
        self.assertEqual(pkt.transport.dst_port, 80)

    def test_sll2_inner_ipv6_udp(self):
        raw = (PacketBuilder().sll2(address="aa:bb:cc:00:00:02")
               .ip(src="2001:db8::1", dst="2001:db8::2").udp(dst_port=53).build())
        pkt = parse_packet(raw, link_type=LINKTYPE_LINUX_SLL2)
        self.assertIsInstance(pkt.sll, SLL2Header)
        self.assertEqual(pkt.ip.src, "2001:db8::1")
        self.assertEqual(pkt.transport.dst_port, 53)

    def test_sll_carrying_arp(self):
        raw = (PacketBuilder().sll(address="aa:bb:cc:00:00:01")
               .arp(sender_mac="aa:bb:cc:00:00:01", sender_ip="10.0.0.1", target_ip="10.0.0.2")
               .build())
        pkt = parse_packet(raw, link_type=LINKTYPE_LINUX_SLL)
        self.assertIsInstance(pkt.sll, SLLHeader)
        self.assertIsNotNone(pkt.arp)
        self.assertEqual(pkt.arp.target_ip, "10.0.0.2")


def _sll_records(link_type: int) -> list:
    if link_type == LINKTYPE_LINUX_SLL2:
        p = (PacketBuilder().sll2(address="aa:bb:cc:00:00:01", if_index=2)
             .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80).build())
    else:
        p = (PacketBuilder().sll(address="aa:bb:cc:00:00:01")
             .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80).build())
    return [(p, 0, 0)]


class TestSLLRoundTrip(unittest.TestCase):
    def _to_config(self, link_type: int) -> dict:
        buf = io.BytesIO()
        write_pcap(_sll_records(link_type), file_object=buf, link_type=link_type)
        buf.seek(0)
        return json.loads(parse_pcap_file(file_object=buf))

    def test_sll_v1_config_and_rebuild(self):
        from packeteer import __main__ as cli
        cfg = self._to_config(LINKTYPE_LINUX_SLL)
        self.assertEqual(cfg["metadata"]["link_type"], LINKTYPE_LINUX_SLL)
        self.assertIn("sll", cfg["packets"][0])
        self.assertNotIn("ethernet", cfg["packets"][0])
        b, _ = cli._apply_spec_to_builder(PacketBuilder(), cfg["packets"][0], 1)
        self.assertEqual(b.build(), _sll_records(LINKTYPE_LINUX_SLL)[0][0])

    def test_sll2_config_and_rebuild(self):
        from packeteer import __main__ as cli
        cfg = self._to_config(LINKTYPE_LINUX_SLL2)
        self.assertEqual(cfg["metadata"]["link_type"], LINKTYPE_LINUX_SLL2)
        self.assertEqual(cfg["packets"][0]["sll2"]["if_index"], 2)
        b, _ = cli._apply_spec_to_builder(PacketBuilder(), cfg["packets"][0], 1)
        self.assertEqual(b.build(), _sll_records(LINKTYPE_LINUX_SLL2)[0][0])

    def test_infer_link_type_from_sll_section(self):
        from packeteer import __main__ as cli
        self.assertEqual(cli._infer_link_type([{"sll": {}}]), LINKTYPE_LINUX_SLL)
        self.assertEqual(cli._infer_link_type([{"sll2": {}}]), LINKTYPE_LINUX_SLL2)


class TestSLLFileInfo(unittest.TestCase):
    def test_link_name_and_layer(self):
        buf = io.BytesIO()
        write_pcap(_sll_records(LINKTYPE_LINUX_SLL), file_object=buf, link_type=LINKTYPE_LINUX_SLL)
        buf.seek(0)
        info = pcap_info(file_object=buf)
        self.assertEqual(info.layer_counts.get("sll"), 1)
        self.assertIn("linux_sll", format_pcap_info(info))


class TestSLLSanitise(unittest.TestCase):
    def test_cooked_address_rewritten(self):
        buf = io.BytesIO()
        write_pcap(_sll_records(LINKTYPE_LINUX_SLL), file_object=buf, link_type=LINKTYPE_LINUX_SLL)
        buf.seek(0)
        cfg = json.loads(parse_pcap_file(file_object=buf))
        clean = sanitise(cfg, SanitiseOptions(macs=True))
        self.assertNotEqual(clean["packets"][0]["sll"]["address"], "aa:bb:cc:00:00:01")


class TestSLLCLILinkType(unittest.TestCase):
    def test_link_type_names(self):
        from packeteer import __main__ as cli
        self.assertEqual(cli._link_type("linux_sll"), LINKTYPE_LINUX_SLL)
        self.assertEqual(cli._link_type("sll"), LINKTYPE_LINUX_SLL)
        self.assertEqual(cli._link_type("linux_sll2"), LINKTYPE_LINUX_SLL2)
        self.assertEqual(cli._link_type("sll2"), LINKTYPE_LINUX_SLL2)


if __name__ == "__main__":
    unittest.main()
