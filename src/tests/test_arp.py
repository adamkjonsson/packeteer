"""Tests for ARP (RFC 826) building, parsing, config, file-info, and sanitise."""
from __future__ import annotations

import io
import json
import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.arp import (
    ARP_OP_REPLY,
    ARP_OP_REQUEST,
    ARPHeader,
    _build_arp_header,
)
from packeteer.parse import arp_packet_parser
from packeteer.parse.core import parse_packet, parse_pcap_file
from packeteer.parse.info import pcap_info
from packeteer.pcap import write_pcap
from packeteer.sanitise import SanitiseOptions, sanitise


class TestBuildARPHeader(unittest.TestCase):
    def test_length_and_fixed_fields(self):
        raw = _build_arp_header(ARPHeader(
            sender_mac="aa:bb:cc:00:00:01", sender_ip="10.0.0.1", target_ip="10.0.0.2"))
        self.assertEqual(len(raw), 28)
        htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", raw, 0)
        self.assertEqual((htype, ptype, hlen, plen, op), (1, 0x0800, 6, 4, ARP_OP_REQUEST))

    def test_address_encoding(self):
        raw = _build_arp_header(ARPHeader(
            operation=ARP_OP_REPLY,
            sender_mac="aa:bb:cc:00:00:02", sender_ip="10.0.0.2",
            target_mac="aa:bb:cc:00:00:01", target_ip="10.0.0.1"))
        self.assertEqual(raw[8:14].hex(), "aabbcc000002")
        self.assertEqual(".".join(str(b) for b in raw[14:18]), "10.0.0.2")
        self.assertEqual(raw[18:24].hex(), "aabbcc000001")
        self.assertEqual(".".join(str(b) for b in raw[24:28]), "10.0.0.1")


class TestARPParser(unittest.TestCase):
    def test_roundtrip(self):
        raw = _build_arp_header(ARPHeader(
            operation=ARP_OP_REPLY,
            sender_mac="aa:bb:cc:00:00:02", sender_ip="10.0.0.2",
            target_mac="aa:bb:cc:00:00:01", target_ip="10.0.0.1"))
        size, nxt, hdr = arp_packet_parser(raw)
        self.assertEqual(size, 28)
        self.assertIsNone(nxt)
        self.assertEqual(hdr.operation, ARP_OP_REPLY)
        self.assertEqual(hdr.sender_mac, "aa:bb:cc:00:00:02")
        self.assertEqual(hdr.sender_ip, "10.0.0.2")
        self.assertEqual(hdr.target_ip, "10.0.0.1")

    def test_truncated(self):
        self.assertEqual(arp_packet_parser(b"\x00" * 27), (0, None, None))

    def test_non_ethernet_ipv4_rejected(self):
        # hlen=8, plen=4 → unsupported
        raw = struct.pack("!HHBBH", 1, 0x0800, 8, 4, 1) + b"\x00" * 24
        self.assertEqual(arp_packet_parser(raw), (0, None, None))


class TestPacketBuilderARP(unittest.TestCase):
    def _request(self) -> bytes:
        return (PacketBuilder()
            .ethernet(src_mac="aa:bb:cc:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff")
            .arp(sender_mac="aa:bb:cc:00:00:01", sender_ip="10.0.0.1", target_ip="10.0.0.2")
            .build())

    def test_ethertype_is_arp(self):
        self.assertEqual(struct.unpack_from("!H", self._request(), 12)[0], 0x0806)

    def test_padded_to_minimum_frame(self):
        # eth(14) + arp(28) = 42 → padded to the 60-byte Ethernet minimum
        self.assertEqual(len(self._request()), 60)

    def test_builds_without_ip_or_transport(self):
        # No _validate error despite no .ip()/.tcp()
        self.assertIsInstance(self._request(), bytes)

    def test_gratuitous_arp(self):
        pkt = (PacketBuilder().ethernet(src_mac="aa:bb:cc:00:00:01")
            .arp(operation=ARP_OP_REPLY,
                 sender_mac="aa:bb:cc:00:00:01", sender_ip="10.0.0.5",
                 target_mac="ff:ff:ff:ff:ff:ff", target_ip="10.0.0.5").build())
        p = parse_packet(pkt)
        self.assertEqual(p.arp.sender_ip, p.arp.target_ip)


class TestParsePacketARP(unittest.TestCase):
    def test_terminal_no_ip_or_transport(self):
        pkt = parse_packet(
            (PacketBuilder().ethernet(src_mac="aa:bb:cc:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff")
             .arp(sender_mac="aa:bb:cc:00:00:01", sender_ip="10.0.0.1", target_ip="10.0.0.2")
             .build()))
        self.assertIsInstance(pkt.arp, ARPHeader)
        self.assertEqual(pkt.arp.operation, ARP_OP_REQUEST)
        self.assertEqual(pkt.arp.target_ip, "10.0.0.2")
        self.assertIsNone(pkt.ip)
        self.assertIsNone(pkt.transport)
        self.assertEqual(pkt.ethernet.src_mac, "aa:bb:cc:00:00:01")


def _req_rep() -> list:
    req = (PacketBuilder().ethernet(src_mac="aa:bb:cc:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff")
           .arp(sender_mac="aa:bb:cc:00:00:01", sender_ip="10.0.0.1", target_ip="10.0.0.2").build())
    rep = (PacketBuilder().ethernet(src_mac="aa:bb:cc:00:00:02", dst_mac="aa:bb:cc:00:00:01")
           .arp(operation=ARP_OP_REPLY,
                sender_mac="aa:bb:cc:00:00:02", sender_ip="10.0.0.2",
                target_mac="aa:bb:cc:00:00:01", target_ip="10.0.0.1").build())
    return [(req, 0, 0), (rep, 0, 0)]


class TestARPRoundTrip(unittest.TestCase):
    def _to_config(self, records: list) -> dict:
        buf = io.BytesIO()
        write_pcap(records, file_object=buf)
        buf.seek(0)
        return json.loads(parse_pcap_file(file_object=buf))

    def test_config_structure(self):
        cfg = self._to_config(_req_rep())
        arp = cfg["packets"][0]["arp"]
        self.assertEqual(arp["operation"], ARP_OP_REQUEST)
        self.assertEqual(arp["sender_ip"], "10.0.0.1")
        self.assertEqual(arp["target_ip"], "10.0.0.2")
        self.assertNotIn("network", cfg["packets"][0])

    def test_rebuild_from_config(self):
        from packeteer import __main__ as cli
        records = _req_rep()
        cfg = self._to_config(records)
        for i, (raw, _, _) in enumerate(records):
            b, _term = cli._apply_spec_to_builder(PacketBuilder(), cfg["packets"][i], i + 1)
            self.assertEqual(b.build(), raw)


class TestARPFileInfo(unittest.TestCase):
    def test_arp_counted(self):
        buf = io.BytesIO()
        write_pcap(_req_rep(), file_object=buf)
        buf.seek(0)
        counts = pcap_info(file_object=buf).layer_counts
        self.assertEqual(counts.get("arp"), 2)
        self.assertEqual(counts.get("ethernet"), 2)
        self.assertNotIn("ipv4", counts)


class TestARPSanitise(unittest.TestCase):
    def test_addresses_rewritten_consistently(self):
        buf = io.BytesIO()
        write_pcap(_req_rep(), file_object=buf)
        buf.seek(0)
        cfg = json.loads(parse_pcap_file(file_object=buf))
        clean = sanitise(cfg, SanitiseOptions(ips=True, macs=True))
        a0 = clean["packets"][0]["arp"]
        a1 = clean["packets"][1]["arp"]
        # Real addresses are gone...
        self.assertNotEqual(a0["sender_ip"], "10.0.0.1")
        self.assertNotEqual(a0["sender_mac"], "aa:bb:cc:00:00:01")
        # ...but mapping is consistent: packet 0 sender == packet 1 target.
        self.assertEqual(a0["sender_ip"], a1["target_ip"])
        self.assertEqual(a0["sender_mac"], a1["target_mac"])


if __name__ == "__main__":
    unittest.main()
