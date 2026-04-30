"""Tests for RFC 4385 pseudowire control word building and parsing."""
from __future__ import annotations

import json
import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.pseudowire import PseudowireHeader, _build_pseudowire_header
from packeteer.parse.core import parse_packet
from packeteer.parse.pseudowire import packet_parser

# ---------------------------------------------------------------------------
# Unit tests — PseudowireHeader dataclass and build function
# ---------------------------------------------------------------------------

class TestPseudowireHeader(unittest.TestCase):

    def test_defaults(self):
        hdr = PseudowireHeader()
        self.assertEqual(hdr.flags, 0)
        self.assertEqual(hdr.frag, 0)
        self.assertEqual(hdr.length, 0)
        self.assertEqual(hdr.sequence, 0)

    def test_invalid_flags(self):
        with self.assertRaises(ValueError):
            PseudowireHeader(flags=16)

    def test_invalid_frag(self):
        with self.assertRaises(ValueError):
            PseudowireHeader(frag=4)

    def test_invalid_length(self):
        with self.assertRaises(ValueError):
            PseudowireHeader(length=64)

    def test_invalid_sequence(self):
        with self.assertRaises(ValueError):
            PseudowireHeader(sequence=0x10000)

    def test_build_zeros(self):
        raw = _build_pseudowire_header(PseudowireHeader(), b"\xAB\xCD")
        self.assertEqual(len(raw), 6)
        self.assertEqual(raw[:4], b"\x00\x00\x00\x00")
        self.assertEqual(raw[4:], b"\xAB\xCD")

    def test_build_first_nibble_always_zero(self):
        """First nibble of control word must always be 0x0."""
        raw = _build_pseudowire_header(PseudowireHeader(flags=0xF), b"")
        self.assertEqual((raw[0] >> 4) & 0xF, 0)

    def test_build_flags_encoded(self):
        raw = _build_pseudowire_header(PseudowireHeader(flags=0b1010), b"")
        word0, _ = struct.unpack("!HH", raw)
        self.assertEqual((word0 >> 8) & 0xF, 0b1010)

    def test_build_frag_encoded(self):
        raw = _build_pseudowire_header(PseudowireHeader(frag=0b11), b"")
        word0, _ = struct.unpack("!HH", raw)
        self.assertEqual((word0 >> 6) & 0x3, 0b11)

    def test_build_length_encoded(self):
        raw = _build_pseudowire_header(PseudowireHeader(length=42), b"")
        word0, _ = struct.unpack("!HH", raw)
        self.assertEqual(word0 & 0x3F, 42)

    def test_build_sequence_encoded(self):
        raw = _build_pseudowire_header(PseudowireHeader(sequence=0xBEEF), b"")
        _, seq = struct.unpack("!HH", raw)
        self.assertEqual(seq, 0xBEEF)


# ---------------------------------------------------------------------------
# Unit tests — pseudowire parser
# ---------------------------------------------------------------------------

class TestPseudowireParser(unittest.TestCase):

    def test_parse_zeros(self):
        data = b"\x00\x00\x00\x00" + b"\x45\x00"  # followed by IPv4 nibble
        size, inner_et, hdr = packet_parser(data)
        self.assertEqual(size, 4)
        self.assertIsNotNone(hdr)
        assert hdr is not None
        self.assertEqual(hdr.flags, 0)
        self.assertEqual(hdr.sequence, 0)

    def test_parse_inner_ipv4(self):
        data = b"\x00\x00\x00\x00\x45"  # byte 4: version nibble 4
        size, inner_et, hdr = packet_parser(data)
        from packeteer.generate.ethernet import ETHERTYPE_IPV4
        self.assertEqual(inner_et, ETHERTYPE_IPV4)

    def test_parse_inner_ipv6(self):
        data = b"\x00\x00\x00\x00\x60"  # byte 4: version nibble 6
        size, inner_et, _ = packet_parser(data)
        from packeteer.generate.ethernet import ETHERTYPE_IPV6
        self.assertEqual(inner_et, ETHERTYPE_IPV6)

    def test_parse_inner_ethernet(self):
        data = b"\x00\x00\x00\x00\xAA"  # byte 4: version nibble 0xA → Ethernet
        size, inner_et, _ = packet_parser(data)
        from packeteer.generate.gre import GRE_PROTO_TEB
        self.assertEqual(inner_et, GRE_PROTO_TEB)

    def test_parse_rejects_nonzero_first_nibble(self):
        data = b"\x40\x00\x00\x00"  # first nibble 4 — looks like IPv4, not PW
        size, inner_et, hdr = packet_parser(data)
        self.assertEqual(size, 0)
        self.assertIsNone(hdr)

    def test_parse_too_short(self):
        size, inner_et, hdr = packet_parser(b"\x00\x00\x00")
        self.assertEqual(size, 0)
        self.assertIsNone(hdr)

    def test_parse_sequence(self):
        raw = _build_pseudowire_header(PseudowireHeader(sequence=0x1234), b"\x45")
        size, inner_et, hdr = packet_parser(raw)
        self.assertEqual(size, 4)
        assert hdr is not None
        self.assertEqual(hdr.sequence, 0x1234)


# ---------------------------------------------------------------------------
# Builder tests — PacketBuilder.pseudowire()
# ---------------------------------------------------------------------------

class TestPacketBuilderPseudowire(unittest.TestCase):

    def _build_eth_mpls_pw_eth_ip(self, **pw_kwargs: int) -> bytes:
        return (PacketBuilder()
            .ethernet()
            .mpls(label=100)
            .pseudowire(**pw_kwargs)
            .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=80)
            .build()
        )

    def test_mpls_s_bit_set(self):
        """MPLS bottom-of-stack bit must be 1 when next layer is PseudowireHeader."""
        raw = self._build_eth_mpls_pw_eth_ip()
        # Ethernet=14, MPLS word at byte 14
        mpls_word, = struct.unpack_from("!I", raw, 14)
        s_bit = (mpls_word >> 8) & 0x1
        self.assertEqual(s_bit, 1)

    def test_pw_first_nibble_zero(self):
        """First nibble of PW control word must be 0x0 on the wire."""
        raw = self._build_eth_mpls_pw_eth_ip()
        pw_byte = raw[18]  # Ethernet(14) + MPLS(4)
        self.assertEqual((pw_byte >> 4) & 0xF, 0)

    def test_pw_four_bytes(self):
        """PW control word is exactly 4 bytes before the inner Ethernet header."""
        raw_with_pw = self._build_eth_mpls_pw_eth_ip()
        raw_no_pw = (PacketBuilder()
            .ethernet()
            .mpls(label=100)
            .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=80)
            .build()
        )
        self.assertEqual(len(raw_with_pw), len(raw_no_pw) + 4)

    def test_pw_sequence_on_wire(self):
        """Non-zero sequence number should appear in the control word."""
        raw = self._build_eth_mpls_pw_eth_ip(sequence=0xABCD)
        _, seq = struct.unpack_from("!HH", raw, 18)
        self.assertEqual(seq, 0xABCD)

    def test_pw_ip_only(self):
        """Pseudowire can carry a raw IP packet (no inner Ethernet)."""
        raw = (PacketBuilder()
            .ethernet()
            .mpls(label=200)
            .pseudowire()
            .ip(src="10.1.1.1", dst="10.1.1.2")
            .udp(dst_port=53)
            .build()
        )
        self.assertIsInstance(raw, bytes)
        self.assertGreater(len(raw), 14 + 4 + 4)  # Eth + MPLS + PW + at least IP


# ---------------------------------------------------------------------------
# Parse tests
# ---------------------------------------------------------------------------

class TestPseudowireParse(unittest.TestCase):

    def _make_eth_mpls_pw_eth_ip(self, **pw_kwargs: int) -> bytes:
        return (PacketBuilder()
            .ethernet()
            .mpls(label=100)
            .pseudowire(**pw_kwargs)
            .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=80)
            .build()
        )

    def test_parse_sets_pseudowire(self):
        raw = self._make_eth_mpls_pw_eth_ip()
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.pseudowire)

    def test_parse_pseudowire_fields(self):
        raw = self._make_eth_mpls_pw_eth_ip(flags=3, sequence=0x1234)
        pkt = parse_packet(raw)
        assert pkt.pseudowire is not None
        self.assertEqual(pkt.pseudowire.flags, 3)
        self.assertEqual(pkt.pseudowire.sequence, 0x1234)

    def test_parse_mpls_present(self):
        raw = self._make_eth_mpls_pw_eth_ip()
        pkt = parse_packet(raw)
        self.assertEqual(len(pkt.mpls), 1)
        self.assertEqual(pkt.mpls[0].label, 100)

    def test_parse_tunneled_ethernet(self):
        raw = self._make_eth_mpls_pw_eth_ip()
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.tunneled)
        assert pkt.tunneled is not None
        self.assertIsNotNone(pkt.tunneled.ethernet)

    def test_parse_tunneled_ip(self):
        raw = self._make_eth_mpls_pw_eth_ip()
        pkt = parse_packet(raw)
        assert pkt.tunneled is not None
        self.assertIsNotNone(pkt.tunneled.ip)
        assert pkt.tunneled.ip is not None
        self.assertEqual(pkt.tunneled.ip.src, "10.0.0.1")
        self.assertEqual(pkt.tunneled.ip.dst, "10.0.0.2")

    def test_parse_tunneled_transport(self):
        raw = self._make_eth_mpls_pw_eth_ip()
        pkt = parse_packet(raw)
        assert pkt.tunneled is not None
        from packeteer.generate.tcp import TCPHeader
        self.assertIsInstance(pkt.tunneled.transport, TCPHeader)

    def test_parse_pw_ip_only(self):
        """PW carrying raw IP (no inner Ethernet) should parse without tunneled.ethernet."""
        raw = (PacketBuilder()
            .ethernet()
            .mpls(label=200)
            .pseudowire()
            .ip(src="10.1.1.1", dst="10.1.1.2")
            .udp(dst_port=53)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.pseudowire)
        assert pkt.tunneled is not None
        self.assertIsNone(pkt.tunneled.ethernet)
        self.assertIsNotNone(pkt.tunneled.ip)


# ---------------------------------------------------------------------------
# Round-trip tests — parse → to_config → spec → build
# ---------------------------------------------------------------------------

class TestPseudowireRoundTrip(unittest.TestCase):

    def _round_trip(self, raw: bytes) -> bytes:
        from packeteer.parse.to_config import apply_tunneled, to_json_string, update_config
        pkt = parse_packet(raw)
        cfg: dict = {}
        if pkt.ethernet is not None:
            update_config(cfg, pkt.ethernet)
        for label in pkt.mpls:
            update_config(cfg, label)
        if pkt.pseudowire is not None:
            apply_tunneled(cfg, pkt)
        elif pkt.ip is not None:
            update_config(cfg, pkt.ip)
            if pkt.transport is not None:
                update_config(cfg, pkt.transport)
            if pkt.payload:
                update_config(cfg, pkt.payload)
        spec = json.loads(to_json_string({"packets": [cfg]}))["packets"][0]

        b = PacketBuilder()
        # Replay manually the same way __main__._apply_spec_to_builder does
        eth = spec.get("ethernet", {})
        if eth.get("enabled", True):
            b = b.ethernet(
                src_mac=eth.get("src_mac", "00:00:00:00:00:01"),
                dst_mac=eth.get("dst_mac", "00:00:00:00:00:02"),
            )
        for m in spec.get("mpls", []):
            b = b.mpls(label=m["label"], tc=m.get("tc", 0), ttl=m.get("ttl", 64))

        pw = spec.get("pseudowire", {})
        if pw:
            b = b.pseudowire(
                flags=pw.get("flags", 0),
                frag=pw.get("frag", 0),
                length=pw.get("length", 0),
                sequence=pw.get("sequence", 0),
            )
            inner_eth = pw.get("ethernet", {})
            if inner_eth:
                b = b.ethernet(
                    src_mac=inner_eth.get("src_mac", "00:00:00:00:00:01"),
                    dst_mac=inner_eth.get("dst_mac", "00:00:00:00:00:02"),
                )
            inner_net = pw.get("network", {})
            if inner_net:
                b = b.ip(src=inner_net["src"], dst=inner_net["dst"])
            inner_t = pw.get("transport", {})
            if inner_net.get("protocol") == "tcp":
                b = b.tcp(
                    src_port=inner_t.get("src_port", 0),
                    dst_port=inner_t.get("dst_port", 0),
                    seq=inner_t.get("seq", 0),
                    ack=inner_t.get("ack", 0),
                    flags=inner_t.get("flags", 0),
                    window=inner_t.get("window", 65535),
                )
            elif inner_net.get("protocol") == "udp":
                b = b.udp(
                    src_port=inner_t.get("src_port", 0),
                    dst_port=inner_t.get("dst_port", 0),
                )

        return b.build()

    def test_round_trip_eth_pw_eth_ip_tcp(self):
        original = (PacketBuilder()
            .ethernet()
            .mpls(label=100)
            .pseudowire()
            .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=80)
            .build()
        )
        rebuilt = self._round_trip(original)
        self.assertEqual(original, rebuilt)

    def test_round_trip_with_sequence(self):
        original = (PacketBuilder()
            .ethernet()
            .mpls(label=300, ttl=32)
            .pseudowire(sequence=0x5678)
            .ethernet(src_mac="aa:bb:cc:00:00:01", dst_mac="aa:bb:cc:00:00:02")
            .ip(src="172.16.0.1", dst="172.16.0.2")
            .tcp(dst_port=443)
            .build()
        )
        rebuilt = self._round_trip(original)
        self.assertEqual(original, rebuilt)

    def test_spec_contains_pseudowire_key(self):
        from packeteer.parse.to_config import apply_tunneled, update_config
        raw = (PacketBuilder()
            .ethernet()
            .mpls(label=100)
            .pseudowire()
            .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=80)
            .build()
        )
        pkt = parse_packet(raw)
        cfg: dict = {}
        if pkt.ethernet is not None:
            update_config(cfg, pkt.ethernet)
        for label in pkt.mpls:
            update_config(cfg, label)
        apply_tunneled(cfg, pkt)
        self.assertIn("pseudowire", cfg)
        pw = cfg["pseudowire"]
        self.assertIn("ethernet", pw)
        self.assertIn("network", pw)
        self.assertIn("transport", pw)


if __name__ == "__main__":
    unittest.main()
