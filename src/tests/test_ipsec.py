"""Tests for IPsec — AH (RFC 4302) and ESP (RFC 4303) building and parsing.

packeteer performs no cryptography: AH is integrity-only and therefore fully
parseable (its protected content stays in cleartext), while ESP is modelled as
the SPI + Sequence prefix followed by an opaque payload — exactly what a capture
without the Security Association key looks like.
"""
from __future__ import annotations

import io
import json
import struct
import unittest
from collections.abc import Callable

from packeteer.generate import PacketBuilder
from packeteer.generate.ipsec import (
    AH_ICV_LEN_SHA1_96,
    AH_ICV_LEN_SHA256_128,
    IPPROTO_AH,
    IPPROTO_ESP,
    AHHeader,
    ESPHeader,
    _build_ah_header,
    _build_esp_header,
)
from packeteer.generate.tcp import TCPHeader
from packeteer.parse import ah_packet_parser, esp_packet_parser
from packeteer.parse.core import ParsedPacket, parse_packet, parse_pcap_file
from packeteer.parse.info import pcap_info
from packeteer.pcap import write_pcap
from packeteer.sanitise import SanitiseOptions, sanitise


class TestBuildAHHeader(unittest.TestCase):
    def test_layout_with_default_icv(self):
        raw = _build_ah_header(AHHeader(spi=0x11223344, sequence=7), next_header=6)
        # 12-byte fixed header (NextHdr+PayLen+Reserved+SPI+Seq) + 12-byte ICV.
        self.assertEqual(len(raw), 12 + AH_ICV_LEN_SHA1_96)
        self.assertEqual(raw[0], 6)                                # Next Header = TCP
        self.assertEqual(struct.unpack_from("!H", raw, 2)[0], 0)   # Reserved
        self.assertEqual(struct.unpack_from("!I", raw, 4)[0], 0x11223344)
        self.assertEqual(struct.unpack_from("!I", raw, 8)[0], 7)
        # Payload Len = total/4 - 2 = 20/4 - 2 = 3
        self.assertEqual(raw[1], len(raw) // 4 - 2)

    def test_icv_padded_to_word_boundary(self):
        # A 13-byte ICV must be padded so the whole AH is a multiple of 4 bytes.
        raw = _build_ah_header(AHHeader(spi=1, icv=b"\x01" * 13), next_header=4)
        self.assertEqual(len(raw) % 4, 0)
        self.assertEqual(raw[1], len(raw) // 4 - 2)

    def test_explicit_icv_preserved(self):
        icv = bytes(range(16))
        raw = _build_ah_header(AHHeader(spi=1, icv=icv), next_header=4)
        self.assertEqual(raw[12:], icv)   # ICV follows the 12-byte fixed header

    def test_sha256_icv_length(self):
        raw = _build_ah_header(
            AHHeader(spi=1, icv_len=AH_ICV_LEN_SHA256_128), next_header=6,
        )
        self.assertEqual(len(raw), 12 + AH_ICV_LEN_SHA256_128)


class TestBuildESPHeader(unittest.TestCase):
    def test_spi_seq_prefix_then_payload(self):
        raw = _build_esp_header(ESPHeader(spi=0xAABBCCDD, sequence=9, payload=b"opaque"))
        self.assertEqual(struct.unpack_from("!I", raw, 0)[0], 0xAABBCCDD)
        self.assertEqual(struct.unpack_from("!I", raw, 4)[0], 9)
        self.assertEqual(raw[8:], b"opaque")

    def test_icv_tail_appended(self):
        raw = _build_esp_header(ESPHeader(spi=1, payload=b"abcd", icv_len=4))
        self.assertEqual(len(raw), 8 + 4 + 4)
        self.assertEqual(raw[8:12], b"abcd")


class TestAHParser(unittest.TestCase):
    def test_roundtrip(self):
        raw = _build_ah_header(AHHeader(spi=0x99, sequence=3), next_header=6) + b"inner"
        size, next_header, hdr = ah_packet_parser(raw)
        self.assertEqual(size, 12 + AH_ICV_LEN_SHA1_96)
        self.assertEqual(next_header, 6)
        self.assertEqual(hdr.spi, 0x99)
        self.assertEqual(hdr.sequence, 3)
        self.assertEqual(hdr.icv_len, AH_ICV_LEN_SHA1_96)

    def test_truncated(self):
        self.assertEqual(ah_packet_parser(b"\x00\x00"), (0, None, None))


class TestESPParser(unittest.TestCase):
    def test_prefix_only(self):
        raw = _build_esp_header(ESPHeader(spi=0x2000, sequence=5, payload=b"x" * 20))
        size, next_header, hdr = esp_packet_parser(raw)
        self.assertEqual(size, 8)            # only SPI + Sequence are cleartext
        self.assertIsNone(next_header)       # ESP is terminal — rest is opaque
        self.assertEqual(hdr.spi, 0x2000)
        self.assertEqual(hdr.sequence, 5)

    def test_truncated(self):
        self.assertEqual(esp_packet_parser(b"\x00\x00\x00"), (0, None, None))


class TestPacketBuilderAH(unittest.TestCase):
    def test_outer_ip_protocol_is_ah(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .ah(spi=1).tcp(dst_port=80).build())
        self.assertEqual(pkt[23], IPPROTO_AH)

    def test_next_header_set_from_following_layer(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .ah(spi=1).tcp(dst_port=80).build())
        # AH starts at eth(14)+ip(20)=34; Next Header is the first byte → TCP (6)
        self.assertEqual(pkt[34], 6)

    def test_tunnel_mode_next_header_is_ipip(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .ah(spi=1).ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        self.assertEqual(pkt[34], 4)   # Next Header = IP-in-IP


class TestPacketBuilderESP(unittest.TestCase):
    def test_outer_ip_protocol_is_esp(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .esp(spi=1, size=32).build())
        self.assertEqual(pkt[23], IPPROTO_ESP)

    def test_esp_with_size_builds_without_inner(self):
        pkt = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .esp(spi=0x2000, sequence=1, size=64).build())
        # ESP header at 34; SPI then sequence are cleartext.
        self.assertEqual(struct.unpack_from("!I", pkt, 34)[0], 0x2000)
        self.assertEqual(struct.unpack_from("!I", pkt, 38)[0], 1)


class TestParsePacketAH(unittest.TestCase):
    def test_transport_mode_inner_visible(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .ah(spi=0x1000, sequence=2).tcp(dst_port=80).build())
        pkt = parse_packet(raw)
        self.assertIsInstance(pkt.ah, AHHeader)
        self.assertEqual(pkt.ah.spi, 0x1000)
        self.assertEqual(pkt.ah.sequence, 2)
        self.assertIsInstance(pkt.transport, TCPHeader)
        self.assertEqual(pkt.transport.dst_port, 80)
        self.assertIsNone(pkt.tunneled)

    def test_tunnel_mode_inner_under_tunneled(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .ah(spi=0x1000).ip(src="192.168.1.1", dst="192.168.1.2")
               .tcp(dst_port=80).build())
        pkt = parse_packet(raw)
        self.assertIsInstance(pkt.ah, AHHeader)
        self.assertIsInstance(pkt.tunneled, ParsedPacket)
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.transport.dst_port, 80)

    def test_ah_then_esp(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .ah(spi=0x1000).esp(spi=0x2000, size=16).build())
        pkt = parse_packet(raw)
        self.assertIsInstance(pkt.ah, AHHeader)
        self.assertIsInstance(pkt.esp, ESPHeader)
        self.assertEqual(pkt.esp.spi, 0x2000)


class TestParsePacketESP(unittest.TestCase):
    def test_terminal_opaque(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .esp(spi=0x2000, sequence=4, size=32).build())
        pkt = parse_packet(raw)
        self.assertIsInstance(pkt.esp, ESPHeader)
        self.assertEqual(pkt.esp.spi, 0x2000)
        self.assertEqual(pkt.esp.sequence, 4)
        self.assertIsNone(pkt.transport)   # opaque — inner not decoded

    def test_esp_inner_not_decoded(self):
        # Even structured inner layers become opaque ESP payload on parse.
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .esp(spi=0x2000).ip(src="192.168.1.1", dst="192.168.1.2")
               .tcp(dst_port=80).build())
        pkt = parse_packet(raw)
        self.assertIsInstance(pkt.esp, ESPHeader)
        self.assertIsNone(pkt.tunneled)
        self.assertIsNone(pkt.transport)


def _to_config(raw: bytes) -> dict:
    buf = io.BytesIO()
    write_pcap([(raw, 0, 0)], file_object=buf)
    buf.seek(0)
    return json.loads(parse_pcap_file(file_object=buf))


def _rebuild(raw: bytes) -> bytes:
    from packeteer import __main__ as cli

    cfg = _to_config(raw)
    b, _ = cli._apply_spec_to_builder(PacketBuilder(), cfg["packets"][0], 1)
    return b.build()


class TestIPsecRoundTrip(unittest.TestCase):
    def _src_mac_pkt(self, build_inner: Callable[[PacketBuilder], PacketBuilder]) -> bytes:
        b = (PacketBuilder()
             .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
             .ip(src="10.0.0.1", dst="10.0.0.2"))
        return build_inner(b).build()

    def test_ah_transport_config_structure(self):
        raw = self._src_mac_pkt(lambda b: b.ah(spi=0x1000, sequence=5).tcp(dst_port=80))
        cfg = _to_config(raw)["packets"][0]
        self.assertEqual(cfg["network"]["protocol"], "ah")
        self.assertEqual(cfg["ah"]["spi"], 0x1000)
        self.assertEqual(cfg["ah"]["sequence"], 5)
        self.assertEqual(cfg["ah"]["protocol"], "tcp")
        self.assertEqual(cfg["ah"]["transport"]["dst_port"], 80)

    def test_ah_tunnel_config_structure(self):
        raw = self._src_mac_pkt(
            lambda b: b.ah(spi=0x1000).ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80),
        )
        cfg = _to_config(raw)["packets"][0]
        self.assertEqual(cfg["ah"]["network"]["src"], "192.168.1.1")
        self.assertEqual(cfg["ah"]["transport"]["dst_port"], 80)

    def test_esp_config_structure(self):
        raw = self._src_mac_pkt(lambda b: b.esp(spi=0x2000, sequence=3, size=16))
        cfg = _to_config(raw)["packets"][0]
        self.assertEqual(cfg["network"]["protocol"], "esp")
        self.assertEqual(cfg["esp"]["spi"], 0x2000)
        self.assertEqual(cfg["esp"]["sequence"], 3)
        self.assertIn("payload", cfg["esp"])

    def test_ah_transport_roundtrip(self):
        raw = self._src_mac_pkt(lambda b: b.ah(spi=0x1000, sequence=5).tcp(dst_port=80))
        self.assertEqual(_rebuild(raw), raw)

    def test_ah_tunnel_roundtrip(self):
        raw = self._src_mac_pkt(
            lambda b: b.ah(spi=0x1000).ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80),
        )
        self.assertEqual(_rebuild(raw), raw)

    def test_ah_then_esp_roundtrip(self):
        raw = self._src_mac_pkt(lambda b: b.ah(spi=0x1000).esp(spi=0x2000, size=16))
        self.assertEqual(_rebuild(raw), raw)

    def test_esp_size_roundtrip(self):
        raw = self._src_mac_pkt(lambda b: b.esp(spi=0x2000, sequence=3, size=64))
        self.assertEqual(_rebuild(raw), raw)

    def test_esp_inner_roundtrip(self):
        raw = self._src_mac_pkt(
            lambda b: b.esp(spi=0x2000).ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80),
        )
        self.assertEqual(_rebuild(raw), raw)


class TestIPsecFileInfo(unittest.TestCase):
    def test_ah_and_esp_counted(self):
        ah = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
              .ah(spi=1).tcp(dst_port=80).build())
        esp = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .esp(spi=2, size=32).build())
        buf = io.BytesIO()
        write_pcap([(ah, 0, 0), (esp, 0, 0)], file_object=buf)
        buf.seek(0)
        counts = pcap_info(file_object=buf).layer_counts
        self.assertEqual(counts.get("ah"), 1)
        self.assertEqual(counts.get("esp"), 1)
        # AH inner TCP is still counted; ESP carries no decoded inner.
        self.assertEqual(counts.get("tcp"), 1)
        self.assertNotIn("ipip", counts)   # AH tunnel must not spuriously add ipip

    def test_ah_tunnel_inner_counted(self):
        ah = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
              .ah(spi=1).ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=80).build())
        buf = io.BytesIO()
        write_pcap([(ah, 0, 0)], file_object=buf)
        buf.seek(0)
        counts = pcap_info(file_object=buf).layer_counts
        self.assertEqual(counts.get("ah"), 1)
        # Inner stack is reached via recursion; ipv4 at two depths de-dupes to one
        # packet, and the inner TCP is reported.
        self.assertEqual(counts.get("ipv4"), 1)
        self.assertEqual(counts.get("tcp"), 1)


class TestIPsecSanitise(unittest.TestCase):
    def test_ah_tunnel_inner_addresses_scrubbed_spi_kept(self):
        raw = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
               .ah(spi=0x1000).ip(src="192.168.1.1", dst="192.168.1.2")
               .tcp(dst_port=80).build())
        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)
        cfg = json.loads(parse_pcap_file(file_object=buf))
        clean = sanitise(cfg, SanitiseOptions(ips=True))
        pkt = clean["packets"][0]
        # Outer and inner IPs are rewritten...
        self.assertNotEqual(pkt["network"]["src"], "10.0.0.1")
        self.assertNotEqual(pkt["ah"]["network"]["src"], "192.168.1.1")
        # ...but the SPI is not an address/PII, so it is left intact.
        self.assertEqual(pkt["ah"]["spi"], 0x1000)


if __name__ == "__main__":
    unittest.main()
