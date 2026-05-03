"""Tests for IPv6 Hop-by-Hop Options extension header (RFC 8200 §4.3)."""
from __future__ import annotations

import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.ipv6 import (
    HBH_NEXT_HEADER,
    HBH_OPT_JUMBO_PAYLOAD,
    HBH_OPT_ROUTER_ALERT,
    HopByHopOptions,
    IPv6Header,
    JumboPayloadOption,
    RawOption,
    RouterAlertOption,
    _build_hop_by_hop_header,
    _build_ipv6_header,
)
from packeteer.parse.core import parse_packet
from packeteer.parse.ip import packet_parser
from packeteer.parse.to_config import update_config
from packeteer.pcap import LINKTYPE_RAW

# ── helpers ───────────────────────────────────────────────────────────────────

def _ipv6_hbh_packet(hbh: HopByHopOptions, transport_proto: int = 17) -> bytes:
    """Return a raw IPv6 + HBH + minimal UDP packet for parse-path tests."""
    hbh_bytes = _build_hop_by_hop_header(hbh, transport_proto)
    udp = struct.pack("!HHHH", 1234, 5678, 8, 0)  # src, dst, len, checksum (dummy)
    payload = b"\x00" * 4
    ip_hdr = IPv6Header(
        src="::1", dst="::2",
        next_header=HBH_NEXT_HEADER,
        hop_limit=64,
    )
    return _build_ipv6_header(ip_hdr, hbh_bytes + udp + payload) + hbh_bytes + udp + payload


# ── generation ────────────────────────────────────────────────────────────────

class TestBuildHopByHopHeader(unittest.TestCase):

    def _build(self, opts: list, next_proto: int = 17) -> bytes:
        return _build_hop_by_hop_header(HopByHopOptions(options=opts), next_proto)

    def test_multiple_of_8_bytes(self):
        for opts in [
            [],
            [RouterAlertOption(0)],
            [JumboPayloadOption(70_000)],
            [RawOption(0x10, b"\xab\xcd")],
            [RouterAlertOption(0), JumboPayloadOption(70_000)],
        ]:
            raw = self._build(opts)
            self.assertEqual(len(raw) % 8, 0, f"Not 8-byte aligned for {opts}")

    def test_minimum_length_empty_options(self):
        raw = self._build([])
        self.assertEqual(len(raw), 8)

    def test_next_proto_field(self):
        raw = self._build([], next_proto=6)
        self.assertEqual(raw[0], 6)

    def test_hdr_ext_len_empty(self):
        raw = self._build([])
        # 8 bytes total → hdr_ext_len = 8//8 - 1 = 0
        self.assertEqual(raw[1], 0)

    def test_router_alert_wire_bytes(self):
        raw = self._build([RouterAlertOption(value=0)], next_proto=17)
        # bytes 0,1 = next_proto, hdr_ext_len
        # bytes 2,3,4,5 = type=0x05, len=2, value=0x0000
        self.assertEqual(raw[2], HBH_OPT_ROUTER_ALERT)
        self.assertEqual(raw[3], 2)
        self.assertEqual(struct.unpack("!H", raw[4:6])[0], 0)

    def test_router_alert_rsvp_value(self):
        raw = self._build([RouterAlertOption(value=1)], next_proto=17)
        self.assertEqual(struct.unpack("!H", raw[4:6])[0], 1)

    def test_jumbo_payload_wire_bytes(self):
        length = 70_000
        raw = self._build([JumboPayloadOption(length)], next_proto=17)
        self.assertEqual(raw[2], HBH_OPT_JUMBO_PAYLOAD)
        self.assertEqual(raw[3], 4)
        self.assertEqual(struct.unpack("!I", raw[4:8])[0], length)

    def test_raw_option_wire_bytes(self):
        raw = self._build([RawOption(0x11, b"\xde\xad")], next_proto=17)
        self.assertEqual(raw[2], 0x11)
        self.assertEqual(raw[3], 2)
        self.assertEqual(raw[4:6], b"\xde\xad")

    def test_multiple_options_padded(self):
        # RouterAlert (4 bytes) + JumboPayload (6 bytes) = 10 option bytes
        # total used = 2 (hdr bytes) + 10 = 12 → pad to 16 → need 4 bytes of PadN
        raw = self._build([RouterAlertOption(0), JumboPayloadOption(70_000)])
        self.assertEqual(len(raw), 16)
        self.assertEqual(raw[1], 1)  # hdr_ext_len = 16//8 - 1 = 1

    def test_pad1_when_one_byte_needed(self):
        # RawOption with 3 bytes data → type(1) + len(1) + data(3) = 5 option bytes
        # total = 2 + 5 = 7 → need 1 byte pad → Pad1 (0x00)
        raw = self._build([RawOption(0x10, b"\x01\x02\x03")])
        self.assertEqual(len(raw), 8)
        self.assertEqual(raw[7], 0x00)  # Pad1

    def test_padn_when_multiple_bytes_needed(self):
        # RawOption with 2 bytes data → type(1)+len(1)+data(2) = 4 option bytes
        # total = 2 + 4 = 6 → need 2 bytes pad → PadN: 0x01, 0x00
        raw = self._build([RawOption(0x10, b"\xab\xcd")])
        self.assertEqual(len(raw), 8)
        self.assertEqual(raw[6], 0x01)  # PadN type
        self.assertEqual(raw[7], 0x00)  # PadN length = 0


# ── parsing ───────────────────────────────────────────────────────────────────

class TestParseHopByHopHeader(unittest.TestCase):

    def _parse(
        self, hbh: HopByHopOptions, transport_proto: int = 17,
    ) -> tuple[int, int | None, IPv6Header | None]:
        raw = _ipv6_hbh_packet(hbh, transport_proto)
        size, proto, hdr = packet_parser(raw)
        return size, proto, hdr

    def test_parse_advances_past_hbh(self):
        hbh = HopByHopOptions(options=[RouterAlertOption(0)])
        raw = _ipv6_hbh_packet(hbh)
        hbh_bytes = _build_hop_by_hop_header(hbh, 17)
        size, _, _ = packet_parser(raw)
        self.assertEqual(size, 40 + len(hbh_bytes))

    def test_parse_returns_transport_proto(self):
        hbh = HopByHopOptions(options=[RouterAlertOption(0)])
        _, proto, _ = self._parse(hbh, transport_proto=6)
        self.assertEqual(proto, 6)

    def test_parse_router_alert(self):
        hbh = HopByHopOptions(options=[RouterAlertOption(value=1)])
        _, _, hdr = self._parse(hbh)
        assert hdr is not None
        assert hdr.hop_by_hop is not None
        opts = hdr.hop_by_hop.options
        self.assertEqual(len(opts), 1)
        self.assertIsInstance(opts[0], RouterAlertOption)
        self.assertEqual(opts[0].value, 1)

    def test_parse_jumbo_payload(self):
        hbh = HopByHopOptions(options=[JumboPayloadOption(jumbo_length=70_000)])
        _, _, hdr = self._parse(hbh)
        assert hdr is not None
        assert hdr.hop_by_hop is not None
        opts = hdr.hop_by_hop.options
        self.assertEqual(len(opts), 1)
        self.assertIsInstance(opts[0], JumboPayloadOption)
        self.assertEqual(opts[0].jumbo_length, 70_000)

    def test_parse_raw_option(self):
        hbh = HopByHopOptions(options=[RawOption(0x11, b"\xca\xfe")])
        _, _, hdr = self._parse(hbh)
        assert hdr is not None
        assert hdr.hop_by_hop is not None
        opts = hdr.hop_by_hop.options
        self.assertEqual(len(opts), 1)
        self.assertIsInstance(opts[0], RawOption)
        self.assertEqual(opts[0].option_type, 0x11)
        self.assertEqual(opts[0].data, b"\xca\xfe")

    def test_parse_multiple_options(self):
        hbh = HopByHopOptions(options=[RouterAlertOption(0), JumboPayloadOption(100_000)])
        _, _, hdr = self._parse(hbh)
        assert hdr is not None
        assert hdr.hop_by_hop is not None
        opts = hdr.hop_by_hop.options
        self.assertEqual(len(opts), 2)
        self.assertIsInstance(opts[0], RouterAlertOption)
        self.assertIsInstance(opts[1], JumboPayloadOption)

    def test_parse_empty_options(self):
        hbh = HopByHopOptions(options=[])
        _, _, hdr = self._parse(hbh)
        assert hdr is not None
        assert hdr.hop_by_hop is not None
        self.assertEqual(hdr.hop_by_hop.options, [])

    def test_parse_next_header_reflects_transport(self):
        hbh = HopByHopOptions(options=[RouterAlertOption(0)])
        _, _, hdr = self._parse(hbh, transport_proto=17)
        assert hdr is not None
        self.assertEqual(hdr.next_header, 17)

    def test_malformed_hbh_too_short(self):
        # Build a packet where the advertised HBH size exceeds available bytes.
        # hdr_ext_len=1 means total=16 bytes, but we'll truncate the packet.
        raw_hbh = bytes([17, 1]) + b"\x00" * 6  # claims 16 bytes total but only 8 here
        ip_raw = _build_ipv6_header(
            IPv6Header("::1", "::2", next_header=0),
            raw_hbh,
        )
        truncated = ip_raw + raw_hbh   # only 8 HBH bytes, hdr says 16
        size, proto, hdr = packet_parser(truncated)
        self.assertEqual(size, 0)
        self.assertIsNone(proto)
        self.assertIsNone(hdr)

    def test_no_hop_by_hop_when_not_present(self):
        raw = _build_ipv6_header(IPv6Header("::1", "::2", 17), b"\x00" * 8)
        raw += b"\x00" * 8
        _, _, hdr = packet_parser(raw)
        assert hdr is not None
        self.assertIsNone(hdr.hop_by_hop)


# ── round-trip ────────────────────────────────────────────────────────────────

class TestHopByHopRoundTrip(unittest.TestCase):

    def _roundtrip(self, options: list) -> list:
        hbh = HopByHopOptions(options=options)
        raw = _ipv6_hbh_packet(hbh, transport_proto=17)
        _, _, hdr = packet_parser(raw)
        assert hdr is not None and hdr.hop_by_hop is not None
        return hdr.hop_by_hop.options

    def test_roundtrip_router_alert(self):
        result = self._roundtrip([RouterAlertOption(value=2)])
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], RouterAlertOption)
        self.assertEqual(result[0].value, 2)

    def test_roundtrip_jumbo_payload(self):
        result = self._roundtrip([JumboPayloadOption(jumbo_length=131_072)])
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], JumboPayloadOption)
        self.assertEqual(result[0].jumbo_length, 131_072)

    def test_roundtrip_raw_option(self):
        result = self._roundtrip([RawOption(0x22, b"\x01\x02\x03\x04")])
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], RawOption)
        self.assertEqual(result[0].option_type, 0x22)
        self.assertEqual(result[0].data, b"\x01\x02\x03\x04")


# ── PacketBuilder integration ─────────────────────────────────────────────────

class TestPacketBuilderHopByHop(unittest.TestCase):

    def test_build_produces_correct_next_header(self):
        pkt = (PacketBuilder()
               .ip(src="::1", dst="::2")
               .hop_by_hop_options([RouterAlertOption(value=0)])
               .udp()
               .build())
        # IPv6 next_header (byte 6) must be 0 (HBH)
        self.assertEqual(pkt[6], HBH_NEXT_HEADER)

    def test_hbh_next_header_points_to_udp(self):
        pkt = (PacketBuilder()
               .ip(src="::1", dst="::2")
               .hop_by_hop_options([RouterAlertOption(value=0)])
               .udp()
               .build())
        # HBH extension header starts at byte 40; byte 40 = next_header = 17 (UDP)
        self.assertEqual(pkt[40], 17)

    def test_build_and_parse_router_alert(self):
        pkt = (PacketBuilder()
               .ip(src="::1", dst="::2")
               .hop_by_hop_options([RouterAlertOption(value=0)])
               .udp()
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_RAW)
        assert parsed.ip is not None
        assert parsed.ip.hop_by_hop is not None
        opts = parsed.ip.hop_by_hop.options
        self.assertEqual(len(opts), 1)
        self.assertIsInstance(opts[0], RouterAlertOption)
        self.assertEqual(opts[0].value, 0)

    def test_build_and_parse_transport_reached(self):
        pkt = (PacketBuilder()
               .ip(src="::1", dst="::2")
               .hop_by_hop_options([RouterAlertOption(value=0)])
               .udp(dst_port=9999)
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_RAW)
        assert parsed.transport is not None
        from packeteer.generate.udp import UDPHeader
        self.assertIsInstance(parsed.transport, UDPHeader)
        self.assertEqual(parsed.transport.dst_port, 9999)

    def test_build_with_ethernet(self):
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="::1", dst="::2")
               .hop_by_hop_options([RouterAlertOption(value=1)])
               .tcp(dst_port=443)
               .build())
        parsed = parse_packet(pkt)
        assert parsed.ip is not None
        assert parsed.ip.hop_by_hop is not None
        self.assertEqual(parsed.ip.hop_by_hop.options[0].value, 1)

    def test_payload_length_includes_hbh(self):
        pkt = (PacketBuilder()
               .ip(src="::1", dst="::2")
               .hop_by_hop_options([RouterAlertOption(value=0)])
               .udp()
               .build())
        payload_length = struct.unpack("!H", pkt[4:6])[0]
        # HBH (8 bytes) + UDP (8 bytes) = 16
        self.assertEqual(payload_length, 16)

    def test_default_empty_options(self):
        pkt = (PacketBuilder()
               .ip(src="::1", dst="::2")
               .hop_by_hop_options()
               .udp()
               .build())
        # Should not raise; HBH header still present with all-padding
        self.assertEqual(pkt[6], HBH_NEXT_HEADER)


# ── config serialization ──────────────────────────────────────────────────────

class TestHopByHopConfigSerialisation(unittest.TestCase):

    def _cfg(self, hdr: IPv6Header) -> dict:
        return update_config({}, hdr)

    def test_router_alert_serialised(self):
        hdr = IPv6Header("::1", "::2", 17,
                         hop_by_hop=HopByHopOptions([RouterAlertOption(value=0)]))
        cfg = self._cfg(hdr)
        self.assertIn("hop_by_hop_options", cfg["network"])
        opts = cfg["network"]["hop_by_hop_options"]
        self.assertEqual(opts, [{"type": "router_alert", "value": 0}])

    def test_jumbo_payload_serialised(self):
        hdr = IPv6Header("::1", "::2", 17,
                         hop_by_hop=HopByHopOptions([JumboPayloadOption(70_000)]))
        cfg = self._cfg(hdr)
        opts = cfg["network"]["hop_by_hop_options"]
        self.assertEqual(opts, [{"type": "jumbo_payload", "jumbo_length": 70_000}])

    def test_raw_option_serialised(self):
        hdr = IPv6Header("::1", "::2", 17,
                         hop_by_hop=HopByHopOptions([RawOption(0x11, b"\xca\xfe")]))
        cfg = self._cfg(hdr)
        opts = cfg["network"]["hop_by_hop_options"]
        self.assertEqual(opts, [{"type": "raw", "option_type": 0x11, "data": "cafe"}])

    def test_no_hop_by_hop_field_when_absent(self):
        hdr = IPv6Header("::1", "::2", 17)
        cfg = self._cfg(hdr)
        self.assertNotIn("hop_by_hop_options", cfg["network"])

    def test_multiple_options_serialised(self):
        hdr = IPv6Header("::1", "::2", 17,
                         hop_by_hop=HopByHopOptions([
                             RouterAlertOption(1),
                             JumboPayloadOption(80_000),
                         ]))
        cfg = self._cfg(hdr)
        opts = cfg["network"]["hop_by_hop_options"]
        self.assertEqual(len(opts), 2)
        self.assertEqual(opts[0]["type"], "router_alert")
        self.assertEqual(opts[1]["type"], "jumbo_payload")


if __name__ == "__main__":
    unittest.main()
