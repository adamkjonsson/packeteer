from __future__ import annotations

import struct
import unittest

from packeteer.generate.ethernet import (
    EthernetHeader,
    VLANTag,
    build_ethernet_header,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    ETHERTYPE_8021Q,
)
from packeteer.parse.vlan import packet_parser


DST = "aa:bb:cc:dd:ee:ff"
SRC = "11:22:33:44:55:66"

# Offset within a tagged Ethernet frame where the VLAN tag (TCI + inner
# EtherType) begins — right after dst(6) + src(6) + TPID(2).
_VLAN_OFFSET = 14


def _vlan_bytes(
    vid: int = 10, pcp: int = 0, dei: int = 0, ethertype: int = ETHERTYPE_IPV4,
) -> bytes:
    """Return just the 4-byte VLAN tag portion (TCI + inner EtherType)."""
    raw = build_ethernet_header(
        EthernetHeader(DST, SRC, ethertype, VLANTag(vid=vid, pcp=pcp, dei=dei))
    )
    return raw[_VLAN_OFFSET:]


class TestPacketParserVLAN(unittest.TestCase):
    def test_returns_4_bytes(self):
        size, _, tag = packet_parser(_vlan_bytes())
        self.assertEqual(size, 4)

    def test_inner_ethertype_ipv4(self):
        _, proto, tag = packet_parser(_vlan_bytes(ethertype=ETHERTYPE_IPV4))
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_inner_ethertype_ipv6(self):
        _, proto, tag = packet_parser(_vlan_bytes(ethertype=ETHERTYPE_IPV6))
        self.assertEqual(proto, ETHERTYPE_IPV6)

    def test_various_vids(self):
        for vid in (0, 1, 100, 1000, 4094):
            with self.subTest(vid=vid):
                size, proto, tag = packet_parser(_vlan_bytes(vid=vid))
                self.assertEqual(size, 4)
                self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_max_pcp(self):
        size, _, tag = packet_parser(_vlan_bytes(vid=1, pcp=7))
        self.assertEqual(size, 4)

    def test_dei_set(self):
        size, _, tag = packet_parser(_vlan_bytes(vid=1, dei=1))
        self.assertEqual(size, 4)

    def test_extra_payload_ignored(self):
        size, proto, tag = packet_parser(_vlan_bytes() + b"\xff" * 20)
        self.assertEqual(size, 4)
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_tag_is_vlan_tag_instance(self):
        _, _, tag = packet_parser(_vlan_bytes())
        self.assertIsInstance(tag, VLANTag)

    def test_tag_vid(self):
        _, _, tag = packet_parser(_vlan_bytes(vid=42))
        self.assertEqual(tag.vid, 42)

    def test_tag_pcp(self):
        _, _, tag = packet_parser(_vlan_bytes(vid=1, pcp=6))
        self.assertEqual(tag.pcp, 6)

    def test_tag_dei(self):
        _, _, tag = packet_parser(_vlan_bytes(vid=1, dei=1))
        self.assertEqual(tag.dei, 1)


class TestPacketParserVLANFailure(unittest.TestCase):
    def test_empty_bytes(self):
        self.assertEqual(packet_parser(b""), (0, None, None))

    def test_too_short(self):
        self.assertEqual(packet_parser(b"\x00" * 3), (0, None, None))

    def test_exactly_4_bytes_succeeds(self):
        size, proto, tag = packet_parser(_vlan_bytes())
        self.assertNotEqual(size, 0)
        self.assertIsNotNone(proto)
        self.assertIsNotNone(tag)


class TestParserVLANGeneratorRoundtrip(unittest.TestCase):
    """Verify that packeteer.parse.vlan and packeteer.generate.ethernet are compatible."""

    def _roundtrip(self, vid: int, pcp: int, dei: int, ethertype: int) -> tuple:
        raw_frame = build_ethernet_header(
            EthernetHeader(DST, SRC, ethertype, VLANTag(vid=vid, pcp=pcp, dei=dei))
        )
        vlan_data = raw_frame[_VLAN_OFFSET:]
        size, proto, tag = packet_parser(vlan_data)
        return raw_frame, size, proto, tag

    def test_size_is_always_4(self):
        _, size, _, tag = self._roundtrip(10, 0, 0, ETHERTYPE_IPV4)
        self.assertEqual(size, 4)

    def test_proto_matches_ethertype_ipv4(self):
        _, _, proto, tag = self._roundtrip(10, 0, 0, ETHERTYPE_IPV4)
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_proto_matches_ethertype_ipv6(self):
        _, _, proto, tag = self._roundtrip(200, 3, 1, ETHERTYPE_IPV6)
        self.assertEqual(proto, ETHERTYPE_IPV6)

    def test_tci_fields_round_trip(self):
        """TCI encoded by VLANTag.tci() must decode back to the same fields."""
        for vid, pcp, dei in [(1, 0, 0), (42, 5, 1), (4094, 7, 1)]:
            with self.subTest(vid=vid, pcp=pcp, dei=dei):
                vlan_bytes = _vlan_bytes(vid=vid, pcp=pcp, dei=dei)
                tci = struct.unpack("!H", vlan_bytes[0:2])[0]
                self.assertEqual((tci >> 13) & 0x7, pcp)
                self.assertEqual((tci >> 12) & 0x1, dei)
                self.assertEqual(tci & 0xFFF, vid)

    def test_vlan_tag_offset_aligns_with_ethernet_parser(self):
        """Bytes at _VLAN_OFFSET in a tagged frame must be valid VLAN input."""
        raw_frame = build_ethernet_header(
            EthernetHeader(DST, SRC, ETHERTYPE_IPV4, VLANTag(vid=99))
        )
        outer_ethertype = struct.unpack("!H", raw_frame[12:14])[0]
        self.assertEqual(outer_ethertype, ETHERTYPE_8021Q)
        size, proto, tag = packet_parser(raw_frame[_VLAN_OFFSET:])
        self.assertEqual(size, 4)
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_parser_consumes_exactly_4_bytes(self):
        payload = b"\xde\xad\xbe\xef" * 10
        vlan_data = _vlan_bytes() + payload
        size, _, tag = packet_parser(vlan_data)
        self.assertEqual(vlan_data[size:], payload)

    def test_roundtrip_tag_equals_original(self):
        for vid, pcp, dei in [(1, 0, 0), (42, 5, 1), (4094, 7, 1)]:
            with self.subTest(vid=vid, pcp=pcp, dei=dei):
                _, _, proto, tag = self._roundtrip(vid, pcp, dei, ETHERTYPE_IPV4)
                self.assertEqual(tag.vid, vid)
                self.assertEqual(tag.pcp, pcp)
                self.assertEqual(tag.dei, dei)


if __name__ == "__main__":
    unittest.main()
