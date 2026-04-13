import unittest

from packeteer.generator.ethernet import (
    EthernetHeader,
    VLANTag,
    build_ethernet_header,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    ETHERTYPE_8021Q,
)
from packeteer.parser.ethernet import packet_parser


DST = "aa:bb:cc:dd:ee:ff"
SRC = "11:22:33:44:55:66"


def _plain(ethertype=ETHERTYPE_IPV4) -> bytes:
    return build_ethernet_header(EthernetHeader(DST, SRC, ethertype))


def _tagged(vid=10, pcp=0, dei=0, ethertype=ETHERTYPE_IPV4) -> bytes:
    return build_ethernet_header(
        EthernetHeader(DST, SRC, ethertype, VLANTag(vid=vid, pcp=pcp, dei=dei))
    )


class TestPacketParserPlain(unittest.TestCase):
    def test_returns_14_for_ipv4(self):
        size, proto, hdr = packet_parser(_plain(ETHERTYPE_IPV4))
        self.assertEqual(size, 14)

    def test_returns_ipv4_ethertype(self):
        size, proto, hdr = packet_parser(_plain(ETHERTYPE_IPV4))
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_returns_14_for_ipv6(self):
        size, proto, hdr = packet_parser(_plain(ETHERTYPE_IPV6))
        self.assertEqual(size, 14)

    def test_returns_ipv6_ethertype(self):
        size, proto, hdr = packet_parser(_plain(ETHERTYPE_IPV6))
        self.assertEqual(proto, ETHERTYPE_IPV6)

    def test_extra_payload_bytes_ignored(self):
        size, proto, hdr = packet_parser(_plain() + b"\x00" * 46)
        self.assertEqual(size, 14)
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_header_is_ethernet_header_instance(self):
        _, _, hdr = packet_parser(_plain())
        self.assertIsInstance(hdr, EthernetHeader)

    def test_header_dst_mac(self):
        _, _, hdr = packet_parser(_plain())
        self.assertEqual(hdr.dst_mac, DST)

    def test_header_src_mac(self):
        _, _, hdr = packet_parser(_plain())
        self.assertEqual(hdr.src_mac, SRC)

    def test_header_ethertype_ipv4(self):
        _, _, hdr = packet_parser(_plain(ETHERTYPE_IPV4))
        self.assertEqual(hdr.ethertype, ETHERTYPE_IPV4)

    def test_header_ethertype_ipv6(self):
        _, _, hdr = packet_parser(_plain(ETHERTYPE_IPV6))
        self.assertEqual(hdr.ethertype, ETHERTYPE_IPV6)

    def test_header_no_vlan_tag(self):
        _, _, hdr = packet_parser(_plain())
        self.assertIsNone(hdr.vlan_tag)


class TestPacketParserVLAN(unittest.TestCase):
    def test_returns_18_for_tagged(self):
        size, proto, hdr = packet_parser(_tagged())
        self.assertEqual(size, 18)

    def test_returns_inner_ethertype_ipv4(self):
        size, proto, hdr = packet_parser(_tagged(ethertype=ETHERTYPE_IPV4))
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_returns_inner_ethertype_ipv6(self):
        size, proto, hdr = packet_parser(_tagged(ethertype=ETHERTYPE_IPV6))
        self.assertEqual(proto, ETHERTYPE_IPV6)

    def test_various_vids(self):
        for vid in (1, 100, 1000, 4094):
            with self.subTest(vid=vid):
                size, proto, hdr = packet_parser(_tagged(vid=vid))
                self.assertEqual(size, 18)
                self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_pcp_and_dei_do_not_affect_result(self):
        size, proto, hdr = packet_parser(_tagged(vid=42, pcp=7, dei=1))
        self.assertEqual(size, 18)
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_header_has_vlan_tag(self):
        _, _, hdr = packet_parser(_tagged(vid=10))
        self.assertIsNotNone(hdr.vlan_tag)

    def test_header_vlan_vid(self):
        _, _, hdr = packet_parser(_tagged(vid=42))
        self.assertEqual(hdr.vlan_tag.vid, 42)

    def test_header_vlan_pcp(self):
        _, _, hdr = packet_parser(_tagged(vid=1, pcp=5))
        self.assertEqual(hdr.vlan_tag.pcp, 5)

    def test_header_vlan_dei(self):
        _, _, hdr = packet_parser(_tagged(vid=1, dei=1))
        self.assertEqual(hdr.vlan_tag.dei, 1)

    def test_header_inner_ethertype(self):
        _, _, hdr = packet_parser(_tagged(ethertype=ETHERTYPE_IPV6))
        self.assertEqual(hdr.ethertype, ETHERTYPE_IPV6)

    def test_header_mac_addresses(self):
        _, _, hdr = packet_parser(_tagged())
        self.assertEqual(hdr.dst_mac, DST)
        self.assertEqual(hdr.src_mac, SRC)


class TestPacketParserFailure(unittest.TestCase):
    def test_empty_bytes(self):
        self.assertEqual(packet_parser(b""), (0, None, None))

    def test_too_short_for_plain(self):
        self.assertEqual(packet_parser(b"\x00" * 13), (0, None, None))

    def test_exactly_14_bytes_succeeds(self):
        size, proto, hdr = packet_parser(_plain())
        self.assertNotEqual(size, 0)

    def test_vlan_truncated_to_15_bytes(self):
        self.assertEqual(packet_parser(_tagged()[:15]), (0, None, None))


class TestParsorGeneratorRoundtrip(unittest.TestCase):
    """Verify that packet_parser.ethernet and packet_generator.ethernet are compatible."""

    def test_plain_ipv4_roundtrip(self):
        raw = _plain(ETHERTYPE_IPV4)
        size, proto, hdr = packet_parser(raw)
        self.assertEqual(size, len(raw))
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_plain_ipv6_roundtrip(self):
        raw = _plain(ETHERTYPE_IPV6)
        size, proto, hdr = packet_parser(raw)
        self.assertEqual(size, len(raw))
        self.assertEqual(proto, ETHERTYPE_IPV6)

    def test_tagged_ipv4_roundtrip(self):
        raw = _tagged(vid=100, pcp=3, dei=0, ethertype=ETHERTYPE_IPV4)
        size, proto, hdr = packet_parser(raw)
        self.assertEqual(size, len(raw))
        self.assertEqual(proto, ETHERTYPE_IPV4)

    def test_tagged_ipv6_roundtrip(self):
        raw = _tagged(vid=200, ethertype=ETHERTYPE_IPV6)
        size, proto, hdr = packet_parser(raw)
        self.assertEqual(size, len(raw))
        self.assertEqual(proto, ETHERTYPE_IPV6)

    def test_parser_consumes_exactly_the_header(self):
        payload = b"\xde\xad\xbe\xef" * 10
        raw = _plain() + payload
        size, _, hdr = packet_parser(raw)
        self.assertEqual(raw[size:], payload)

    def test_parser_consumes_exactly_the_vlan_header(self):
        payload = b"\xca\xfe\xba\xbe" * 10
        raw = _tagged() + payload
        size, _, hdr = packet_parser(raw)
        self.assertEqual(raw[size:], payload)

    def test_roundtrip_header_equals_original(self):
        orig = EthernetHeader(DST, SRC, ETHERTYPE_IPV4)
        _, _, hdr = packet_parser(build_ethernet_header(orig))
        self.assertEqual(hdr.dst_mac, orig.dst_mac)
        self.assertEqual(hdr.src_mac, orig.src_mac)
        self.assertEqual(hdr.ethertype, orig.ethertype)

    def test_roundtrip_vlan_header_equals_original(self):
        tag = VLANTag(vid=77, pcp=3, dei=1)
        orig = EthernetHeader(DST, SRC, ETHERTYPE_IPV6, tag)
        _, _, hdr = packet_parser(build_ethernet_header(orig))
        self.assertEqual(hdr.dst_mac, orig.dst_mac)
        self.assertEqual(hdr.src_mac, orig.src_mac)
        self.assertEqual(hdr.ethertype, orig.ethertype)
        self.assertEqual(hdr.vlan_tag.vid, tag.vid)
        self.assertEqual(hdr.vlan_tag.pcp, tag.pcp)
        self.assertEqual(hdr.vlan_tag.dei, tag.dei)


if __name__ == "__main__":
    unittest.main()
