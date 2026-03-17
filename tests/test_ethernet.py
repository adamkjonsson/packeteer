import struct
import unittest
from packet_generator.ethernet import (
    EthernetHeader, VLANTag, build_ethernet_header,
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_8021Q,
)


class TestEthernetHeader(unittest.TestCase):
    def test_length(self):
        hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        self.assertEqual(len(build_ethernet_header(hdr)), 14)

    def test_dst_mac(self):
        hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "00:00:00:00:00:00", ETHERTYPE_IPV4)
        raw = build_ethernet_header(hdr)
        self.assertEqual(raw[:6], bytes.fromhex('aabbccddeeff'))

    def test_src_mac(self):
        hdr = EthernetHeader("00:00:00:00:00:00", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        raw = build_ethernet_header(hdr)
        self.assertEqual(raw[6:12], bytes.fromhex('112233445566'))

    def test_ethertype_ipv4(self):
        hdr = EthernetHeader("00:00:00:00:00:01", "00:00:00:00:00:02", ETHERTYPE_IPV4)
        raw = build_ethernet_header(hdr)
        self.assertEqual(struct.unpack('!H', raw[12:14])[0], 0x0800)

    def test_ethertype_ipv6(self):
        hdr = EthernetHeader("00:00:00:00:00:01", "00:00:00:00:00:02", ETHERTYPE_IPV6)
        raw = build_ethernet_header(hdr)
        self.assertEqual(struct.unpack('!H', raw[12:14])[0], 0x86DD)

    def test_hyphen_mac(self):
        hdr = EthernetHeader("aa-bb-cc-dd-ee-ff", "00:00:00:00:00:00", ETHERTYPE_IPV4)
        raw = build_ethernet_header(hdr)
        self.assertEqual(raw[:6], bytes.fromhex('aabbccddeeff'))


class TestVLANTag(unittest.TestCase):
    def test_tci_vid_only(self):
        tag = VLANTag(vid=100)
        self.assertEqual(tag.tci(), 100)

    def test_tci_with_pcp(self):
        # PCP=5, DEI=0, VID=200  →  (5 << 13) | 200 = 0xA0C8
        tag = VLANTag(vid=200, pcp=5)
        self.assertEqual(tag.tci(), (5 << 13) | 200)

    def test_tci_with_dei(self):
        tag = VLANTag(vid=10, dei=1)
        self.assertEqual(tag.tci(), (1 << 12) | 10)

    def test_tci_all_fields(self):
        tag = VLANTag(vid=4094, pcp=7, dei=1)
        self.assertEqual(tag.tci(), (7 << 13) | (1 << 12) | 4094)

    def test_invalid_vid(self):
        with self.assertRaises(ValueError):
            VLANTag(vid=4096)
        with self.assertRaises(ValueError):
            VLANTag(vid=-1)

    def test_invalid_pcp(self):
        with self.assertRaises(ValueError):
            VLANTag(vid=1, pcp=8)

    def test_invalid_dei(self):
        with self.assertRaises(ValueError):
            VLANTag(vid=1, dei=2)


class TestEthernetHeaderVLAN(unittest.TestCase):
    def _tagged(self, vid=10, pcp=0, dei=0, ethertype=ETHERTYPE_IPV4):
        hdr = EthernetHeader(
            "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
            ethertype, VLANTag(vid=vid, pcp=pcp, dei=dei),
        )
        return build_ethernet_header(hdr)

    def test_length_with_vlan(self):
        self.assertEqual(len(self._tagged()), 18)

    def test_outer_ethertype_is_8021q(self):
        raw = self._tagged()
        self.assertEqual(struct.unpack('!H', raw[12:14])[0], ETHERTYPE_8021Q)

    def test_inner_ethertype_ipv4(self):
        raw = self._tagged(ethertype=ETHERTYPE_IPV4)
        self.assertEqual(struct.unpack('!H', raw[16:18])[0], ETHERTYPE_IPV4)

    def test_inner_ethertype_ipv6(self):
        raw = self._tagged(ethertype=ETHERTYPE_IPV6)
        self.assertEqual(struct.unpack('!H', raw[16:18])[0], ETHERTYPE_IPV6)

    def test_tci_vid(self):
        raw = self._tagged(vid=42)
        tci = struct.unpack('!H', raw[14:16])[0]
        self.assertEqual(tci & 0x0FFF, 42)

    def test_tci_pcp(self):
        raw = self._tagged(vid=1, pcp=6)
        tci = struct.unpack('!H', raw[14:16])[0]
        self.assertEqual((tci >> 13) & 0x7, 6)

    def test_tci_dei(self):
        raw = self._tagged(vid=1, dei=1)
        tci = struct.unpack('!H', raw[14:16])[0]
        self.assertEqual((tci >> 12) & 0x1, 1)

    def test_mac_addresses_preserved(self):
        raw = self._tagged()
        self.assertEqual(raw[:6], bytes.fromhex('aabbccddeeff'))
        self.assertEqual(raw[6:12], bytes.fromhex('112233445566'))

    def test_no_vlan_tag_unchanged(self):
        hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        raw = build_ethernet_header(hdr)
        self.assertEqual(len(raw), 14)
        self.assertEqual(struct.unpack('!H', raw[12:14])[0], ETHERTYPE_IPV4)


if __name__ == '__main__':
    unittest.main()
