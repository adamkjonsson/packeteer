import struct
import unittest
from packet_generator.ethernet import (
    EthernetHeader, build_ethernet_header, ETHERTYPE_IPV4, ETHERTYPE_IPV6,
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


if __name__ == '__main__':
    unittest.main()
