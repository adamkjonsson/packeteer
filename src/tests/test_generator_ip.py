import struct
import unittest
from packeteer.generate.ip import IPHeader, build_ip_header
from packeteer.generate.checksum import ones_complement_checksum


class TestIPHeader(unittest.TestCase):
    def _make(self, payload=b''):
        return build_ip_header(IPHeader("192.168.1.1", "10.0.0.1", 6), payload)

    def test_length(self):
        self.assertEqual(len(self._make()), 20)

    def test_version_ihl(self):
        raw = self._make()
        self.assertEqual(raw[0], 0x45)

    def test_total_length(self):
        payload = b'\x00' * 40
        raw = build_ip_header(IPHeader("1.2.3.4", "5.6.7.8", 17), payload)
        total = struct.unpack('!H', raw[2:4])[0]
        self.assertEqual(total, 60)

    def test_checksum_valid(self):
        raw = self._make(b'\xab' * 20)
        self.assertEqual(ones_complement_checksum(raw), 0)

    def test_ttl_default(self):
        raw = self._make()
        self.assertEqual(raw[8], 64)

    def test_protocol_field(self):
        raw = self._make()
        self.assertEqual(raw[9], 6)  # TCP

    def test_src_dst_addresses(self):
        import socket
        raw = self._make()
        self.assertEqual(raw[12:16], socket.inet_aton("192.168.1.1"))
        self.assertEqual(raw[16:20], socket.inet_aton("10.0.0.1"))


if __name__ == '__main__':
    unittest.main()
