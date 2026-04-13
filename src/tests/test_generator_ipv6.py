import struct
import unittest
from packeteer.generator.ipv6 import IPv6Header, build_ipv6_header


class TestIPv6Header(unittest.TestCase):
    def _make(self, payload=b''):
        return build_ipv6_header(IPv6Header("::1", "::2", 6), payload)

    def test_length(self):
        self.assertEqual(len(self._make()), 40)

    def test_version(self):
        raw = self._make()
        version = (struct.unpack('!I', raw[:4])[0] >> 28) & 0xF
        self.assertEqual(version, 6)

    def test_payload_length_empty(self):
        raw = self._make(b'')
        pl = struct.unpack('!H', raw[4:6])[0]
        self.assertEqual(pl, 0)

    def test_payload_length_with_data(self):
        raw = self._make(b'\x00' * 30)
        pl = struct.unpack('!H', raw[4:6])[0]
        self.assertEqual(pl, 30)

    def test_next_header(self):
        raw = self._make()
        self.assertEqual(raw[6], 6)  # TCP

    def test_hop_limit_default(self):
        raw = self._make()
        self.assertEqual(raw[7], 64)

    def test_src_dst_addresses(self):
        import socket
        raw = self._make()
        self.assertEqual(raw[8:24], socket.inet_pton(socket.AF_INET6, "::1"))
        self.assertEqual(raw[24:40], socket.inet_pton(socket.AF_INET6, "::2"))


if __name__ == '__main__':
    unittest.main()
