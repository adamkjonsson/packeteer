import unittest

from packeteer.generate.checksum import ones_complement_checksum


class TestChecksum(unittest.TestCase):
    def test_all_zeros(self):
        result = ones_complement_checksum(b'\x00\x00')
        self.assertEqual(result, 0xFFFF)

    def test_odd_length_padded(self):
        # Padding a single byte \x01 should give same result as \x01\x00
        self.assertEqual(
            ones_complement_checksum(b'\x01'),
            ones_complement_checksum(b'\x01\x00'),
        )

    def test_rfc1071_example(self):
        # Verification: checksum of data + checksum over data should equal 0
        data = b'\x00\x01\xf2\x03\xf4\xf5\xf6\xf7'
        cksum = ones_complement_checksum(data)
        import struct
        verify = ones_complement_checksum(data + struct.pack('!H', cksum))
        self.assertEqual(verify, 0)

    def test_known_ip_header(self):
        # Build a header ourselves and verify the checksum round-trips to 0
        from packeteer.generate.ip import IPHeader, _build_ip_header
        raw = _build_ip_header(IPHeader("192.168.0.1", "10.0.0.1", 6), b'\x00' * 20)
        self.assertEqual(ones_complement_checksum(raw), 0)


if __name__ == '__main__':
    unittest.main()
