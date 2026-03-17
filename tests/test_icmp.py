import unittest
from packet_generator.icmp import ICMPHeader, build_icmp_header
from packet_generator.checksum import ones_complement_checksum


class TestICMPHeader(unittest.TestCase):
    def test_length(self):
        raw = build_icmp_header(ICMPHeader(), b'')
        self.assertEqual(len(raw), 8)

    def test_type_code(self):
        raw = build_icmp_header(ICMPHeader(type=8, code=0), b'')
        self.assertEqual(raw[0], 8)
        self.assertEqual(raw[1], 0)

    def test_checksum_no_payload(self):
        raw = build_icmp_header(ICMPHeader(), b'')
        self.assertEqual(ones_complement_checksum(raw), 0)

    def test_checksum_with_payload(self):
        payload = b'hello world'
        raw = build_icmp_header(ICMPHeader(), payload)
        self.assertEqual(ones_complement_checksum(raw + payload), 0)

    def test_custom_type(self):
        raw = build_icmp_header(ICMPHeader(type=0, code=0), b'')
        self.assertEqual(raw[0], 0)


if __name__ == '__main__':
    unittest.main()
