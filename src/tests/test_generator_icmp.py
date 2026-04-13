import struct
import socket
import unittest
from packeteer.generator.icmpv6 import ICMPv6Header, build_icmpv6_header
from packeteer.generator.checksum import ones_complement_checksum


def _verify_icmpv6_checksum(src_ip, dst_ip, icmpv6_bytes, payload):
    icmpv6_length = len(icmpv6_bytes) + len(payload)
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', icmpv6_length, b'\x00\x00\x00', 58)
    )
    return ones_complement_checksum(pseudo + icmpv6_bytes + payload)


class TestICMPv6Header(unittest.TestCase):
    def test_length(self):
        raw = build_icmpv6_header(ICMPv6Header(), b'', "::1", "::2")
        self.assertEqual(len(raw), 8)

    def test_type_echo_request(self):
        raw = build_icmpv6_header(ICMPv6Header(), b'', "::1", "::2")
        self.assertEqual(raw[0], 128)

    def test_code_zero(self):
        raw = build_icmpv6_header(ICMPv6Header(), b'', "::1", "::2")
        self.assertEqual(raw[1], 0)

    def test_checksum_no_payload(self):
        raw = build_icmpv6_header(ICMPv6Header(), b'', "::1", "::2")
        self.assertEqual(_verify_icmpv6_checksum("::1", "::2", raw, b''), 0)

    def test_checksum_with_payload(self):
        payload = b'ping data'
        raw = build_icmpv6_header(ICMPv6Header(), payload, "fe80::1", "fe80::2")
        self.assertEqual(_verify_icmpv6_checksum("fe80::1", "fe80::2", raw, payload), 0)


if __name__ == '__main__':
    unittest.main()
