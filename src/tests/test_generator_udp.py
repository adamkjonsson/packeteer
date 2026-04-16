from __future__ import annotations

import struct
import socket
import unittest
from packeteer.generate.udp import UDPHeader, build_udp_header
from packeteer.generate.checksum import ones_complement_checksum


def _verify_udp_checksum_v4(src_ip: str, dst_ip: str, udp_bytes: bytes, payload: bytes) -> int:
    udp_length = len(udp_bytes) + len(payload)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 17, udp_length)
    )
    return ones_complement_checksum(pseudo + udp_bytes + payload)


def _verify_udp_checksum_v6(src_ip: str, dst_ip: str, udp_bytes: bytes, payload: bytes) -> int:
    udp_length = len(udp_bytes) + len(payload)
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', udp_length, b'\x00\x00\x00', 17)
    )
    return ones_complement_checksum(pseudo + udp_bytes + payload)


class TestUDPHeader(unittest.TestCase):
    def test_length(self):
        raw = build_udp_header(UDPHeader(1234, 53), b'', "1.2.3.4", "5.6.7.8")
        self.assertEqual(len(raw), 8)

    def test_udp_length_field(self):
        payload = b'\x00' * 10
        raw = build_udp_header(UDPHeader(1234, 53), payload, "1.2.3.4", "5.6.7.8")
        length = struct.unpack('!H', raw[4:6])[0]
        self.assertEqual(length, 18)

    def test_checksum_v4(self):
        payload = b'query'
        raw = build_udp_header(UDPHeader(5000, 53), payload, "192.168.1.1", "8.8.8.8")
        self.assertEqual(_verify_udp_checksum_v4("192.168.1.1", "8.8.8.8", raw, payload), 0)

    def test_checksum_v6(self):
        payload = b'data'
        raw = build_udp_header(UDPHeader(5000, 53), payload, "::1", "::2", ip_version=6)
        self.assertEqual(_verify_udp_checksum_v6("::1", "::2", raw, payload), 0)

    def test_zero_payload(self):
        raw = build_udp_header(UDPHeader(1000, 2000), b'', "1.2.3.4", "5.6.7.8")
        self.assertEqual(len(raw), 8)
        length = struct.unpack('!H', raw[4:6])[0]
        self.assertEqual(length, 8)


if __name__ == '__main__':
    unittest.main()
