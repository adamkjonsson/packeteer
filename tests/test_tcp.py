import struct
import socket
import unittest
from packet_generator.tcp import TCPHeader, build_tcp_header
from packet_generator.checksum import ones_complement_checksum


def _verify_tcp_checksum_v4(src_ip, dst_ip, tcp_bytes, payload):
    tcp_length = len(tcp_bytes) + len(payload)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 6, tcp_length)
    )
    return ones_complement_checksum(pseudo + tcp_bytes + payload)


def _verify_tcp_checksum_v6(src_ip, dst_ip, tcp_bytes, payload):
    tcp_length = len(tcp_bytes) + len(payload)
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', tcp_length, b'\x00\x00\x00', 6)
    )
    return ones_complement_checksum(pseudo + tcp_bytes + payload)


class TestTCPHeader(unittest.TestCase):
    def test_length(self):
        h = build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        self.assertEqual(len(h), 20)

    def test_data_offset(self):
        raw = build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        data_offset = (raw[12] >> 4) & 0xF
        self.assertEqual(data_offset, 5)

    def test_syn_flag_default(self):
        raw = build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        self.assertEqual(raw[13], 0x02)

    def test_checksum_v4(self):
        payload = b'hello'
        raw = build_tcp_header(TCPHeader(5000, 443), payload, "10.0.0.1", "10.0.0.2")
        self.assertEqual(_verify_tcp_checksum_v4("10.0.0.1", "10.0.0.2", raw, payload), 0)

    def test_checksum_v6(self):
        payload = b'world'
        raw = build_tcp_header(
            TCPHeader(5000, 443), payload, "fe80::1", "fe80::2", ip_version=6
        )
        self.assertEqual(_verify_tcp_checksum_v6("fe80::1", "fe80::2", raw, payload), 0)

    def test_ports(self):
        raw = build_tcp_header(TCPHeader(12345, 8080), b'', "1.2.3.4", "5.6.7.8")
        src, dst = struct.unpack('!HH', raw[:4])
        self.assertEqual(src, 12345)
        self.assertEqual(dst, 8080)


if __name__ == '__main__':
    unittest.main()
