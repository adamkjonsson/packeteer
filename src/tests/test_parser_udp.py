import struct
import unittest

from packet_generator.udp import UDPHeader, build_udp_header
from packet_parser.udp import packet_parser


def _udp(src_port=5000, dst_port=53, payload=b"", ip_version=4) -> bytes:
    src_ip = "10.0.0.1" if ip_version == 4 else "::1"
    dst_ip = "10.0.0.2" if ip_version == 4 else "::2"
    return build_udp_header(UDPHeader(src_port, dst_port), payload, src_ip, dst_ip, ip_version)


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------

class TestParserUDP(unittest.TestCase):
    def test_header_size(self):
        size, _, hdr = packet_parser(_udp())
        self.assertEqual(size, 8)

    def test_dst_port(self):
        _, dst_port, hdr = packet_parser(_udp(dst_port=53))
        self.assertEqual(dst_port, 53)

    def test_dst_port_http(self):
        _, dst_port, hdr = packet_parser(_udp(dst_port=80))
        self.assertEqual(dst_port, 80)

    def test_dst_port_min(self):
        _, dst_port, hdr = packet_parser(_udp(dst_port=0))
        self.assertEqual(dst_port, 0)

    def test_dst_port_max(self):
        _, dst_port, hdr = packet_parser(_udp(dst_port=65535))
        self.assertEqual(dst_port, 65535)

    def test_extra_payload_ignored(self):
        size, dst_port, hdr = packet_parser(_udp(dst_port=443) + b"\xff" * 100)
        self.assertEqual(size, 8)
        self.assertEqual(dst_port, 443)

    def test_various_src_ports(self):
        for src in (1024, 32768, 65535):
            with self.subTest(src_port=src):
                size, _, hdr = packet_parser(_udp(src_port=src))
                self.assertEqual(size, 8)

    def test_ipv6_pseudo_header_same_result(self):
        _, dst_v4, _ = packet_parser(_udp(dst_port=53, ip_version=4))
        _, dst_v6, _ = packet_parser(_udp(dst_port=53, ip_version=6))
        self.assertEqual(dst_v4, dst_v6)

    def test_header_is_udp_header_instance(self):
        _, _, hdr = packet_parser(_udp())
        self.assertIsInstance(hdr, UDPHeader)

    def test_header_src_port(self):
        _, _, hdr = packet_parser(_udp(src_port=12345))
        self.assertEqual(hdr.src_port, 12345)

    def test_header_dst_port(self):
        _, _, hdr = packet_parser(_udp(dst_port=53))
        self.assertEqual(hdr.dst_port, 53)


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------

class TestParserUDPFailure(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(packet_parser(b""), (0, None, None))

    def test_too_short(self):
        self.assertEqual(packet_parser(_udp()[:7]), (0, None, None))

    def test_exactly_8_bytes_succeeds(self):
        size, dst_port, hdr = packet_parser(_udp())
        self.assertEqual(size, 8)
        self.assertIsNotNone(dst_port)
        self.assertIsNotNone(hdr)

    def test_length_field_below_8(self):
        raw = struct.pack("!HHHH", 1234, 53, 7, 0)
        self.assertEqual(packet_parser(raw), (0, None, None))


# ---------------------------------------------------------------------------
# Roundtrip: packet_generator → packet_parser
# ---------------------------------------------------------------------------

class TestParserUDPRoundtrip(unittest.TestCase):
    def test_dst_port_matches_generator(self):
        for port in (53, 80, 443, 8080, 65535):
            with self.subTest(dst_port=port):
                raw = _udp(dst_port=port)
                _, parsed_port, hdr = packet_parser(raw)
                self.assertEqual(parsed_port, port)

    def test_dst_port_matches_raw_bytes(self):
        raw = _udp(dst_port=5353)
        _, parsed_port, hdr = packet_parser(raw)
        self.assertEqual(parsed_port, struct.unpack("!H", raw[2:4])[0])

    def test_consumes_exactly_8_bytes(self):
        payload = b"\xde\xad\xbe\xef" * 10
        raw = _udp(payload=payload) + payload
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, 8)

    def test_ipv4_and_ipv6_roundtrip(self):
        for ip_version in (4, 6):
            with self.subTest(ip_version=ip_version):
                raw = _udp(dst_port=123, ip_version=ip_version)
                size, dst_port, hdr = packet_parser(raw)
                self.assertEqual(size, 8)
                self.assertEqual(dst_port, 123)

    def test_length_field_reflects_payload(self):
        payload = b"hello"
        raw = _udp(payload=payload)
        length = struct.unpack("!H", raw[4:6])[0]
        self.assertEqual(length, 8 + len(payload))

    def test_roundtrip_header_equals_original(self):
        orig = UDPHeader(src_port=54321, dst_port=8080)
        raw = build_udp_header(orig, b"", "10.0.0.1", "10.0.0.2")
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.src_port, orig.src_port)
        self.assertEqual(hdr.dst_port, orig.dst_port)


if __name__ == "__main__":
    unittest.main()
