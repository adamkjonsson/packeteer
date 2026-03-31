import struct
import unittest

from packet_generator.icmp import ICMPHeader, build_icmp_header
from packet_generator.icmpv6 import ICMPv6Header, build_icmpv6_header
from packet_parser.icmp import packet_parser as parse_icmp
from packet_parser.icmpv6 import packet_parser as parse_icmpv6

TYPE_ECHO_REQUEST = 8
TYPE_ECHO_REPLY = 0
TYPE_DEST_UNREACHABLE = 3
TYPE_TIME_EXCEEDED = 11

TYPE_V6_ECHO_REQUEST = 128
TYPE_V6_ECHO_REPLY = 129
TYPE_V6_DEST_UNREACHABLE = 1
TYPE_V6_TIME_EXCEEDED = 3


def _icmp(type=TYPE_ECHO_REQUEST, code=0, identifier=1, sequence=1, payload=b"") -> bytes:
    return build_icmp_header(ICMPHeader(type, code, identifier, sequence), payload)


def _icmpv6(type=TYPE_V6_ECHO_REQUEST, code=0, identifier=1, sequence=1, payload=b"") -> bytes:
    return build_icmpv6_header(
        ICMPv6Header(type, code, identifier, sequence), payload, "::1", "::2"
    )


# ---------------------------------------------------------------------------
# ICMPv4
# ---------------------------------------------------------------------------

class TestParserICMPv4(unittest.TestCase):
    def test_header_size(self):
        size, _, hdr = parse_icmp(_icmp())
        self.assertEqual(size, 8)

    def test_type_echo_request(self):
        _, icmp_type, hdr = parse_icmp(_icmp(type=TYPE_ECHO_REQUEST))
        self.assertEqual(icmp_type, TYPE_ECHO_REQUEST)

    def test_type_echo_reply(self):
        _, icmp_type, hdr = parse_icmp(_icmp(type=TYPE_ECHO_REPLY))
        self.assertEqual(icmp_type, TYPE_ECHO_REPLY)

    def test_type_dest_unreachable(self):
        _, icmp_type, hdr = parse_icmp(_icmp(type=TYPE_DEST_UNREACHABLE))
        self.assertEqual(icmp_type, TYPE_DEST_UNREACHABLE)

    def test_type_time_exceeded(self):
        _, icmp_type, hdr = parse_icmp(_icmp(type=TYPE_TIME_EXCEEDED))
        self.assertEqual(icmp_type, TYPE_TIME_EXCEEDED)

    def test_extra_payload_ignored(self):
        size, icmp_type, hdr = parse_icmp(_icmp() + b"\xff" * 32)
        self.assertEqual(size, 8)
        self.assertEqual(icmp_type, TYPE_ECHO_REQUEST)

    def test_various_identifiers_and_sequences(self):
        for ident, seq in [(0, 0), (1, 1), (0xFFFF, 0xFFFF)]:
            with self.subTest(ident=ident, seq=seq):
                size, _, hdr = parse_icmp(_icmp(identifier=ident, sequence=seq))
                self.assertEqual(size, 8)

    def test_header_is_icmp_header_instance(self):
        _, _, hdr = parse_icmp(_icmp())
        self.assertIsInstance(hdr, ICMPHeader)

    def test_header_type(self):
        _, _, hdr = parse_icmp(_icmp(type=TYPE_ECHO_REQUEST))
        self.assertEqual(hdr.type, TYPE_ECHO_REQUEST)

    def test_header_code(self):
        _, _, hdr = parse_icmp(_icmp(type=TYPE_DEST_UNREACHABLE, code=3))
        self.assertEqual(hdr.code, 3)

    def test_header_identifier(self):
        _, _, hdr = parse_icmp(_icmp(identifier=0xABCD))
        self.assertEqual(hdr.identifier, 0xABCD)

    def test_header_sequence(self):
        _, _, hdr = parse_icmp(_icmp(sequence=42))
        self.assertEqual(hdr.sequence, 42)


class TestParserICMPv4Failure(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(parse_icmp(b""), (0, None, None))

    def test_too_short(self):
        self.assertEqual(parse_icmp(_icmp()[:7]), (0, None, None))

    def test_exactly_8_bytes_succeeds(self):
        size, icmp_type, hdr = parse_icmp(_icmp())
        self.assertEqual(size, 8)
        self.assertIsNotNone(icmp_type)
        self.assertIsNotNone(hdr)


# ---------------------------------------------------------------------------
# ICMPv6
# ---------------------------------------------------------------------------

class TestParserICMPv6(unittest.TestCase):
    def test_header_size(self):
        size, _, hdr = parse_icmpv6(_icmpv6())
        self.assertEqual(size, 8)

    def test_type_echo_request(self):
        _, icmp_type, hdr = parse_icmpv6(_icmpv6(type=TYPE_V6_ECHO_REQUEST))
        self.assertEqual(icmp_type, TYPE_V6_ECHO_REQUEST)

    def test_type_echo_reply(self):
        _, icmp_type, hdr = parse_icmpv6(_icmpv6(type=TYPE_V6_ECHO_REPLY))
        self.assertEqual(icmp_type, TYPE_V6_ECHO_REPLY)

    def test_type_dest_unreachable(self):
        _, icmp_type, hdr = parse_icmpv6(_icmpv6(type=TYPE_V6_DEST_UNREACHABLE))
        self.assertEqual(icmp_type, TYPE_V6_DEST_UNREACHABLE)

    def test_type_time_exceeded(self):
        _, icmp_type, hdr = parse_icmpv6(_icmpv6(type=TYPE_V6_TIME_EXCEEDED))
        self.assertEqual(icmp_type, TYPE_V6_TIME_EXCEEDED)

    def test_extra_payload_ignored(self):
        size, icmp_type, hdr = parse_icmpv6(_icmpv6() + b"\xff" * 32)
        self.assertEqual(size, 8)
        self.assertEqual(icmp_type, TYPE_V6_ECHO_REQUEST)

    def test_various_identifiers_and_sequences(self):
        for ident, seq in [(0, 0), (1, 1), (0xFFFF, 0xFFFF)]:
            with self.subTest(ident=ident, seq=seq):
                size, _, hdr = parse_icmpv6(_icmpv6(identifier=ident, sequence=seq))
                self.assertEqual(size, 8)

    def test_header_is_icmpv6_header_instance(self):
        _, _, hdr = parse_icmpv6(_icmpv6())
        self.assertIsInstance(hdr, ICMPv6Header)

    def test_header_type(self):
        _, _, hdr = parse_icmpv6(_icmpv6(type=TYPE_V6_ECHO_REQUEST))
        self.assertEqual(hdr.type, TYPE_V6_ECHO_REQUEST)

    def test_header_code(self):
        _, _, hdr = parse_icmpv6(_icmpv6(type=TYPE_V6_DEST_UNREACHABLE, code=1))
        self.assertEqual(hdr.code, 1)

    def test_header_identifier(self):
        _, _, hdr = parse_icmpv6(_icmpv6(identifier=0x1234))
        self.assertEqual(hdr.identifier, 0x1234)

    def test_header_sequence(self):
        _, _, hdr = parse_icmpv6(_icmpv6(sequence=99))
        self.assertEqual(hdr.sequence, 99)


class TestParserICMPv6Failure(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(parse_icmpv6(b""), (0, None, None))

    def test_too_short(self):
        self.assertEqual(parse_icmpv6(_icmpv6()[:7]), (0, None, None))

    def test_exactly_8_bytes_succeeds(self):
        size, icmp_type, hdr = parse_icmpv6(_icmpv6())
        self.assertEqual(size, 8)
        self.assertIsNotNone(icmp_type)
        self.assertIsNotNone(hdr)


# ---------------------------------------------------------------------------
# Roundtrip: packet_generator → packet_parser
# ---------------------------------------------------------------------------

class TestParserICMPRoundtrip(unittest.TestCase):
    def test_icmpv4_type_preserved(self):
        for t in (TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY, TYPE_DEST_UNREACHABLE, TYPE_TIME_EXCEEDED):
            with self.subTest(type=t):
                raw = _icmp(type=t)
                _, parsed_type, hdr = parse_icmp(raw)
                self.assertEqual(parsed_type, t)

    def test_icmpv6_type_preserved(self):
        for t in (TYPE_V6_ECHO_REQUEST, TYPE_V6_ECHO_REPLY, TYPE_V6_DEST_UNREACHABLE, TYPE_V6_TIME_EXCEEDED):
            with self.subTest(type=t):
                raw = _icmpv6(type=t)
                _, parsed_type, hdr = parse_icmpv6(raw)
                self.assertEqual(parsed_type, t)

    def test_icmpv4_consumes_exactly_8_bytes(self):
        payload = b"\xde\xad\xbe\xef" * 4
        raw = _icmp(payload=payload) + payload
        size, _, hdr = parse_icmp(raw)
        self.assertEqual(size, 8)

    def test_icmpv6_consumes_exactly_8_bytes(self):
        payload = b"\xca\xfe\xba\xbe" * 4
        raw = _icmpv6(payload=payload) + payload
        size, _, hdr = parse_icmpv6(raw)
        self.assertEqual(size, 8)

    def test_icmpv4_type_byte_matches_raw(self):
        raw = _icmp(type=TYPE_ECHO_REQUEST)
        _, parsed_type, hdr = parse_icmp(raw)
        self.assertEqual(parsed_type, raw[0])

    def test_icmpv6_type_byte_matches_raw(self):
        raw = _icmpv6(type=TYPE_V6_ECHO_REQUEST)
        _, parsed_type, hdr = parse_icmpv6(raw)
        self.assertEqual(parsed_type, raw[0])

    def test_icmpv4_roundtrip_header_equals_original(self):
        orig = ICMPHeader(type=TYPE_ECHO_REQUEST, code=0, identifier=0xBEEF, sequence=7)
        _, _, hdr = parse_icmp(_icmp(type=orig.type, code=orig.code,
                                     identifier=orig.identifier, sequence=orig.sequence))
        self.assertEqual(hdr.type, orig.type)
        self.assertEqual(hdr.code, orig.code)
        self.assertEqual(hdr.identifier, orig.identifier)
        self.assertEqual(hdr.sequence, orig.sequence)

    def test_icmpv6_roundtrip_header_equals_original(self):
        orig = ICMPv6Header(type=TYPE_V6_ECHO_REQUEST, code=0, identifier=0xCAFE, sequence=3)
        _, _, hdr = parse_icmpv6(_icmpv6(type=orig.type, code=orig.code,
                                         identifier=orig.identifier, sequence=orig.sequence))
        self.assertEqual(hdr.type, orig.type)
        self.assertEqual(hdr.code, orig.code)
        self.assertEqual(hdr.identifier, orig.identifier)
        self.assertEqual(hdr.sequence, orig.sequence)


if __name__ == "__main__":
    unittest.main()
