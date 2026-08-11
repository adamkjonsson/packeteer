from __future__ import annotations

import struct
import unittest

from packeteer.generate.tcp import (
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCPHeader,
    TCPOptions,
    _build_tcp_header,
)
from packeteer.parse.tcp import packet_parser


def _tcp(
    src_port: int = 12345, dst_port: int = 80, seq: int = 0, ack: int = 0,
    flags: int = TCP_ACK, payload: bytes = b"", ip_version: int = 4,
    options: TCPOptions | None = None,
) -> bytes:
    src_ip = "10.0.0.1" if ip_version == 4 else "::1"
    dst_ip = "10.0.0.2" if ip_version == 4 else "::2"
    hdr = TCPHeader(src_port, dst_port, seq=seq, ack=ack, flags=flags, options=options)
    return _build_tcp_header(hdr, payload, src_ip, dst_ip, ip_version)


# ---------------------------------------------------------------------------
# Basic parsing — no options
# ---------------------------------------------------------------------------

class TestParserTCP(unittest.TestCase):
    def test_header_size_no_options(self):
        size, _, hdr = packet_parser(_tcp())
        self.assertEqual(size, 20)

    def test_dst_port(self):
        _, dst_port, hdr = packet_parser(_tcp(dst_port=80))
        self.assertEqual(dst_port, 80)

    def test_dst_port_https(self):
        _, dst_port, hdr = packet_parser(_tcp(dst_port=443))
        self.assertEqual(dst_port, 443)

    def test_dst_port_min(self):
        _, dst_port, hdr = packet_parser(_tcp(dst_port=0))
        self.assertEqual(dst_port, 0)

    def test_dst_port_max(self):
        _, dst_port, hdr = packet_parser(_tcp(dst_port=65535))
        self.assertEqual(dst_port, 65535)

    def test_extra_payload_ignored(self):
        size, dst_port, hdr = packet_parser(_tcp(dst_port=8080) + b"\xff" * 100)
        self.assertEqual(size, 20)
        self.assertEqual(dst_port, 8080)

    def test_flags_do_not_affect_result(self):
        for flags in (TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST, TCP_PSH | TCP_ACK, TCP_SYN | TCP_ACK):
            with self.subTest(flags=flags):
                size, _, hdr = packet_parser(_tcp(flags=flags))
                self.assertEqual(size, 20)

    def test_ipv6_same_result(self):
        _, dst_v4, _ = packet_parser(_tcp(dst_port=443, ip_version=4))
        _, dst_v6, _ = packet_parser(_tcp(dst_port=443, ip_version=6))
        self.assertEqual(dst_v4, dst_v6)

    def test_header_is_tcp_header_instance(self):
        _, _, hdr = packet_parser(_tcp())
        self.assertIsInstance(hdr, TCPHeader)

    def test_header_src_port(self):
        _, _, hdr = packet_parser(_tcp(src_port=54321))
        self.assertEqual(hdr.src_port, 54321)

    def test_header_dst_port(self):
        _, _, hdr = packet_parser(_tcp(dst_port=443))
        self.assertEqual(hdr.dst_port, 443)

    def test_header_seq(self):
        _, _, hdr = packet_parser(_tcp(seq=0xDEADBEEF))
        self.assertEqual(hdr.seq, 0xDEADBEEF)

    def test_header_ack(self):
        _, _, hdr = packet_parser(_tcp(ack=0xCAFEBABE))
        self.assertEqual(hdr.ack, 0xCAFEBABE)

    def test_header_flags(self):
        _, _, hdr = packet_parser(_tcp(flags=TCP_SYN | TCP_ACK))
        self.assertEqual(hdr.flags, TCP_SYN | TCP_ACK)

    def test_header_window(self):
        _, _, hdr = packet_parser(_tcp())
        self.assertEqual(hdr.window, 65535)  # default in TCPHeader

    def test_header_options_none(self):
        _, _, hdr = packet_parser(_tcp())
        self.assertIsNone(hdr.options)


# ---------------------------------------------------------------------------
# Options — variable header size
# ---------------------------------------------------------------------------

class TestParserTCPOptions(unittest.TestCase):
    def test_mss_option_header_size(self):
        # MSS(4) → padded to 4 bytes → data_offset = 6 → header = 24
        raw = _tcp(options=TCPOptions(mss=1460))
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, 24)

    def test_timestamps_option_header_size(self):
        # Timestamps(10) → padded to 12 bytes → data_offset = 8 → header = 32
        raw = _tcp(options=TCPOptions(timestamps=(1000, 2000)))
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, 32)

    def test_window_scale_option_header_size(self):
        # WindowScale(3) → padded to 4 bytes → data_offset = 6 → header = 24
        raw = _tcp(options=TCPOptions(window_scale=7))
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, 24)

    def test_sack_permitted_option_header_size(self):
        # SACK Permitted(2) → padded to 4 bytes → data_offset = 6 → header = 24
        raw = _tcp(options=TCPOptions(sack_permitted=True))
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, 24)

    def test_full_syn_options_header_size(self):
        # MSS(4) + WindowScale(3) + SACK Permitted(2) + Timestamps(10) = 19 → padded to 20
        # data_offset = 5 + 20//4 = 10 → header = 40
        raw = _tcp(options=TCPOptions(mss=1460, window_scale=7, sack_permitted=True,
                                    timestamps=(0, 0)))
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, 40)

    def test_dst_port_preserved_with_options(self):
        raw = _tcp(dst_port=443, options=TCPOptions(mss=1460))
        _, dst_port, hdr = packet_parser(raw)
        self.assertEqual(dst_port, 443)

    def test_header_size_matches_data_offset(self):
        raw = _tcp(options=TCPOptions(mss=1460))
        data_offset = (raw[12] >> 4) & 0xF
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, data_offset * 4)


# ---------------------------------------------------------------------------
# Options — decoding
# ---------------------------------------------------------------------------

class TestParserTCPOptionValues(unittest.TestCase):
    def test_mss_decoded(self):
        _, _, hdr = packet_parser(_tcp(options=TCPOptions(mss=1460)))
        self.assertEqual(hdr.options.mss, 1460)

    def test_window_scale_decoded(self):
        _, _, hdr = packet_parser(_tcp(options=TCPOptions(window_scale=7)))
        self.assertEqual(hdr.options.window_scale, 7)

    def test_sack_permitted_decoded(self):
        _, _, hdr = packet_parser(_tcp(options=TCPOptions(sack_permitted=True)))
        self.assertTrue(hdr.options.sack_permitted)

    def test_timestamps_decoded(self):
        _, _, hdr = packet_parser(_tcp(options=TCPOptions(timestamps=(123456, 654321))))
        self.assertEqual(hdr.options.timestamps, (123456, 654321))

    def test_single_sack_block_decoded(self):
        opts = TCPOptions(sack_blocks=[(1000, 2000)])
        _, _, hdr = packet_parser(_tcp(options=opts))
        self.assertEqual(hdr.options.sack_blocks, [(1000, 2000)])

    def test_four_sack_blocks_decoded(self):
        blocks = [(1, 2), (3, 4), (5, 6), (7, 8)]
        _, _, hdr = packet_parser(_tcp(options=TCPOptions(sack_blocks=blocks)))
        self.assertEqual(hdr.options.sack_blocks, blocks)

    def test_full_syn_options_decoded_together(self):
        opts = TCPOptions(mss=1460, window_scale=7, sack_permitted=True,
                          timestamps=(1, 2))
        _, _, hdr = packet_parser(_tcp(flags=TCP_SYN, options=opts))
        self.assertEqual(hdr.options, opts)

    def test_realistic_linux_syn_layout(self):
        # Hand-built as Linux emits it: MSS, SACK-permitted, Timestamps, NOP,
        # Window Scale — the NOP aligns the 3-byte option to a 4-byte boundary.
        options = (
            bytes([2, 4, 0x05, 0xB4])           # MSS 1460
            + bytes([4, 2])                     # SACK permitted
            + bytes([8, 10, 0, 0, 0, 1, 0, 0, 0, 2])  # Timestamps (1, 2)
            + bytes([1])                        # NOP
            + bytes([3, 3, 7])                  # Window scale 7
        )
        raw = _tcp() + b""
        header = bytearray(raw[:20]) + options
        header[12] = ((20 + len(options)) // 4) << 4
        _, _, hdr = packet_parser(bytes(header))
        self.assertEqual(hdr.options.mss, 1460)
        self.assertTrue(hdr.options.sack_permitted)
        self.assertEqual(hdr.options.timestamps, (1, 2))
        self.assertEqual(hdr.options.window_scale, 7)
        self.assertEqual(hdr.options.unknown, [])

    def test_options_none_when_only_padding(self):
        header = bytearray(_tcp()[:20]) + bytes([1, 1, 1, 1])   # four NOPs
        header[12] = 6 << 4
        _, _, hdr = packet_parser(bytes(header))
        self.assertIsNone(hdr.options)


class TestParserTCPUnknownOptions(unittest.TestCase):
    def _with_options(self, options: bytes) -> bytes:
        header = bytearray(_tcp()[:20]) + options
        header[12] = ((20 + len(options)) // 4) << 4
        return bytes(header)

    def test_unrecognised_kind_preserved(self):
        # Kind 28 (User Timeout) is not modelled; its bytes must survive.
        _, _, hdr = packet_parser(self._with_options(bytes([28, 4, 0x00, 0x05])))
        self.assertEqual(hdr.options.unknown, [(28, b"\x00\x05")])

    def test_known_kind_with_wrong_length_kept_as_unknown(self):
        # An MSS option that is 3 bytes rather than 4 is not a valid MSS, but
        # dropping it would lose bytes that were on the wire.
        _, _, hdr = packet_parser(self._with_options(bytes([2, 3, 5, 1])))
        self.assertIsNone(hdr.options.mss)
        self.assertEqual(hdr.options.unknown, [(2, b"\x05")])

    def test_unknown_option_survives_rebuild(self):
        opts = TCPOptions(mss=1460, unknown=[(28, b"\xaa\xbb")])
        _, _, hdr = packet_parser(_tcp(options=opts))
        self.assertEqual(hdr.options.mss, 1460)
        self.assertEqual(hdr.options.unknown, [(28, b"\xaa\xbb")])


class TestParserTCPMalformedOptions(unittest.TestCase):
    def _with_options(self, options: bytes) -> bytes:
        header = bytearray(_tcp()[:20]) + options
        header[12] = ((20 + len(options)) // 4) << 4
        return bytes(header)

    def test_end_of_option_list_stops_walk(self):
        # EOL, then bytes that would otherwise decode as an MSS option.
        _, _, hdr = packet_parser(self._with_options(bytes([0, 2, 4, 0x05])))
        self.assertIsNone(hdr.options)

    def test_length_below_minimum_stops_walk(self):
        _, _, hdr = packet_parser(self._with_options(bytes([5, 1, 2, 3])))
        self.assertIsNone(hdr.options)

    def test_length_past_end_of_region_stops_walk(self):
        _, _, hdr = packet_parser(self._with_options(bytes([2, 40, 1, 2])))
        self.assertIsNone(hdr.options)

    def test_options_decoded_before_malformed_entry_are_kept(self):
        options = bytes([2, 4, 0x05, 0xB4]) + bytes([3, 99, 7, 0])
        _, _, hdr = packet_parser(self._with_options(options))
        self.assertEqual(hdr.options.mss, 1460)
        self.assertIsNone(hdr.options.window_scale)

    def test_kind_byte_with_no_length_stops_walk(self):
        options = bytes([2, 4, 0x05, 0xB4]) + bytes([1, 1, 1, 8])
        _, _, hdr = packet_parser(self._with_options(options))
        self.assertEqual(hdr.options.mss, 1460)
        self.assertIsNone(hdr.options.timestamps)


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------

class TestParserTCPFailure(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(packet_parser(b""), (0, None, None))

    def test_too_short(self):
        self.assertEqual(packet_parser(_tcp()[:19]), (0, None, None))

    def test_exactly_20_bytes_succeeds(self):
        size, dst_port, hdr = packet_parser(_tcp())
        self.assertEqual(size, 20)
        self.assertIsNotNone(dst_port)
        self.assertIsNotNone(hdr)

    def test_data_offset_too_small(self):
        # Patch byte 12 to set data_offset = 4 (invalid, minimum is 5)
        raw = bytearray(_tcp())
        raw[12] = (4 << 4) | (raw[12] & 0x0F)
        self.assertEqual(packet_parser(bytes(raw)), (0, None, None))

    def test_data_offset_beyond_data(self):
        # data_offset = 6 claims 24-byte header but we only give 20 bytes
        raw = bytearray(_tcp())
        raw[12] = (6 << 4) | (raw[12] & 0x0F)
        self.assertEqual(packet_parser(bytes(raw)[:20]), (0, None, None))


# ---------------------------------------------------------------------------
# Roundtrip: packeteer.generate → packeteer.parse
# ---------------------------------------------------------------------------

class TestParserTCPRoundtrip(unittest.TestCase):
    def test_dst_port_matches_generator(self):
        for port in (22, 80, 443, 8080, 65535):
            with self.subTest(dst_port=port):
                raw = _tcp(dst_port=port)
                _, parsed_port, hdr = packet_parser(raw)
                self.assertEqual(parsed_port, port)

    def test_dst_port_matches_raw_bytes(self):
        raw = _tcp(dst_port=9000)
        _, parsed_port, hdr = packet_parser(raw)
        self.assertEqual(parsed_port, struct.unpack("!H", raw[2:4])[0])

    def test_consumes_exactly_20_bytes_no_options(self):
        payload = b"\xde\xad\xbe\xef" * 10
        raw = _tcp(payload=payload) + payload
        size, _, hdr = packet_parser(raw)
        self.assertEqual(size, 20)

    def test_consumes_exactly_header_with_options(self):
        opts = TCPOptions(mss=1460, timestamps=(100, 200))
        payload = b"\xca\xfe" * 8
        raw = _tcp(options=opts, payload=payload) + payload
        size, _, hdr = packet_parser(raw)
        data_offset = (raw[12] >> 4) & 0xF
        self.assertEqual(size, data_offset * 4)

    def test_ipv4_and_ipv6_roundtrip(self):
        for ip_version in (4, 6):
            with self.subTest(ip_version=ip_version):
                raw = _tcp(dst_port=22, ip_version=ip_version)
                size, dst_port, hdr = packet_parser(raw)
                self.assertEqual(size, 20)
                self.assertEqual(dst_port, 22)

    def test_seq_and_ack_do_not_affect_size_or_port(self):
        raw = _tcp(dst_port=80, seq=0xDEADBEEF, ack=0xCAFEBABE)
        size, dst_port, hdr = packet_parser(raw)
        self.assertEqual(size, 20)
        self.assertEqual(dst_port, 80)

    def test_roundtrip_header_equals_original(self):
        from packeteer.generate.tcp import TCPHeader
        orig = TCPHeader(src_port=54321, dst_port=8080, seq=0x11223344, ack=0x55667788,
                         flags=TCP_SYN | TCP_ACK, window=4096)
        raw = _build_tcp_header(orig, b"", "10.0.0.1", "10.0.0.2", 4)
        _, _, hdr = packet_parser(raw)
        self.assertEqual(hdr.src_port, orig.src_port)
        self.assertEqual(hdr.dst_port, orig.dst_port)
        self.assertEqual(hdr.seq, orig.seq)
        self.assertEqual(hdr.ack, orig.ack)
        self.assertEqual(hdr.flags, orig.flags)
        self.assertEqual(hdr.window, orig.window)


if __name__ == "__main__":
    unittest.main()
