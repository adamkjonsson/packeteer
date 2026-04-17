from __future__ import annotations

import struct
import socket
import unittest
from packeteer.generate.tcp import (
    TCPHeader, TCPOptions, _build_tcp_header,
    TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR,
)
from packeteer.generate.checksum import ones_complement_checksum


def _verify_tcp_checksum_v4(src_ip: str, dst_ip: str, tcp_bytes: bytes, payload: bytes) -> int:
    tcp_length = len(tcp_bytes) + len(payload)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 6, tcp_length)
    )
    return ones_complement_checksum(pseudo + tcp_bytes + payload)


def _verify_tcp_checksum_v6(src_ip: str, dst_ip: str, tcp_bytes: bytes, payload: bytes) -> int:
    tcp_length = len(tcp_bytes) + len(payload)
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', tcp_length, b'\x00\x00\x00', 6)
    )
    return ones_complement_checksum(pseudo + tcp_bytes + payload)


class TestTCPHeader(unittest.TestCase):
    def test_length(self):
        h = _build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        self.assertEqual(len(h), 20)

    def test_data_offset(self):
        raw = _build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        data_offset = (raw[12] >> 4) & 0xF
        self.assertEqual(data_offset, 5)

    def test_ack_flag_default(self):
        raw = _build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        self.assertEqual(raw[13], 0x10)

    def test_checksum_v4(self):
        payload = b'hello'
        raw = _build_tcp_header(TCPHeader(5000, 443), payload, "10.0.0.1", "10.0.0.2")
        self.assertEqual(_verify_tcp_checksum_v4("10.0.0.1", "10.0.0.2", raw, payload), 0)

    def test_checksum_v6(self):
        payload = b'world'
        raw = _build_tcp_header(
            TCPHeader(5000, 443), payload, "fe80::1", "fe80::2", ip_version=6
        )
        self.assertEqual(_verify_tcp_checksum_v6("fe80::1", "fe80::2", raw, payload), 0)

    def test_ports(self):
        raw = _build_tcp_header(TCPHeader(12345, 8080), b'', "1.2.3.4", "5.6.7.8")
        src, dst = struct.unpack('!HH', raw[:4])
        self.assertEqual(src, 12345)
        self.assertEqual(dst, 8080)

    def test_seq_default_is_zero(self):
        raw = _build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        seq = struct.unpack('!I', raw[4:8])[0]
        self.assertEqual(seq, 0)

    def test_seq_custom_value(self):
        raw = _build_tcp_header(TCPHeader(1234, 80, seq=0xDEADBEEF), b'', "1.2.3.4", "5.6.7.8")
        seq = struct.unpack('!I', raw[4:8])[0]
        self.assertEqual(seq, 0xDEADBEEF)

    def test_seq_via_packet_builder(self):
        from packeteer.generate import PacketBuilder
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp(seq=0x12345678)
               .build())
        # 20-byte IP header, then TCP seq at bytes 4–7
        seq = struct.unpack('!I', pkt[20 + 4: 20 + 8])[0]
        self.assertEqual(seq, 0x12345678)


class TestTCPFlagConstants(unittest.TestCase):
    def test_flag_values(self):
        self.assertEqual(TCP_FIN, 0x001)
        self.assertEqual(TCP_SYN, 0x002)
        self.assertEqual(TCP_RST, 0x004)
        self.assertEqual(TCP_PSH, 0x008)
        self.assertEqual(TCP_ACK, 0x010)
        self.assertEqual(TCP_URG, 0x020)
        self.assertEqual(TCP_ECE, 0x040)
        self.assertEqual(TCP_CWR, 0x080)

    def test_all_flags_distinct(self):
        flags = [TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR]
        self.assertEqual(len(set(flags)), 8)

    def test_combined_flags_encoded(self):
        raw = _build_tcp_header(
            TCPHeader(1234, 80, flags=TCP_PSH | TCP_ACK), b'', "1.2.3.4", "5.6.7.8"
        )
        self.assertEqual(raw[13], TCP_PSH | TCP_ACK)

    def test_ece_cwr_flags_encoded(self):
        raw = _build_tcp_header(
            TCPHeader(1234, 80, flags=TCP_SYN | TCP_ECE | TCP_CWR), b'', "1.2.3.4", "5.6.7.8"
        )
        self.assertEqual(raw[13], TCP_SYN | TCP_ECE | TCP_CWR)


class TestTCPReservedField(unittest.TestCase):
    def test_reserved_default_is_zero(self):
        raw = _build_tcp_header(TCPHeader(1234, 80), b'', "1.2.3.4", "5.6.7.8")
        reserved = raw[12] & 0xF
        self.assertEqual(reserved, 0)

    def test_reserved_custom_value(self):
        raw = _build_tcp_header(TCPHeader(1234, 80, reserved=0b1010), b'', "1.2.3.4", "5.6.7.8")
        reserved = raw[12] & 0xF
        self.assertEqual(reserved, 0b1010)

    def test_reserved_does_not_corrupt_data_offset(self):
        raw = _build_tcp_header(TCPHeader(1234, 80, reserved=0xF), b'', "1.2.3.4", "5.6.7.8")
        data_offset = (raw[12] >> 4) & 0xF
        self.assertEqual(data_offset, 5)


class TestTCPOptions(unittest.TestCase):
    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _build(opts: TCPOptions) -> bytes:
        hdr = TCPHeader(1234, 80, flags=TCP_SYN, options=opts)
        return _build_tcp_header(hdr, b'', "10.0.0.1", "10.0.0.2")

    @staticmethod
    def _data_offset(raw: bytes) -> int:
        return (raw[12] >> 4) & 0xF

    @staticmethod
    def _options_bytes(raw: bytes) -> bytes:
        """Return the options area (everything after the fixed 20-byte header)."""
        data_offset = (raw[12] >> 4) & 0xF
        return raw[20: data_offset * 4]

    # ── no options ────────────────────────────────────────────────────────────

    def test_no_options_length_and_offset(self):
        raw = self._build(None)
        self.assertEqual(len(raw), 20)
        self.assertEqual(self._data_offset(raw), 5)

    # ── MSS ───────────────────────────────────────────────────────────────────

    def test_mss_length(self):
        raw = self._build(TCPOptions(mss=1460))
        # MSS (4) padded to 4 bytes → header = 24 bytes, data offset = 6
        self.assertEqual(len(raw), 24)
        self.assertEqual(self._data_offset(raw), 6)

    def test_mss_encoding(self):
        raw = self._build(TCPOptions(mss=1460))
        opts = self._options_bytes(raw)
        self.assertEqual(opts[0], 2)      # kind
        self.assertEqual(opts[1], 4)      # length
        self.assertEqual(struct.unpack('!H', opts[2:4])[0], 1460)

    def test_mss_checksum_valid(self):
        raw = self._build(TCPOptions(mss=1460))
        self.assertEqual(_verify_tcp_checksum_v4("10.0.0.1", "10.0.0.2", raw, b''), 0)

    # ── Window Scale ──────────────────────────────────────────────────────────

    def test_window_scale_encoding(self):
        raw = self._build(TCPOptions(window_scale=7))
        opts = self._options_bytes(raw)
        self.assertEqual(opts[0], 3)   # kind
        self.assertEqual(opts[1], 3)   # length
        self.assertEqual(opts[2], 7)   # shift count

    def test_window_scale_padding(self):
        # Window Scale is 3 bytes → padded to 4 bytes with one NOP
        raw = self._build(TCPOptions(window_scale=4))
        opts = self._options_bytes(raw)
        self.assertEqual(len(opts), 4)
        self.assertEqual(opts[3], 1)   # NOP padding

    # ── SACK Permitted ────────────────────────────────────────────────────────

    def test_sack_permitted_encoding(self):
        raw = self._build(TCPOptions(sack_permitted=True))
        opts = self._options_bytes(raw)
        self.assertEqual(opts[0], 4)   # kind
        self.assertEqual(opts[1], 2)   # length

    def test_sack_permitted_false_not_encoded(self):
        raw_with = self._build(TCPOptions(sack_permitted=True))
        raw_without = self._build(TCPOptions(sack_permitted=False))
        self.assertGreater(len(raw_with), len(raw_without))

    # ── Timestamps ────────────────────────────────────────────────────────────

    def test_timestamps_encoding(self):
        raw = self._build(TCPOptions(timestamps=(0xDEAD, 0xBEEF)))
        opts = self._options_bytes(raw)
        self.assertEqual(opts[0], 8)    # kind
        self.assertEqual(opts[1], 10)   # length
        tsval = struct.unpack('!I', opts[2:6])[0]
        tsecr = struct.unpack('!I', opts[6:10])[0]
        self.assertEqual(tsval, 0xDEAD)
        self.assertEqual(tsecr, 0xBEEF)

    def test_timestamps_length(self):
        # Timestamps is 10 bytes → padded to 12 bytes → data offset = 5 + 3 = 8
        raw = self._build(TCPOptions(timestamps=(1, 0)))
        self.assertEqual(self._data_offset(raw), 8)

    def test_timestamps_checksum_valid(self):
        raw = self._build(TCPOptions(timestamps=(1000, 0)))
        self.assertEqual(_verify_tcp_checksum_v4("10.0.0.1", "10.0.0.2", raw, b''), 0)

    # ── SACK blocks ───────────────────────────────────────────────────────────

    def test_sack_one_block_encoding(self):
        raw = self._build(TCPOptions(sack_blocks=[(100, 200)]))
        opts = self._options_bytes(raw)
        self.assertEqual(opts[0], 5)    # kind
        self.assertEqual(opts[1], 10)   # length = 2 + 8*1
        left  = struct.unpack('!I', opts[2:6])[0]
        right = struct.unpack('!I', opts[6:10])[0]
        self.assertEqual(left, 100)
        self.assertEqual(right, 200)

    def test_sack_two_blocks_length(self):
        raw = self._build(TCPOptions(sack_blocks=[(0, 100), (200, 300)]))
        opts = self._options_bytes(raw)
        # kind(1) + len(1) + 2 blocks * 8 = 18 bytes, padded to 20
        self.assertEqual(opts[1], 18)   # SACK option length field

    # ── combined options ──────────────────────────────────────────────────────

    def test_combined_syn_options(self):
        """SYN-typical option set: MSS + Window Scale + SACK Permitted + Timestamps."""
        opts = TCPOptions(mss=1460, window_scale=7, sack_permitted=True, timestamps=(0, 0))
        raw = self._build(opts)
        # MSS=4, WS=3, SACK-perm=2, Timestamps=10 → 19 bytes, padded to 20
        # data offset = 5 + 20//4 = 10
        self.assertEqual(self._data_offset(raw), 10)
        self.assertEqual(len(raw), 40)
        self.assertEqual(_verify_tcp_checksum_v4("10.0.0.1", "10.0.0.2", raw, b''), 0)

    def test_combined_checksum_v6(self):
        opts = TCPOptions(mss=1440, timestamps=(500, 0))
        hdr = TCPHeader(9000, 443, flags=TCP_SYN, options=opts)
        raw = _build_tcp_header(hdr, b'data', "fe80::1", "fe80::2", ip_version=6)
        self.assertEqual(_verify_tcp_checksum_v6("fe80::1", "fe80::2", raw, b'data'), 0)

    # ── PacketBuilder integration ─────────────────────────────────────────────

    def test_options_via_packet_builder(self):
        from packeteer.generate import PacketBuilder
        opts = TCPOptions(mss=1460, window_scale=7)
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp(options=opts)
               .build())
        # IP header = 20, then TCP; data offset at byte 20+12
        tcp_start = 20
        data_offset = (pkt[tcp_start + 12] >> 4) & 0xF
        self.assertGreater(data_offset, 5)

    def test_reserved_via_packet_builder(self):
        from packeteer.generate import PacketBuilder
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp(reserved=0b0011)
               .build())
        tcp_start = 20
        reserved = pkt[tcp_start + 12] & 0xF
        self.assertEqual(reserved, 0b0011)


if __name__ == '__main__':
    unittest.main()
