"""Explicit transport length and checksum in a packet spec (#68)."""
from __future__ import annotations

import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.tcp import TCPHeader
from packeteer.generate.udp import UDPHeader, _build_udp_header
from packeteer.parse import parse_packet
from packeteer.parse.to_config import update_config

_UDP_OFF = 14 + 20      # Ethernet + IPv4
_TCP_OFF = 14 + 20


def _fragments(payload_len: int = 1024, mtu: int = 576) -> list[bytes]:
    """Return a UDP datagram larger than *mtu*, fragmented."""
    return (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp(dst_port=9999)
        .payload(data=b"A" * payload_len)
        .fragment(mtu=mtu)
    )


def _spec(frame: bytes) -> dict:
    """Return the transport section of *frame*'s packet spec."""
    pkt = parse_packet(frame)
    return update_config({}, pkt.transport).get("transport", {})


class TestFirstFragmentRoundTrip(unittest.TestCase):
    """The case the issue was filed for."""

    def setUp(self) -> None:
        self.frags = _fragments()

    def test_first_fragment_records_the_captured_values(self) -> None:
        section = _spec(self.frags[0])
        # 8-byte header + 1024 bytes of payload, not the 552 in this fragment.
        self.assertEqual(section["length"], 1032)
        self.assertIn("checksum", section)

    def test_first_fragment_rebuilds_byte_for_byte(self) -> None:
        original = self.frags[0]
        section = _spec(original)
        rebuilt = (
            PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2", flags=0b001, identification=
                struct.unpack("!H", original[14 + 4:14 + 6])[0])
            .udp(dst_port=9999, length=section["length"],
                 checksum=section["checksum"])
            .payload(data=original[_UDP_OFF + 8:])
            .build()
        )
        self.assertEqual(rebuilt[_UDP_OFF:_UDP_OFF + 8],
                         original[_UDP_OFF:_UDP_OFF + 8])

    def test_later_fragments_carry_no_transport_section(self) -> None:
        """They have no transport header at all, so nothing to record."""
        self.assertIsNone(parse_packet(self.frags[1]).transport)


class TestNoNoiseOnOrdinaryPackets(unittest.TestCase):
    """Values a rebuild would derive are not written to the spec."""

    def test_udp_packet_has_neither_key(self) -> None:
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9999)
                 .payload(data=b"hello").build())
        section = _spec(frame)
        self.assertNotIn("length", section)
        self.assertNotIn("checksum", section)

    def test_tcp_packet_has_no_checksum_key(self) -> None:
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80)
                 .payload(data=b"hello").build())
        self.assertNotIn("checksum", _spec(frame))

    def test_parsed_header_fields_are_none_when_derivable(self) -> None:
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9999)
                 .payload(data=b"hello").build())
        hdr = parse_packet(frame).transport
        self.assertIsNone(hdr.length)
        self.assertIsNone(hdr.checksum)


class TestWrongChecksumSurvives(unittest.TestCase):
    """A checksum that was wrong on the wire is recorded and reproduced."""

    def _corrupted(self) -> bytes:
        frame = bytearray(
            PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9999)
            .payload(data=b"hello").build()
        )
        frame[_UDP_OFF + 6:_UDP_OFF + 8] = b"\xde\xad"
        return bytes(frame)

    def test_parse_records_it(self) -> None:
        self.assertEqual(_spec(self._corrupted())["checksum"], 0xDEAD)

    def test_build_reproduces_it(self) -> None:
        original = self._corrupted()
        rebuilt = (PacketBuilder()
                   .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                   .ip(src="10.0.0.1", dst="10.0.0.2")
                   .udp(dst_port=9999, checksum=0xDEAD)
                   .payload(data=b"hello").build())
        self.assertEqual(rebuilt, original)

    def test_tcp_wrong_checksum_reproduced(self) -> None:
        frame = bytearray(
            PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80)
            .payload(data=b"hello").build()
        )
        frame[_TCP_OFF + 16:_TCP_OFF + 18] = b"\xbe\xef"
        self.assertEqual(_spec(bytes(frame))["checksum"], 0xBEEF)
        rebuilt = (PacketBuilder()
                   .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                   .ip(src="10.0.0.1", dst="10.0.0.2")
                   .tcp(dst_port=80, checksum=0xBEEF)
                   .payload(data=b"hello").build())
        self.assertEqual(rebuilt, bytes(frame))


class TestOverrideSemantics(unittest.TestCase):

    def test_udp_length_written_verbatim(self) -> None:
        raw = _build_udp_header(
            UDPHeader(1234, 80, length=9999), b"hi", "10.0.0.1", "10.0.0.2",
        )
        self.assertEqual(struct.unpack("!H", raw[4:6])[0], 9999)

    def test_udp_checksum_zero_is_preserved(self) -> None:
        """Zero means "no checksum" in IPv4 UDP, and must not become 0xFFFF."""
        raw = _build_udp_header(
            UDPHeader(1234, 80, checksum=0), b"hi", "10.0.0.1", "10.0.0.2",
        )
        self.assertEqual(struct.unpack("!H", raw[6:8])[0], 0)

    def test_defaults_derive_as_before(self) -> None:
        derived = _build_udp_header(
            UDPHeader(1234, 80), b"hi", "10.0.0.1", "10.0.0.2",
        )
        self.assertEqual(struct.unpack("!H", derived[4:6])[0], 10)
        self.assertNotEqual(struct.unpack("!H", derived[6:8])[0], 0)

    def test_header_defaults_are_none(self) -> None:
        self.assertIsNone(UDPHeader(1, 2).length)
        self.assertIsNone(UDPHeader(1, 2).checksum)
        self.assertIsNone(TCPHeader(1, 2).checksum)


class TestIPv6Fragment(unittest.TestCase):

    def test_first_fragment_records_the_whole_datagram_length(self) -> None:
        frags = (
            PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="2001:db8::1", dst="2001:db8::2")
            .udp(dst_port=9999)
            .payload(data=b"B" * 2048)
            .fragment(mtu=800)
        )
        self.assertGreater(len(frags), 1)
        pkt = parse_packet(frags[0])
        self.assertEqual(pkt.transport.length, 2048 + 8)


if __name__ == "__main__":
    unittest.main()
