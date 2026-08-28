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


def _snaplen(frame: bytes, cut: int) -> bytes:
    """Return *frame* as a capture taken with a snaplen would have held it."""
    return frame[:len(frame) - cut]


def _payload_frame(version: int, transport: str, size: int = 200) -> bytes:
    """Build an Ethernet frame carrying *size* payload bytes over *transport*."""
    b = (PacketBuilder()
         .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
         .ip(src="10.0.0.1" if version == 4 else "2001:db8::1",
             dst="10.0.0.2" if version == 4 else "2001:db8::2"))
    b = b.udp(dst_port=9999) if transport == "udp" else b.tcp(dst_port=80)
    return b.payload(data=b"A" * size).build()


class TestTruncatedCaptureClearsBoth(unittest.TestCase):
    """A snaplen must not read as corruption on every packet (#92).

    The keys mean "a rebuild could not work this out for itself", which a
    consumer reads as "this was wrong on the wire".  A truncated payload
    derives a different value from fewer bytes than the sender used, so
    keeping the captured one would make that reading false everywhere.
    """

    def test_neither_key_appears_for_any_transport_or_version(self) -> None:
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    frame = _payload_frame(version, transport)
                    section = _spec(_snaplen(frame, 100))
                    self.assertNotIn("checksum", section)
                    self.assertNotIn("length", section)

    def test_parsed_header_fields_are_none(self) -> None:
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    hdr = parse_packet(
                        _snaplen(_payload_frame(version, transport), 100)
                    ).transport
                    self.assertIsNone(hdr.checksum)
                    if isinstance(hdr, UDPHeader):
                        self.assertIsNone(hdr.length)

    def test_the_same_packets_captured_whole_also_have_neither(self) -> None:
        """The control: the test above must be measuring truncation."""
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    section = _spec(_payload_frame(version, transport))
                    self.assertNotIn("checksum", section)
                    self.assertNotIn("length", section)

    def test_payload_keeps_the_bytes_that_were_captured(self) -> None:
        """Clearing the header fields must not disturb the payload itself."""
        pkt = parse_packet(_snaplen(_payload_frame(4, "udp"), 100))
        self.assertEqual(pkt.payload, b"A" * 100)

    def test_truncation_inside_the_transport_header_parses_nothing(self) -> None:
        frame = _payload_frame(4, "tcp")
        cut = len(frame) - (_TCP_OFF + 10)      # 10 bytes into the TCP header
        self.assertIsNone(parse_packet(_snaplen(frame, cut)).transport)


class TestTruncationHidesCorruption(unittest.TestCase):
    """The cost of the fix, pinned so it is a decision rather than a surprise."""

    def _corrupt(self, frame: bytes) -> bytes:
        raw = bytearray(frame)
        raw[_UDP_OFF + 6:_UDP_OFF + 8] = b"\xde\xad"
        return bytes(raw)

    def test_corrupt_and_whole_is_still_reported(self) -> None:
        frame = self._corrupt(_payload_frame(4, "udp"))
        self.assertEqual(_spec(frame)["checksum"], 0xDEAD)

    def test_corrupt_and_truncated_reports_nothing(self) -> None:
        """The sender's bytes are not in the file, so "unknown" is the answer."""
        frame = self._corrupt(_payload_frame(4, "udp"))
        self.assertNotIn("checksum", _spec(_snaplen(frame, 100)))


class TestFragmentsAreNotTruncated(unittest.TestCase):
    """A fragment carries exactly what its IP header declares (#68 stands)."""

    def test_ipv4_first_fragment_still_records_both(self) -> None:
        section = _spec(_fragments()[0])
        self.assertEqual(section["length"], 1032)
        self.assertIn("checksum", section)

    def test_ipv6_first_fragment_still_records_its_length(self) -> None:
        frags = (
            PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="2001:db8::1", dst="2001:db8::2")
            .udp(dst_port=9999)
            .payload(data=b"B" * 2048)
            .fragment(mtu=800)
        )
        self.assertEqual(parse_packet(frags[0]).transport.length, 2048 + 8)
