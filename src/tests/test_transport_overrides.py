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


class TestTruncatedCaptureKeepsBoth(unittest.TestCase):
    """A truncated packet records both keys, because neither is derivable (#126).

    #92 cleared them, on the reasoning that a recorded key reads as "this was
    wrong on the wire" and that a truncated packet could not be rebuilt as
    itself anyway.  #126 supplies the missing lengths, so the second half no
    longer holds: these are the values that make the rebuild truncated rather
    than a smaller whole packet.  What separates "wrong" from "unknowable" is
    ``packet_metadata.truncated`` (#94), which the keys now travel with.
    """

    def test_both_keys_appear_for_any_transport_or_version(self) -> None:
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    frame = _payload_frame(version, transport)
                    section = _spec(_snaplen(frame, 100))
                    self.assertIn("checksum", section)
                    if transport == "udp":
                        self.assertIn("length", section)

    def test_parsed_header_fields_hold_the_captured_values(self) -> None:
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    frame = _payload_frame(version, transport)
                    cut = parse_packet(_snaplen(frame, 100)).transport
                    # What the sender wrote, read straight off the wire, not
                    # what 100 fewer bytes would derive.
                    at = 14 + (20 if version == 4 else 40)
                    at += 6 if transport == "udp" else 16
                    (on_the_wire,) = struct.unpack_from("!H", frame, at)
                    self.assertEqual(cut.checksum, on_the_wire)
                    if isinstance(cut, UDPHeader):
                        self.assertEqual(cut.length, 8 + 200)

    def test_the_same_packets_captured_whole_have_neither(self) -> None:
        """The control: the test above must be measuring truncation."""
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    section = _spec(_payload_frame(version, transport))
                    self.assertNotIn("checksum", section)
                    self.assertNotIn("length", section)

    def test_payload_keeps_the_bytes_that_were_captured(self) -> None:
        """Keeping the header fields must not disturb the payload itself."""
        pkt = parse_packet(_snaplen(_payload_frame(4, "udp"), 100))
        self.assertEqual(pkt.payload, b"A" * 100)

    def test_truncation_inside_the_transport_header_parses_nothing(self) -> None:
        frame = _payload_frame(4, "tcp")
        cut = len(frame) - (_TCP_OFF + 10)      # 10 bytes into the TCP header
        self.assertIsNone(parse_packet(_snaplen(frame, cut)).transport)


class TestTruncationCannotVerifyCorruption(unittest.TestCase):
    """The cost of the fix, pinned so it is a decision rather than a surprise."""

    def _corrupt(self, frame: bytes) -> bytes:
        raw = bytearray(frame)
        raw[_UDP_OFF + 6:_UDP_OFF + 8] = b"\xde\xad"
        return bytes(raw)

    def test_corrupt_and_whole_is_still_reported(self) -> None:
        frame = self._corrupt(_payload_frame(4, "udp"))
        self.assertEqual(_spec(frame)["checksum"], 0xDEAD)

    def test_corrupt_and_intact_look_the_same_once_truncated(self) -> None:
        """The sender's bytes are not in the file, so nothing can say which.

        Both record a checksum; only ``packet_metadata.truncated`` says the
        value could not be checked.  Reading a recorded checksum as "wrong on
        the wire" without looking at that flag is what this pins down.
        """
        intact = _payload_frame(4, "udp")
        corrupt = self._corrupt(intact)
        self.assertIn("checksum", _spec(_snaplen(intact, 100)))
        self.assertEqual(_spec(_snaplen(corrupt, 100))["checksum"], 0xDEAD)


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


class TestDatagramTruncated(unittest.TestCase):
    """The signal that tells a wrong checksum from an unknowable one (#94).

    A recorded `transport.checksum` means "a rebuild would not derive this".
    On a whole packet that is corruption; on a truncated one it is simply the
    captured value, since the bytes it covers are not all in the file.  This
    flag is what separates the two.
    """

    def test_set_for_every_transport_and_version_when_truncated(self) -> None:
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    frame = _payload_frame(version, transport)
                    self.assertTrue(
                        parse_packet(_snaplen(frame, 100)).datagram_truncated)

    def test_clear_for_the_same_packets_captured_whole(self) -> None:
        for version in (4, 6):
            for transport in ("udp", "tcp"):
                with self.subTest(version=version, transport=transport):
                    frame = _payload_frame(version, transport)
                    self.assertFalse(parse_packet(frame).datagram_truncated)

    def test_clear_for_every_fragment(self) -> None:
        """A fragment carries exactly what its own IP header declares."""
        for i, frag in enumerate(_fragments()):
            with self.subTest(fragment=i):
                self.assertFalse(parse_packet(frag).datagram_truncated)

    def test_a_short_padded_frame_is_not_truncated(self) -> None:
        """Ethernet padding makes the frame longer than the datagram, not shorter."""
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9999)
                 .payload(data=b"hi").build())
        self.assertEqual(len(frame), 60)
        self.assertFalse(parse_packet(frame).datagram_truncated)

    def test_false_for_an_ipv6_jumbogram(self) -> None:
        """A documented limit: the header states no payload length to compare.

        RFC 2675 encodes a jumbogram as Payload Length ``0`` plus a Jumbo
        Payload hop-by-hop option, so the two bytes are zeroed here rather
        than allocating an actual 64 KiB-plus datagram.
        """
        from packeteer.generate.ipv6 import JumboPayloadOption

        frame = bytearray(
            PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="2001:db8::1", dst="2001:db8::2")
            .hop_by_hop_options([JumboPayloadOption(jumbo_length=70000)])
            .udp(dst_port=9999).payload(data=b"A" * 200).build()
        )
        frame[14 + 4:14 + 6] = b"\x00\x00"          # IPv6 Payload Length
        pkt = parse_packet(_snaplen(bytes(frame), 100))
        self.assertIsNotNone(pkt.ip)
        self.assertFalse(pkt.datagram_truncated)

    def test_the_inner_packet_of_a_tunnel_answers_for_itself(self) -> None:
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .ip(src="192.168.1.1", dst="192.168.1.2")
                 .udp(dst_port=9999).payload(data=b"A" * 200).build())
        pkt = parse_packet(_snaplen(frame, 100))
        self.assertTrue(pkt.datagram_truncated)
        self.assertIsNotNone(pkt.tunneled)
        self.assertTrue(pkt.tunneled.datagram_truncated)

    def test_a_whole_tunnel_is_clear_at_both_depths(self) -> None:
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .ip(src="192.168.1.1", dst="192.168.1.2")
                 .udp(dst_port=9999).payload(data=b"A" * 200).build())
        pkt = parse_packet(frame)
        self.assertFalse(pkt.datagram_truncated)
        self.assertFalse(pkt.tunneled.datagram_truncated)


class TestTruncatedReachesTheSpec(unittest.TestCase):
    """Without a marker, `packeteer parse` output stays ambiguous."""

    def _spec_metadata(self, frame: bytes) -> dict:
        import io
        import json

        from packeteer.parse import parse_pcap_file
        from packeteer.pcap import LINKTYPE_ETHERNET, write_pcap

        buf = io.BytesIO()
        write_pcap([(frame, 1, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        buf.seek(0)
        spec = json.loads(parse_pcap_file(file_object=buf))
        return spec["packets"][0]["packet_metadata"]

    def test_present_only_when_truncated(self) -> None:
        frame = _payload_frame(4, "tcp")
        self.assertNotIn("truncated", self._spec_metadata(frame))
        # write_pcap records incl_len from the bytes it is given, so a short
        # frame is a truncated datagram as far as the IP header is concerned.
        self.assertTrue(self._spec_metadata(_snaplen(frame, 100))["truncated"])

    def test_a_recorded_checksum_needs_the_marker_to_read(self) -> None:
        """Which is exactly why the marker is needed to tell them apart."""
        frame = _payload_frame(4, "tcp")
        self.assertNotIn("checksum", _spec(frame))
        self.assertIn("checksum", _spec(_snaplen(frame, 100)))
        self.assertTrue(self._spec_metadata(_snaplen(frame, 100))["truncated"])
