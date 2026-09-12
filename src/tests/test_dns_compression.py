"""A compressed DNS message round-trips byte for byte (#130).

Since #131 packeteer compresses too, so the fixture here has to be a message
whose sender chose a pointer target packeteer's encoder would not — that is
the case `raw` exists for, and the only case in which it is set.
"""
from __future__ import annotations

import struct
import unittest

from packeteer.app.dns import from_spec, to_spec
from packeteer.generate import PacketBuilder
from packeteer.generate.dns import DNSMessage, _build_dns_message
from packeteer.parse import parse_packet
from packeteer.parse.dns import parse_dns_udp


def _compressed_query() -> bytes:
    """Hand-build a response whose answer name points at a *shorter* suffix.

    RFC 1035 §4.1.4: `0b11` followed by a 14-bit offset, and any suffix of
    an earlier name may be the target.  The question `example.com` is at
    offset 12, with `com` at offset 20.  The answer's name is written as the
    label `example` followed by `0xC014` — a pointer to `com` — where a
    canonical encoder, packeteer's included, would point the whole name at
    offset 12 as `0xC00C`.  Both are legal; only the bytes tell them apart.
    """
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    answer = (b"\x07example" + struct.pack("!H", 0xC014)   # pointer to `com`
              + struct.pack("!HHIH", 1, 1, 300, 4)          # A, IN, ttl, rdlength
              + bytes([93, 184, 216, 34]))
    return header + question + answer


class TestTheFixtureIsActuallyCompressed(unittest.TestCase):
    """If the fixture stops being non-canonical, everything below proves nothing."""

    def test_it_holds_a_pointer(self) -> None:
        message = _compressed_query()
        self.assertEqual(message[len(message) - 16:len(message) - 14].hex(), "c014")

    def test_the_canonical_encoding_differs(self) -> None:
        """Which is exactly why re-encoding cannot reproduce it."""
        decoded = parse_dns_udp(_compressed_query())
        decoded.raw = b""                       # force a real encode
        canonical = _build_dns_message(decoded)
        self.assertNotEqual(canonical, _compressed_query())
        self.assertIn(b"\xc0\x0c", canonical, "packeteer points at the longest suffix")

    def test_a_canonically_compressed_message_records_nothing(self) -> None:
        """The #131 half: a sender who chose as packeteer does needs no raw."""
        decoded = parse_dns_udp(_compressed_query())
        decoded.raw = b""
        canonical = _build_dns_message(decoded)
        self.assertEqual(parse_dns_udp(canonical).raw, b"")
        self.assertEqual(parse_dns_udp(canonical), decoded)


class TestCompressionSurvivesTheRoundTrip(unittest.TestCase):
    """The defect: a compressed message re-encoded larger and never matched."""

    def test_the_message_keeps_its_bytes(self) -> None:
        message = _compressed_query()
        self.assertEqual(parse_dns_udp(message).raw, message)

    def test_it_re_encodes_to_exactly_what_was_captured(self) -> None:
        message = _compressed_query()
        self.assertEqual(_build_dns_message(parse_dns_udp(message)), message)

    def test_the_decoded_fields_are_still_there_to_read(self) -> None:
        """`raw` is a fidelity mechanism, not a substitute for decoding."""
        decoded = parse_dns_udp(_compressed_query())
        self.assertEqual(decoded.questions[0].name.rstrip("."), "example.com")
        self.assertEqual(decoded.answers[0].name.rstrip("."), "example.com")

    def test_a_whole_packet_rebuilds_identically(self) -> None:
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(src_port=53, dst_port=40000)
                 .app(parse_dns_udp(_compressed_query()))
                 .build())
        self.assertEqual(parse_packet(frame).app.raw, _compressed_query())
        self.assertTrue(frame.endswith(_compressed_query()))

    def test_an_uncompressed_message_records_nothing(self) -> None:
        """The control: `raw` on every packet would be noise, not fidelity."""
        plain = _build_dns_message(DNSMessage(id=1))
        self.assertEqual(parse_dns_udp(plain).raw, b"")
        self.assertNotIn("raw", to_spec(parse_dns_udp(plain)))


class TestTheSpecCarriesIt(unittest.TestCase):

    def test_raw_reaches_the_spec_and_comes_back(self) -> None:
        section = to_spec(parse_dns_udp(_compressed_query()))
        self.assertEqual(section["raw"], _compressed_query().hex())
        self.assertEqual(from_spec(section).raw, _compressed_query())

    def test_it_wins_over_the_decoded_fields(self) -> None:
        """The sharp edge, pinned: editing a name does nothing while raw is set."""
        section = to_spec(parse_dns_udp(_compressed_query()))
        section["questions"][0]["name"] = "edited.example"
        self.assertEqual(_build_dns_message(from_spec(section)), _compressed_query())


class TestSanitiseDropsIt(unittest.TestCase):
    """`raw` wins on build, so redacting into a section that keeps it leaks.

    The same failure mode as #122 and #125: a file that reports success and
    still carries the value someone asked to have removed.  Asserted through
    the real `packeteer.sanitise.sanitise`, not a stub, so it cannot pass by
    doing nothing.
    """

    _ADDRESS = bytes([93, 184, 216, 34])

    def _sanitised(self) -> dict:
        from packeteer.sanitise import sanitise as sanitise_config

        section = to_spec(parse_dns_udp(_compressed_query()))
        config = {
            "packets": [{
                "ethernet": {"src_mac": "00:00:00:00:00:01",
                             "dst_mac": "00:00:00:00:00:02"},
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2",
                            "protocol": "udp"},
                "transport": {"src_port": 53, "dst_port": 40000},
                "dns": section,
            }],
        }
        return sanitise_config(config)["packets"][0]["dns"]

    def test_the_address_really_is_redacted(self) -> None:
        """The precondition: if nothing changed, the tests below prove nothing."""
        before = to_spec(parse_dns_udp(_compressed_query()))
        self.assertEqual(before["answers"][0]["rdata"]["address"], "93.184.216.34")
        self.assertNotEqual(
            self._sanitised()["answers"][0]["rdata"]["address"], "93.184.216.34",
        )

    def test_a_redaction_removes_raw(self) -> None:
        self.assertIn("raw", to_spec(parse_dns_udp(_compressed_query())))
        self.assertNotIn("raw", self._sanitised())

    def test_the_old_address_is_not_in_the_rebuilt_bytes(self) -> None:
        """The property that actually matters, asserted on the wire."""
        rebuilt = _build_dns_message(from_spec(self._sanitised()))
        self.assertNotIn(self._ADDRESS, rebuilt)


if __name__ == "__main__":
    unittest.main()
