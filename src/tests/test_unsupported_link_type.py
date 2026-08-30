"""An unsupported link type must not be silent (#123).

The whole frame becomes an opaque payload, which in a packet spec is
indistinguishable from a packet that genuinely carried only bytes.  That
difference is the difference between a sanitised file and one that merely
looks sanitised — `sanitise` cannot redact what the parser never saw, and
before this it said nothing at all.
"""
from __future__ import annotations

import io
import unittest
import warnings
from collections.abc import Callable

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.parse import (
    UnsupportedLinkTypeWarning,
    parse_packet,
    parse_pcap_file,
)
from packeteer.parse.core import _packet_to_spec
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_NULL, write_pcap
from packeteer.sanitise import PersonalDataWarning, sanitise

_UNKNOWN = 191          # IEEE 802.15.4, which packeteer has no reader for


def _inner() -> bytes:
    return (PacketBuilder().ip(src="192.0.2.1", dst="192.0.2.9")
            .udp(dst_port=53).payload(data=b"secret").build())


def _capture(link_type: int, frame: bytes) -> bytes:
    buf = io.BytesIO()
    write_pcap([(frame, 1, 0)], file_object=buf, link_type=link_type)
    return buf.getvalue()


def _warnings(fn: Callable[[], object]) -> list[warnings.WarningMessage]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fn()
    return list(caught)


class TestParsingWarns(unittest.TestCase):

    def test_parse_packet_warns_and_names_the_type(self) -> None:
        caught = _warnings(
            lambda: parse_packet(b"\x00\x04" + _inner(), link_type=_UNKNOWN))
        found = [w for w in caught
                 if issubclass(w.category, UnsupportedLinkTypeWarning)]
        self.assertTrue(found)
        self.assertEqual(found[0].message.link_type, _UNKNOWN)
        self.assertIn(str(_UNKNOWN), str(found[0].message))

    def test_a_file_warns_once_rather_than_once_per_packet(self) -> None:
        """The link type is a property of the capture, not of a packet."""
        buf = io.BytesIO()
        write_pcap([(b"\x00\x04" + _inner(), i, 0) for i in range(5)],
                   file_object=buf, link_type=_UNKNOWN)
        caught = _warnings(
            lambda: parse_pcap_file(file_object=io.BytesIO(buf.getvalue())))
        found = [w for w in caught
                 if issubclass(w.category, UnsupportedLinkTypeWarning)]
        self.assertEqual(len(found), 1)

    def test_the_message_says_sanitise_cannot_help(self) -> None:
        caught = _warnings(lambda: parse_pcap_file(
            file_object=io.BytesIO(_capture(_UNKNOWN, b"\x00\x04" + _inner()))))
        message = str([w for w in caught
                       if issubclass(w.category, UnsupportedLinkTypeWarning)][0].message)
        self.assertIn("sanitise", message)

    def test_a_supported_link_type_is_quiet(self) -> None:
        for link_type in (LINKTYPE_ETHERNET, LINKTYPE_NULL):
            with self.subTest(link_type=link_type):
                frame = (PacketBuilder().loopback() if link_type == LINKTYPE_NULL
                         else PacketBuilder().ethernet())
                frame = (frame.ip(src="192.0.2.1", dst="192.0.2.9")
                         .udp(dst_port=53).payload(data=b"x").build())
                caught = _warnings(
                    lambda f=frame, lt=link_type: parse_packet(f, link_type=lt))
                self.assertEqual(
                    [w for w in caught
                     if issubclass(w.category, UnsupportedLinkTypeWarning)], [])


class TestSanitiseWarns(unittest.TestCase):
    """It cannot redact what it cannot see, and must not imply otherwise."""

    def _undecoded_spec(self) -> dict:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            pkt = parse_packet(b"\x00\x04" + _inner(), link_type=_UNKNOWN)
        return {"packets": [_packet_to_spec(pkt)]}

    def test_it_warns(self) -> None:
        caught = _warnings(lambda: sanitise(self._undecoded_spec()))
        found = [w for w in caught
                 if issubclass(w.category, PersonalDataWarning)]
        self.assertTrue(found)
        self.assertEqual(found[0].message.kind, "unredacted")

    def test_the_addresses_really_are_still_there(self) -> None:
        """What the warning is about, asserted rather than assumed."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            clean = sanitise(self._undecoded_spec())
        self.assertIn("c0000201", clean["packets"][0]["payload"]["data"])

    def test_a_decoded_packet_does_not_warn(self) -> None:
        frame = (PacketBuilder().ethernet().ip(src="192.0.2.1", dst="192.0.2.9")
                 .udp(dst_port=53).payload(data=b"x").build())
        spec = {"packets": [_packet_to_spec(parse_packet(frame))]}
        caught = _warnings(lambda: sanitise(spec))
        self.assertEqual([w for w in caught
                          if issubclass(w.category, PersonalDataWarning)], [])

    def test_a_later_fragment_is_not_mistaken_for_one(self) -> None:
        """It has only a payload too, but it was decoded — `network` proves it."""
        spec = {"packets": [{
            "network": {"src": "192.0.2.1", "dst": "192.0.2.9",
                        "protocol": "udp", "fragment_offset": 185},
            "payload": {"data": "00ff"},
        }]}
        caught = _warnings(lambda: sanitise(spec))
        self.assertEqual([w for w in caught
                          if issubclass(w.category, PersonalDataWarning)], [])


class TestWarningsAreNotRelabelled(unittest.TestCase):
    """Consolidation used to rewrite every finding as "Possible name found"."""

    def _icmp_spec(self, count: int) -> dict:
        packet = {
            "network": {"src": "192.0.2.1", "dst": "192.0.2.9",
                        "protocol": "icmp"},
            "transport": {"type": 200, "code": 0, "identifier": 0, "sequence": 0},
            "payload": {"data": "00" * 8},
        }
        return {"packets": [dict(packet) for _ in range(count)]}

    def test_an_unredacted_warning_keeps_its_own_wording(self) -> None:
        caught = _warnings(lambda: sanitise(self._icmp_spec(1)))
        message = str([w for w in caught
                       if issubclass(w.category, PersonalDataWarning)][0].message)
        self.assertIn("ICMP type 200", message)
        self.assertNotIn("Possible name", message)

    def test_it_is_consolidated_across_packets(self) -> None:
        caught = _warnings(lambda: sanitise(self._icmp_spec(3)))
        found = [w for w in caught
                 if issubclass(w.category, PersonalDataWarning)]
        self.assertEqual(len(found), 1)
        self.assertIn("3 packets", str(found[0].message))


class TestTheCLISaysWhy(unittest.TestCase):

    def test_build_names_the_link_type_rather_than_a_missing_key(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            pkt = parse_packet(b"\x00\x04" + _inner(), link_type=_UNKNOWN)
        spec = _packet_to_spec(pkt)
        with self.assertRaises(SystemExit):
            cli._apply_spec_to_builder(PacketBuilder(), spec, 1)


if __name__ == "__main__":
    unittest.main()
