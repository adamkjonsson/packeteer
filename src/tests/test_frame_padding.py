"""Short Ethernet frames keep their captured length through a round trip (#86)."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.parse import parse_packet, parse_pcap_file
from packeteer.pcap import LINKTYPE_ETHERNET, read_pcap, write_pcap

_TESTCASES = Path(__file__).resolve().parents[2] / "testcases"


def _tmp(suffix: str = ".pcap") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def _roundtrip(frames: list[bytes]) -> list[bytes]:
    """Write *frames*, parse them to a spec, rebuild, and read them back."""
    src, spec, out = _tmp(), _tmp(".json"), _tmp()
    try:
        write_pcap([(f, 0, i) for i, f in enumerate(frames)], path=src,
                   link_type=LINKTYPE_ETHERNET)
        Path(spec).write_text(parse_pcap_file(path=src))
        cli._cmd_build(argparse.Namespace(config=spec, pcap=out, pcapng=None))
        return [p[0] for p in read_pcap(path=out).packets]
    finally:
        for path in (src, spec, out):
            os.remove(path)


def _short_frame() -> bytes:
    """Return a 54-byte frame — a bare TCP ACK, under the Ethernet minimum."""
    frame = (PacketBuilder()
             .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02",
                       pad=False)
             .ip(src="10.0.0.1", dst="10.0.0.2")
             .tcp(src_port=54321, dst_port=80)
             .build())
    assert len(frame) == 54, len(frame)
    return frame


class TestShortFrames(unittest.TestCase):

    def test_captured_length_is_preserved(self) -> None:
        original = _short_frame()
        self.assertEqual(_roundtrip([original]), [original])

    def test_parser_marks_the_frame_unpadded(self) -> None:
        self.assertFalse(parse_packet(_short_frame()).ethernet.pad)

    def test_spec_carries_pad_false(self) -> None:
        src, spec = _tmp(), None
        try:
            write_pcap([(_short_frame(), 0, 0)], path=src,
                       link_type=LINKTYPE_ETHERNET)
            spec = json.loads(parse_pcap_file(path=src))
        finally:
            os.remove(src)
        self.assertIs(spec["packets"][0]["ethernet"]["pad"], False)


class TestOrdinaryFrames(unittest.TestCase):
    """Frames at or above the minimum are untouched, and gain no spec key."""

    def _long_frame(self) -> bytes:
        return (PacketBuilder()
                .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .tcp(src_port=54321, dst_port=80)
                .payload(data=b"x" * 100).build())

    def test_parser_leaves_pad_set(self) -> None:
        self.assertTrue(parse_packet(self._long_frame()).ethernet.pad)

    def test_spec_has_no_pad_key(self) -> None:
        src = _tmp()
        try:
            write_pcap([(self._long_frame(), 0, 0)], path=src,
                       link_type=LINKTYPE_ETHERNET)
            spec = json.loads(parse_pcap_file(path=src))
        finally:
            os.remove(src)
        self.assertNotIn("pad", spec["packets"][0]["ethernet"])

    def test_genuinely_padded_frame_still_round_trips(self) -> None:
        """The case that already worked, and must keep working."""
        padded = (PacketBuilder()
                  .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                  .ip(src="10.0.0.1", dst="10.0.0.2")
                  .tcp(src_port=54321, dst_port=80).build())
        self.assertEqual(len(padded), 60)
        self.assertEqual(_roundtrip([padded]), [padded])


class TestTunnelledFrames(unittest.TestCase):
    """Padding describes the outer frame; an inner one is never marked."""

    def _etherip(self) -> bytes:
        return (PacketBuilder()
                .ethernet(src_mac="00:00:00:00:00:0a", dst_mac="00:00:00:00:00:0b")
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .etherip()
                .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                .ip(src="192.168.0.1", dst="192.168.0.2")
                .tcp(src_port=1234, dst_port=80)
                .build())

    def test_inner_frame_not_marked_unpadded(self) -> None:
        """The inner frame is short, but that says nothing about the wire."""
        inner = parse_packet(self._etherip()).tunneled
        self.assertIsNotNone(inner)
        self.assertIsNotNone(inner.ethernet)
        self.assertTrue(inner.ethernet.pad)

    def test_outer_frame_governs(self) -> None:
        self.assertTrue(parse_packet(self._etherip()).ethernet.pad)

    def test_tunnelled_frame_round_trips(self) -> None:
        original = self._etherip()
        self.assertEqual(_roundtrip([original]), [original])


class TestCorpusRoundTrip(unittest.TestCase):
    """Every packet in every shipped capture rebuilds byte-for-byte.

    Only reachable now that #68 and #86 are both fixed; before them the
    fragment first-headers and every sub-60-byte frame came back changed.
    """

    def test_every_pcap_rebuilds_exactly(self) -> None:
        captures = sorted(_TESTCASES.glob("*.pcap"))
        if not captures:
            self.skipTest(
                f"no captures under {_TESTCASES} — the corpus is untracked "
                "(.gitignore excludes *.pcap), so this sweep runs only where "
                "it is present. The mechanisms it covers are also tested "
                "against frames this suite builds itself."
            )
        for capture in captures:
            with self.subTest(capture=capture.name):
                original = [p[0] for p in read_pcap(path=str(capture)).packets]
                self.assertEqual(_roundtrip(original), original)


if __name__ == "__main__":
    unittest.main()
