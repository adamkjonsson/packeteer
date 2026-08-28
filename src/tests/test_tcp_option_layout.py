"""A capture's TCP option layout survives a round trip (#87)."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.generate.tcp import TCPOptions, _build_options
from packeteer.parse import parse_packet, parse_pcap_file
from packeteer.parse.tcp import _parse_options
from packeteer.pcap import LINKTYPE_ETHERNET, read_pcap, write_pcap

_TESTCASES = Path(__file__).resolve().parents[2] / "testcases"

#: NOP, NOP, Timestamps — what essentially every modern data segment carries,
#: and what the canonical encoder would write as Timestamps, NOP, NOP.
_SENDER_LAYOUT = bytes.fromhex("0101080a21c6e61e65f1e0d5")


def _tmp(suffix: str = ".pcap") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def _frame_with_options(option_bytes: bytes) -> bytes:
    """Return a TCP frame whose option region is *option_bytes* verbatim."""
    return (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(src_port=54321, dst_port=80,
                 options=TCPOptions(raw=option_bytes))
            .payload(data=b"x" * 20)
            .build())


def _roundtrip(frames: list[bytes]) -> list[bytes]:
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


class TestRawCapturedOnlyWhenNeeded(unittest.TestCase):

    def test_sender_layout_is_captured(self) -> None:
        opts = _parse_options(_SENDER_LAYOUT)
        self.assertEqual(opts.raw, _SENDER_LAYOUT)
        self.assertEqual(opts.timestamps, (0x21C6E61E, 0x65F1E0D5))

    def test_canonical_layouts_do_not_set_raw(self) -> None:
        """Anything the encoder itself produces needs no replay."""
        for opts in (
            TCPOptions(mss=1460),
            TCPOptions(mss=1460, sack_permitted=True),
            TCPOptions(timestamps=(1, 2)),
            TCPOptions(mss=1460, window_scale=7, sack_permitted=True,
                       timestamps=(1, 2)),
            TCPOptions(sack_blocks=[(1, 2), (3, 4)]),
        ):
            with self.subTest(opts=opts):
                self.assertIsNone(_parse_options(_build_options(opts)).raw)

    def test_no_options_stays_none(self) -> None:
        self.assertIsNone(_parse_options(b""))


class TestRawWins(unittest.TestCase):

    def test_encoder_returns_raw_verbatim(self) -> None:
        self.assertEqual(
            _build_options(TCPOptions(raw=_SENDER_LAYOUT)), _SENDER_LAYOUT,
        )

    def test_raw_overrides_the_decoded_fields(self) -> None:
        """Documented precedence: editing a field with raw set does nothing."""
        opts = _parse_options(_SENDER_LAYOUT)
        opts.timestamps = (0, 0)
        self.assertEqual(_build_options(opts), _SENDER_LAYOUT)

    def test_clearing_raw_re_enables_the_fields(self) -> None:
        opts = _parse_options(_SENDER_LAYOUT)
        opts.raw = None
        opts.timestamps = (1, 2)
        self.assertEqual(_build_options(opts), _build_options(
            TCPOptions(timestamps=(1, 2)),
        ))


class TestSpecRoundTrip(unittest.TestCase):

    def _spec(self, frame: bytes) -> dict:
        src = _tmp()
        try:
            write_pcap([(frame, 0, 0)], path=src, link_type=LINKTYPE_ETHERNET)
            return json.loads(parse_pcap_file(path=src))["packets"][0]
        finally:
            os.remove(src)

    def test_spec_carries_raw_as_hex(self) -> None:
        spec = self._spec(_frame_with_options(_SENDER_LAYOUT))
        self.assertEqual(spec["transport"]["options"]["raw"],
                         _SENDER_LAYOUT.hex())

    def test_spec_keeps_the_decoded_fields_beside_raw(self) -> None:
        """The readable fields stay, so a spec is still legible by eye."""
        spec = self._spec(_frame_with_options(_SENDER_LAYOUT))
        self.assertIn("timestamps", spec["transport"]["options"])

    def test_canonical_options_gain_no_raw_key(self) -> None:
        frame = _frame_with_options(_build_options(TCPOptions(mss=1460)))
        self.assertNotIn("raw", self._spec(frame)["transport"]["options"])

    def test_frame_rebuilds_byte_for_byte(self) -> None:
        original = _frame_with_options(_SENDER_LAYOUT)
        self.assertEqual(_roundtrip([original]), [original])

    def test_parsed_header_is_unchanged_in_meaning(self) -> None:
        """Replaying bytes must not change what a parse reports."""
        original = _frame_with_options(_SENDER_LAYOUT)
        rebuilt = _roundtrip([original])[0]
        options = parse_packet(rebuilt).transport.options
        self.assertEqual(options.timestamps, (0x21C6E61E, 0x65F1E0D5))


class TestCorpusRoundTrip(unittest.TestCase):
    """Every shipped capture rebuilds byte-for-byte, pcapng included.

    Extends the `*.pcap` sweep added with #86.  `dns_example.pcapng` needs
    `decode_app=False`: re-encoding a decoded DNS message normalises it, which
    is the documented caveat and unrelated to option layout.
    """

    def test_every_capture_rebuilds_exactly(self) -> None:
        captures = sorted(_TESTCASES.glob("*.pcap*"))
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
                src, spec, out = _tmp(), _tmp(".json"), _tmp()
                try:
                    write_pcap([(f, 0, i) for i, f in enumerate(original)],
                               path=src, link_type=LINKTYPE_ETHERNET)
                    Path(spec).write_text(
                        parse_pcap_file(path=src, decode_app=False)
                    )
                    cli._cmd_build(
                        argparse.Namespace(config=spec, pcap=out, pcapng=None)
                    )
                    rebuilt = [p[0] for p in read_pcap(path=out).packets]
                finally:
                    for path in (src, spec, out):
                        os.remove(path)
                self.assertEqual(rebuilt, original)


if __name__ == "__main__":
    unittest.main()
