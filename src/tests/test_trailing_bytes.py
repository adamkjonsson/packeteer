"""Bytes past the end of a decoded structure survive a round trip (#129)."""
from __future__ import annotations

import json
import unittest
import warnings
from pathlib import Path

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.parse import parse_packet, parse_pcap_file
from packeteer.parse.to_config import update_config
from packeteer.pcap import open_pcap

_PAD = b"\x00" * 16


def _arp_frame(trailer: bytes = b"") -> bytes:
    """Return an ARP frame, with *trailer* bytes after the message."""
    return (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff",
                      pad=False, trailer=trailer)
            .arp(sender_ip="10.0.0.1", target_ip="10.0.0.2")
            .build())


class TestAnEthernetTrailerSurvives(unittest.TestCase):
    """A frame padded to anything but 60 bytes could not be expressed (#129).

    `EthernetHeader.pad` is a boolean: it says "pad to the 60-byte minimum" or
    "do not pad".  A real capture held 58-byte ARP frames — 42 bytes of ARP
    and 16 of zeros — and neither setting reproduces that, so the 16 bytes
    were dropped and the frame came back 16 short.
    """

    def test_the_builder_appends_it_verbatim(self) -> None:
        frame = _arp_frame(_PAD)
        self.assertEqual(len(frame), 42 + 16)
        self.assertEqual(frame[42:], _PAD)

    def test_it_is_parsed_back_off_the_wire(self) -> None:
        pkt = parse_packet(_arp_frame(_PAD))
        self.assertEqual(pkt.ethernet.trailer, _PAD)
        self.assertIsNotNone(pkt.arp, "the ARP message still has to decode")

    def test_it_reaches_the_spec_and_rebuilds(self) -> None:
        frame = _arp_frame(_PAD)
        pkt = parse_packet(frame)
        section = update_config({}, pkt.ethernet)["ethernet"]
        self.assertEqual(section["trailer"], _PAD.hex())
        cfg = {"ethernet": section, **update_config({}, pkt.arp)}
        rebuilt, _ = cli._apply_spec_to_builder(PacketBuilder(), cfg, 1)
        self.assertEqual(rebuilt.build().hex(), frame.hex())

    def test_a_frame_without_one_says_nothing(self) -> None:
        """The control: a key on every packet would be noise."""
        section = update_config({}, parse_packet(_arp_frame()).ethernet)["ethernet"]
        self.assertNotIn("trailer", section)

    def test_a_trailer_suppresses_the_automatic_padding(self) -> None:
        """Padding on top of the captured bytes would lengthen the frame."""
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01",
                           dst_mac="ff:ff:ff:ff:ff:ff", trailer=b"\x00\x00")
                 .arp(sender_ip="10.0.0.1", target_ip="10.0.0.2")
                 .build())
        self.assertEqual(len(frame), 44, "44, not padded on to 60")

    def test_padding_still_happens_without_one(self) -> None:
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff")
                 .arp(sender_ip="10.0.0.1", target_ip="10.0.0.2")
                 .build())
        self.assertEqual(len(frame), 60)


class TestADHCPTrailerSurvives(unittest.TestCase):
    """BOOTP pads a short message with zeros after the END option (#129).

    The parser stopped at END and the encoder appended nothing, so a real
    DHCP Request rebuilt 11 bytes shorter than it was captured.
    """

    def _frame(self, trailer: bytes) -> bytes:
        from packeteer.generate.dhcp import DHCPMessage, DHCPOptMessageType
        msg = DHCPMessage(options=[DHCPOptMessageType(mtype=3)], trailer=trailer)
        return (PacketBuilder()
                .ethernet(src_mac="00:00:00:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff")
                .ip(src="0.0.0.0", dst="255.255.255.255")
                .udp(src_port=68, dst_port=67)
                .app(msg)
                .build())

    def test_the_message_keeps_its_padding(self) -> None:
        frame = self._frame(b"\x00" * 11)
        pkt = parse_packet(frame)
        self.assertEqual(pkt.app.trailer, b"\x00" * 11)

    def test_it_reaches_the_spec_and_rebuilds(self) -> None:
        frame = self._frame(b"\x00" * 11)
        pkt = parse_packet(frame)
        from packeteer.app.dhcp import from_spec, to_spec
        section = to_spec(pkt.app)
        self.assertEqual(section["trailer"], (b"\x00" * 11).hex())
        self.assertEqual(from_spec(section).trailer, b"\x00" * 11)

    def test_a_message_without_padding_says_nothing(self) -> None:
        from packeteer.app.dhcp import to_spec
        self.assertNotIn("trailer", to_spec(parse_packet(self._frame(b"")).app))


_CAPTURES = Path(__file__).resolve().parents[2] / "captures"

class TestTheOriginalsRoundTripToo(unittest.TestCase):
    """The check that found #129, run wherever the unsanitised captures are.

    Every capture on hand rebuilds byte for byte, with no exceptions — the
    DNS one was lifted when #130 landed.

    `testcases/real/` holds packeteer's own output — `sanitise` parsed and
    rebuilt every packet in it — so a round-trip sweep over it cannot catch
    anything `sanitise` itself discards.  That is exactly what hid #129: the
    padded ARP frames were normalised to 42 bytes on the way in, and the
    committed capture passed.

    The unsanitised originals cannot be committed, so this skips when they are
    not there.  It is not CI coverage; it is the check a person adding a
    capture is told to run, made automatic on the machine that has the files.
    """

    def test_every_original_packet_rebuilds_identically(self) -> None:
        if not _CAPTURES.is_dir():
            self.skipTest(f"no unsanitised captures at {_CAPTURES}")
        files = sorted(p for p in _CAPTURES.iterdir()
                       if p.suffix in (".pcap", ".pcapng"))
        if not files:
            self.skipTest(f"no captures in {_CAPTURES}")
        for path in files:
            with self.subTest(capture=path.name):
                self._round_trip(path)

    def _round_trip(self, path: Path) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            spec = json.loads(parse_pcap_file(path=str(path)))
        with open_pcap(path=str(path)) as capture:
            originals = [record.data for record in capture]
        for index, (packet, original) in enumerate(
            zip(spec["packets"], originals, strict=True), start=1,
        ):
            builder, _ = cli._apply_spec_to_builder(PacketBuilder(), packet, index)
            self.assertEqual(
                builder.build().hex(), original.hex(),
                f"{path.name} packet {index} did not rebuild identically",
            )


if __name__ == "__main__":
    unittest.main()
