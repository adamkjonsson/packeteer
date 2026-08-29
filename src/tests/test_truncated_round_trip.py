"""A snaplen-truncated capture rebuilds as itself, not as smaller packets (#126)."""
from __future__ import annotations

import io
import json
import struct
import unittest

from packeteer.generate import PacketBuilder
from packeteer.parse import parse_packet, parse_pcap_file
from packeteer.pcap import (
    LINKTYPE_ETHERNET,
    SNAPLEN_UNLIMITED,
    open_pcap,
    read_pcap,
    write_pcap,
    write_pcapng,
)

_SNAPLEN = 96


def _frame(version: int = 4, size: int = 400) -> bytes:
    """Build a whole Ethernet frame carrying *size* payload bytes over TCP."""
    return (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src="10.0.0.1" if version == 4 else "2001:db8::1",
            dst="10.0.0.2" if version == 4 else "2001:db8::2")
        .tcp(dst_port=80)
        .payload(data=b"A" * size)
        .build()
    )


def _capture(version: int = 4, *, pcapng: bool = False) -> bytes:
    """Return a one-packet capture file, cut to ``_SNAPLEN`` as tcpdump would."""
    whole = _frame(version)
    record = (whole[:_SNAPLEN], 1_700_000_000, 500_000, len(whole))
    buf = io.BytesIO()
    writer = write_pcapng if pcapng else write_pcap
    writer([record], file_object=buf, link_type=LINKTYPE_ETHERNET, snaplen=_SNAPLEN)
    return buf.getvalue()


def _rebuild(capture: bytes) -> bytes:
    """Parse *capture* to a spec and build it back, returning the new file."""
    import packeteer.__main__ as cli

    spec = json.loads(parse_pcap_file(file_object=io.BytesIO(capture)))
    out = io.BytesIO()
    packets = []
    for i, pkt_spec in enumerate(spec["packets"], 1):
        meta = pkt_spec["packet_metadata"]
        built = cli._apply_spec_to_builder(PacketBuilder(), pkt_spec, i)[0].build()
        record = (built, meta["timestamp_s"], meta.get("timestamp_us", 0))
        if "orig_len" in meta:
            record = (*record, meta["orig_len"])
        packets.append(record)
    writer = write_pcapng if spec["metadata"]["type"] == "pcapng" else write_pcap
    writer(
        packets,
        file_object=out,
        link_type=spec["metadata"]["link_type"],
        snaplen=spec["metadata"].get("snaplen", SNAPLEN_UNLIMITED),
    )
    return out.getvalue()


class TestTheCaptureItself(unittest.TestCase):
    """The fixture has to be truncated, or nothing below measures anything."""

    def test_the_record_is_shorter_than_the_packet_was(self) -> None:
        with open_pcap(file_object=io.BytesIO(_capture())) as capture:
            record = next(iter(capture))
        self.assertEqual(len(record.data), _SNAPLEN)
        self.assertEqual(record.orig_len, len(_frame()))

    def test_the_parser_sees_the_datagram_as_truncated(self) -> None:
        for version in (4, 6):
            with self.subTest(version=version):
                whole = _frame(version)
                self.assertTrue(parse_packet(whole[:_SNAPLEN]).datagram_truncated)
                self.assertFalse(parse_packet(whole).datagram_truncated)


class TestTheSpecRecordsWhatWasLost(unittest.TestCase):
    """Three facts a rebuild cannot derive, each recorded only when it differs."""

    def _spec(self, version: int = 4) -> dict:
        return json.loads(parse_pcap_file(file_object=io.BytesIO(_capture(version))))

    def test_declared_length_is_the_header_field_as_captured(self) -> None:
        whole = _frame(4)
        (total_length,) = struct.unpack_from("!H", whole, 14 + 2)
        self.assertEqual(
            self._spec(4)["packets"][0]["network"]["declared_length"], total_length,
        )

    def test_declared_length_is_the_ipv6_payload_length(self) -> None:
        whole = _frame(6)
        (payload_length,) = struct.unpack_from("!H", whole, 14 + 4)
        self.assertEqual(
            self._spec(6)["packets"][0]["network"]["declared_length"], payload_length,
        )

    def test_orig_len_is_the_length_on_the_wire(self) -> None:
        meta = self._spec()["packets"][0]["packet_metadata"]
        self.assertEqual(meta["orig_len"], len(_frame()))

    def test_snaplen_is_the_files_limit(self) -> None:
        self.assertEqual(self._spec()["metadata"]["snaplen"], _SNAPLEN)

    def test_a_whole_capture_records_none_of_them(self) -> None:
        """The control: these keys are silence unless the capture was cut."""
        buf = io.BytesIO()
        write_pcap([(_frame(), 1, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        spec = json.loads(parse_pcap_file(file_object=io.BytesIO(buf.getvalue())))
        self.assertNotIn("snaplen", spec["metadata"])
        self.assertNotIn("declared_length", spec["packets"][0]["network"])
        self.assertNotIn("orig_len", spec["packets"][0]["packet_metadata"])


class TestTheRebuildIsTruncatedToo(unittest.TestCase):
    """The defect itself: `parse` then `build` used to produce whole packets."""

    def test_the_file_comes_back_byte_for_byte(self) -> None:
        for version in (4, 6):
            for pcapng in (False, True):
                with self.subTest(version=version, pcapng=pcapng):
                    capture = _capture(version, pcapng=pcapng)
                    self.assertEqual(_rebuild(capture), capture)

    def test_the_rebuilt_record_is_still_short(self) -> None:
        rebuilt = read_pcap(file_object=io.BytesIO(_rebuild(_capture())))
        self.assertEqual(rebuilt.header.snaplen, _SNAPLEN)
        self.assertEqual(len(rebuilt.packets[0].data), _SNAPLEN)
        self.assertEqual(rebuilt.packets[0].orig_len, len(_frame()))

    def test_the_rebuilt_packet_still_declares_the_full_length(self) -> None:
        """Not a smaller whole packet: the header keeps saying what was cut."""
        rebuilt = read_pcap(file_object=io.BytesIO(_rebuild(_capture())))
        self.assertTrue(parse_packet(rebuilt.packets[0].data).datagram_truncated)


class TestTheBuilderTakesTheLength(unittest.TestCase):
    """`PacketBuilder.ip(declared_length=…)` is the API under all of it."""

    def test_ipv4_total_length_is_written_out(self) -> None:
        frame = (PacketBuilder().ethernet()
                 .ip(src="10.0.0.1", dst="10.0.0.2", declared_length=1500)
                 .tcp().payload(data=b"A" * 10).build())
        self.assertEqual(struct.unpack_from("!H", frame, 14 + 2)[0], 1500)

    def test_ipv6_payload_length_is_written_out(self) -> None:
        frame = (PacketBuilder().ethernet()
                 .ip(src="2001:db8::1", dst="2001:db8::2", declared_length=1400)
                 .tcp().payload(data=b"A" * 10).build())
        self.assertEqual(struct.unpack_from("!H", frame, 14 + 4)[0], 1400)

    def test_omitting_it_derives_the_length_as_before(self) -> None:
        for version in (4, 6):
            with self.subTest(version=version):
                self.assertFalse(parse_packet(_frame(version)).datagram_truncated)


class TestWritersStayBackwardCompatible(unittest.TestCase):
    """Three-tuples and the default snaplen must behave exactly as they did."""

    def test_a_three_tuple_is_a_whole_packet(self) -> None:
        for writer in (write_pcap, write_pcapng):
            with self.subTest(writer=writer.__name__):
                buf = io.BytesIO()
                writer([(b"\x00" * 60, 1, 0)], file_object=buf)
                with open_pcap(file_object=io.BytesIO(buf.getvalue())) as capture:
                    record = next(iter(capture))
                self.assertEqual(record.orig_len, 60)

    def test_the_two_forms_may_be_mixed_in_one_file(self) -> None:
        buf = io.BytesIO()
        write_pcap(
            [(b"\x00" * 60, 1, 0), (b"\x00" * 60, 2, 0, 500)], file_object=buf,
        )
        with open_pcap(file_object=io.BytesIO(buf.getvalue())) as capture:
            self.assertEqual([r.orig_len for r in capture], [60, 500])

    def test_the_default_snaplen_is_unchanged(self) -> None:
        for writer in (write_pcap, write_pcapng):
            with self.subTest(writer=writer.__name__):
                buf = io.BytesIO()
                writer([(b"\x00" * 60, 1, 0)], file_object=buf)
                header = read_pcap(file_object=io.BytesIO(buf.getvalue())).header
                self.assertEqual(header.snaplen, SNAPLEN_UNLIMITED)


class TestSanitisingKeepsTheTruncation(unittest.TestCase):
    """The cloning path drops any field it does not name — this one included."""

    def test_the_cloned_header_keeps_its_declared_length(self) -> None:
        from packeteer.sanitise import sanitise

        spec = json.loads(parse_pcap_file(file_object=io.BytesIO(_capture())))
        clean = sanitise(spec)
        self.assertIn("declared_length", clean["packets"][0]["network"])
        self.assertIn("orig_len", clean["packets"][0]["packet_metadata"])
        self.assertEqual(clean["metadata"]["snaplen"], _SNAPLEN)


if __name__ == "__main__":
    unittest.main()
