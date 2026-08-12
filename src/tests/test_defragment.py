"""Tests for packeteer.parse.defragment — IP reassembly."""
from __future__ import annotations

import io
import json
import socket
import struct
import unittest
import warnings

from packeteer.generate import PacketBuilder
from packeteer.generate.ethernet import EthernetHeader
from packeteer.generate.fragmentation import fragment_ipv4, fragment_ipv6
from packeteer.generate.ip import IPHeader
from packeteer.generate.ipv6 import IPv6Header
from packeteer.parse import iter_packets, parse_packet, parse_pcap_file
from packeteer.parse.defragment import (
    AssembledFrame,
    Defragmenter,
    defragment,
    defragment_ipv4,
    defragment_ipv6,
)
from packeteer.pcap import LINKTYPE_RAW, write_pcap

_ETH = EthernetHeader("00:00:00:00:00:02", "00:00:00:00:00:01")
_PAYLOAD = bytes(range(256)) * 8


def _udp_datagram(payload: bytes = _PAYLOAD) -> bytes:
    """Return a UDP header (12345 -> 53) followed by *payload*."""
    return struct.pack("!HHHH", 12345, 53, 8 + len(payload), 0) + payload


def _v4_fragments(identification: int = 4242, mtu: int = 576,
                  payload: bytes = _PAYLOAD) -> list[bytes]:
    hdr = IPHeader("10.0.0.1", "10.0.0.2", socket.IPPROTO_UDP,
                   identification=identification)
    return fragment_ipv4(hdr, _udp_datagram(payload), mtu=mtu, eth_header=_ETH)


def _v6_fragments(mtu: int = 576, payload: bytes = _PAYLOAD) -> list[bytes]:
    hdr = IPv6Header("::1", "::2", next_header=socket.IPPROTO_UDP)
    return fragment_ipv6(hdr, _udp_datagram(payload), mtu=mtu, eth_header=_ETH)


def _plain_packet() -> bytes:
    return (PacketBuilder().ethernet()
            .ip(src="1.1.1.1", dst="2.2.2.2").tcp(dst_port=80).build())


class TestDefragmentIPv4(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore")

    def test_fragments_become_one_frame(self):
        frames = list(defragment(_v4_fragments()))
        self.assertEqual(len(frames), 1)

    def test_reassembled_payload_matches_original(self):
        frames = list(defragment(_v4_fragments()))
        self.assertEqual(parse_packet(frames[0]).payload, _PAYLOAD)

    def test_transport_header_recovered(self):
        pkt = parse_packet(list(defragment(_v4_fragments()))[0])
        self.assertEqual(pkt.transport.src_port, 12345)
        self.assertEqual(pkt.transport.dst_port, 53)

    def test_reassembled_header_is_not_a_fragment(self):
        pkt = parse_packet(list(defragment(_v4_fragments()))[0])
        self.assertEqual(pkt.ip.fragment_offset, 0)
        self.assertEqual(pkt.ip.flags & 0b001, 0)

    def test_reassembled_total_length_is_correct(self):
        pkt = parse_packet(list(defragment(_v4_fragments()))[0])
        self.assertEqual(pkt.ip.total_length, 20 + 8 + len(_PAYLOAD))

    def test_reassembled_checksum_is_valid(self):
        frame = list(defragment(_v4_fragments()))[0]
        header = frame[14:34]
        total = sum(struct.unpack("!10H", header))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        self.assertEqual(total, 0xFFFF)

    def test_out_of_order_fragments(self):
        frames = list(defragment(list(reversed(_v4_fragments()))))
        self.assertEqual(parse_packet(frames[0]).payload, _PAYLOAD)

    def test_interleaved_datagrams(self):
        a, b = _v4_fragments(identification=1), _v4_fragments(identification=2)
        mixed = [f for pair in zip(a, b, strict=True) for f in pair]
        frames = list(defragment(mixed))
        self.assertEqual(len(frames), 2)
        for frame in frames:
            self.assertEqual(parse_packet(frame).payload, _PAYLOAD)

    def test_round_trip_matches_unfragmented_packet(self):
        whole = (PacketBuilder().ethernet()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(src_port=12345, dst_port=53)
                 .payload(data=_PAYLOAD).build())
        reassembled = list(defragment(_v4_fragments()))[0]
        original, rebuilt = parse_packet(whole), parse_packet(reassembled)
        self.assertEqual(original.payload, rebuilt.payload)
        self.assertEqual(original.ip.src, rebuilt.ip.src)
        self.assertEqual(original.transport.dst_port, rebuilt.transport.dst_port)

    def test_ethernet_padding_not_reassembled_into_payload(self):
        payload = bytes(range(26))
        frags = _v4_fragments(mtu=44, payload=payload)
        padded = frags[:-1] + [frags[-1] + b"\x00" * (60 - len(frags[-1]))]
        frames = list(defragment(padded))
        self.assertEqual(parse_packet(frames[0]).payload, payload)


class TestDefragmentIPv6(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore")

    def test_fragments_become_one_frame(self):
        self.assertEqual(len(list(defragment(_v6_fragments()))), 1)

    def test_reassembled_payload_matches_original(self):
        frames = list(defragment(_v6_fragments()))
        self.assertEqual(parse_packet(frames[0]).payload, _PAYLOAD)

    def test_fragment_header_removed(self):
        pkt = parse_packet(list(defragment(_v6_fragments()))[0])
        self.assertIsNone(pkt.ip.fragment)

    def test_next_header_restored_to_transport(self):
        pkt = parse_packet(list(defragment(_v6_fragments()))[0])
        self.assertEqual(pkt.ip.next_header, socket.IPPROTO_UDP)
        self.assertEqual(pkt.transport.dst_port, 53)

    def test_payload_length_is_correct(self):
        pkt = parse_packet(list(defragment(_v6_fragments()))[0])
        self.assertEqual(pkt.ip.payload_length, 8 + len(_PAYLOAD))

    def test_out_of_order_fragments(self):
        frames = list(defragment(list(reversed(_v6_fragments()))))
        self.assertEqual(parse_packet(frames[0]).payload, _PAYLOAD)


class TestPassThrough(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore")

    def test_unfragmented_frame_unchanged(self):
        plain = _plain_packet()
        self.assertEqual(list(defragment([plain])), [plain])

    def test_order_preserved_around_a_datagram(self):
        plain = _plain_packet()
        frames = list(defragment([plain, *_v4_fragments(), plain]))
        self.assertEqual(len(frames), 3)
        self.assertEqual(frames[0], plain)
        self.assertEqual(frames[2], plain)

    def test_unknown_link_type_passes_through(self):
        frags = _v4_fragments()
        self.assertEqual(list(defragment(frags, link_type=999)), frags)

    def test_raw_ip_link_type(self):
        frags = [f[14:] for f in _v4_fragments()]     # strip Ethernet
        frames = list(defragment(frags, link_type=LINKTYPE_RAW))
        self.assertEqual(len(frames), 1)
        pkt = parse_packet(frames[0], link_type=LINKTYPE_RAW)
        self.assertEqual(pkt.payload, _PAYLOAD)

    def test_vlan_tagged_fragments(self):
        tagged = []
        for frame in _v4_fragments():
            vlan = struct.pack("!HH", 0x8100, 0x002A) + frame[12:14]
            tagged.append(frame[:12] + vlan + frame[14:])
        frames = list(defragment(tagged))
        self.assertEqual(len(frames), 1)
        self.assertEqual(parse_packet(frames[0]).payload, _PAYLOAD)


class TestIncompleteDatagrams(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore")

    def test_missing_fragment_yields_nothing(self):
        self.assertEqual(list(defragment(_v4_fragments()[:-1])), [])

    def test_missing_fragment_is_recorded(self):
        engine = Defragmenter()
        for frame in _v4_fragments()[:-1]:
            engine.feed(frame, 1.0)
        engine.flush()
        self.assertEqual(len(engine.incomplete), 1)
        lost = engine.incomplete[0]
        self.assertEqual((lost.src, lost.dst), ("10.0.0.1", "10.0.0.2"))
        self.assertEqual(lost.identification, 4242)
        self.assertEqual(lost.fragments_seen, 3)
        self.assertEqual(lost.reason, "timeout")

    def test_timeout_abandons_a_stale_datagram(self):
        frags = _v4_fragments()
        engine = Defragmenter(timeout_s=5.0)
        engine.feed(frags[0], 0.0)
        engine.feed(frags[1], 100.0)
        self.assertTrue(any(i.reason == "timeout" for i in engine.incomplete))

    def test_fragments_within_the_timeout_still_reassemble(self):
        frags = _v4_fragments()
        engine = Defragmenter(timeout_s=30.0)
        out = []
        for i, frame in enumerate(frags):
            out += engine.feed(frame, float(i))
        self.assertEqual(len(out), 1)
        self.assertEqual(engine.incomplete, [])

    def test_oversized_datagram_abandoned(self):
        engine = Defragmenter(max_datagram_bytes=100)
        for frame in _v4_fragments():
            engine.feed(frame, 1.0)
        self.assertTrue(any(i.reason == "too_large" for i in engine.incomplete))

    def test_buffer_cap_evicts_oldest(self):
        engine = Defragmenter(max_buffered_bytes=600)
        engine.feed(_v4_fragments(identification=1)[0], 0.0)
        engine.feed(_v4_fragments(identification=2)[0], 1.0)
        engine.feed(_v4_fragments(identification=3)[0], 2.0)
        self.assertTrue(any(i.reason == "evicted" for i in engine.incomplete))


class TestOverlapPolicy(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore")

    def test_ipv4_keeps_first_arrival(self):
        # A duplicate fragment with different content must not overwrite the
        # bytes already accepted — the classic overlap evasion.
        frags = _v4_fragments(identification=7)
        evil = bytearray(frags[1])
        evil[34:] = b"\xff" * (len(evil) - 34)
        engine, out = Defragmenter(), []
        for frame in [frags[0], frags[1], bytes(evil), *frags[2:]]:
            out += engine.feed(frame, 1.0)
        self.assertEqual(len(out), 1)
        self.assertEqual(parse_packet(out[0].frame).payload, _PAYLOAD)

    def test_ipv6_discards_the_datagram(self):
        # RFC 5722 requires an overlapping IPv6 datagram to be dropped whole.
        frags = _v6_fragments()
        evil = bytearray(frags[1])
        evil[62:] = b"\xff" * (len(evil) - 62)
        engine, out = Defragmenter(), []
        for frame in [frags[0], frags[1], bytes(evil), *frags[2:]]:
            out += engine.feed(frame, 1.0)
        engine.flush()
        self.assertEqual(out, [])
        self.assertTrue(any(i.reason == "overlap" for i in engine.incomplete))


class TestPerVersionHelpers(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore")

    def test_ipv4_helper_reassembles_v4(self):
        self.assertEqual(len(list(defragment_ipv4(_v4_fragments()))), 1)

    def test_ipv4_helper_passes_v6_through(self):
        frags = _v6_fragments()
        self.assertEqual(list(defragment_ipv4(frags)), frags)

    def test_ipv6_helper_reassembles_v6(self):
        self.assertEqual(len(list(defragment_ipv6(_v6_fragments()))), 1)

    def test_ipv6_helper_passes_v4_through(self):
        frags = _v4_fragments()
        self.assertEqual(list(defragment_ipv6(frags)), frags)


class TestNonFirstFragmentParsing(unittest.TestCase):
    """A non-first fragment carries no transport header to decode."""

    def setUp(self):
        warnings.simplefilter("ignore")

    def test_ipv4_non_first_fragment_has_no_transport(self):
        frags = _v4_fragments()
        self.assertIsNotNone(parse_packet(frags[0]).transport)
        for frame in frags[1:]:
            pkt = parse_packet(frame)
            self.assertIsNone(pkt.transport)
            self.assertGreater(len(pkt.payload), 0)

    def test_ipv6_non_first_fragment_has_no_transport(self):
        frags = _v6_fragments()
        self.assertIsNotNone(parse_packet(frags[0]).transport)
        for frame in frags[1:]:
            self.assertIsNone(parse_packet(frame).transport)

    def test_ipv4_fragment_payload_is_not_truncated(self):
        # A non-first fragment's payload must be its whole data — the eight
        # bytes a bogus transport header would have consumed are still there.
        datagram = _udp_datagram()
        frags = _v4_fragments()
        first_len = len(parse_packet(frags[0]).payload) + 8   # + the UDP header
        recovered = b"".join(parse_packet(f).payload for f in frags[1:])
        self.assertEqual(recovered, datagram[first_len:])


class TestProvenance(unittest.TestCase):
    """feed() reports which fragments went into each reassembled datagram."""

    def setUp(self):
        warnings.simplefilter("ignore")

    def _feed_all(
        self, frames: list[bytes], engine: Defragmenter | None = None,
    ) -> tuple[Defragmenter, list[AssembledFrame]]:
        engine = engine or Defragmenter()
        out = []
        for i, frame in enumerate(frames):
            out += engine.feed(frame, float(i), token=i)
        return engine, out

    def test_passthrough_reports_one_fragment(self):
        engine, out = self._feed_all([_plain_packet()])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].fragment_count, 1)
        self.assertEqual(out[0].tokens, [0])

    def test_passthrough_frame_is_unchanged(self):
        plain = _plain_packet()
        _, out = self._feed_all([plain])
        self.assertEqual(out[0].frame, plain)

    def test_reassembly_reports_every_contributing_token(self):
        frames = _v4_fragments()
        _, out = self._feed_all(frames)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].tokens, list(range(len(frames))))
        self.assertEqual(out[0].fragment_count, len(frames))

    def test_fragment_count_distinguishes_reassembly_from_passthrough(self):
        plain = _plain_packet()
        _, out = self._feed_all([plain, *_v4_fragments(), plain])
        counts = [a.fragment_count for a in out]
        self.assertEqual(counts[0], 1)
        self.assertGreater(counts[1], 1)
        self.assertEqual(counts[2], 1)

    def test_tokens_are_in_arrival_order_not_offset_order(self):
        # Fed last-fragment-first, the tokens come back in the order fed.
        frames = list(reversed(_v4_fragments()))
        _, out = self._feed_all(frames)
        self.assertEqual(out[0].tokens, list(range(len(frames))))

    def test_interleaved_datagrams_keep_their_own_tokens(self):
        a = _v4_fragments(identification=1)
        b = _v4_fragments(identification=2)
        mixed = [f for pair in zip(a, b, strict=True) for f in pair]
        _, out = self._feed_all(mixed)
        self.assertEqual(len(out), 2)
        first, second = sorted(out, key=lambda r: r.tokens[0])
        self.assertEqual(first.tokens, [0, 2, 4, 6])       # even positions
        self.assertEqual(second.tokens, [1, 3, 5, 7])      # odd positions

    def test_tokens_may_be_any_object(self):
        frames = _v4_fragments()
        engine, out = Defragmenter(), []
        markers = [object() for _ in frames]
        for frame, marker in zip(frames, markers, strict=True):
            out += engine.feed(frame, 1.0, token=marker)
        self.assertEqual(out[0].tokens, markers)

    def test_token_defaults_to_none(self):
        _, out = self._feed_all([_plain_packet()], Defragmenter())
        engine = Defragmenter()
        result = engine.feed(_plain_packet())
        self.assertEqual(result[0].tokens, [None])

    def test_incomplete_datagram_carries_its_tokens(self):
        engine, _ = self._feed_all(_v4_fragments()[:-1])
        engine.flush()
        lost = engine.incomplete[0]
        self.assertEqual(lost.tokens, [0, 1, 2])
        self.assertEqual(lost.fragments_seen, 3)

    def test_overlap_discard_records_tokens(self):
        frags = _v6_fragments()
        evil = bytearray(frags[1])
        evil[62:] = b"\xff" * (len(evil) - 62)
        engine, _ = self._feed_all([frags[0], frags[1], bytes(evil), *frags[2:]])
        engine.flush()
        overlapped = [i for i in engine.incomplete if i.reason == "overlap"]
        self.assertEqual(len(overlapped), 1)
        self.assertEqual(overlapped[0].tokens, [0, 1, 2])

    def test_pcap_records_as_tokens_give_file_offsets(self):
        # The intended use: tokens carry back where each fragment lived.
        import io

        from packeteer.pcap import open_pcap, write_pcap
        frames = _v4_fragments()
        buf = io.BytesIO()
        write_pcap([(f, i, 0) for i, f in enumerate(frames)], file_object=buf)
        buf.seek(0)
        with open_pcap(file_object=buf) as reader:
            engine, out = Defragmenter(link_type=reader.header.link_type), []
            for record in reader:
                out += engine.feed(record.data, record.ts_sec, token=record)
        self.assertEqual(len(out), 1)
        offsets = [r.data_offset for r in out[0].tokens]
        self.assertEqual(len(offsets), len(frames))
        self.assertEqual(sorted(offsets), offsets)      # ascending in the file

    def test_convenience_wrapper_still_yields_bytes(self):
        frames = list(defragment(_v4_fragments()))
        self.assertEqual(len(frames), 1)
        self.assertIsInstance(frames[0], bytes)


class TestFragmentSpecRoundTrip(unittest.TestCase):
    """A fragment must survive parse -> spec -> build."""

    def setUp(self):
        warnings.simplefilter("ignore")

    def _spec(self, frames: list[bytes]) -> dict:
        import io
        import json

        from packeteer.parse import parse_pcap_file
        from packeteer.pcap import write_pcap
        buf = io.BytesIO()
        write_pcap([(f, 0, 0) for f in frames], file_object=buf)
        buf.seek(0)
        return json.loads(parse_pcap_file(file_object=buf))

    def _rebuild(self, frames: list[bytes]) -> list[bytes]:
        import os
        import subprocess
        import sys
        import tempfile

        from packeteer.pcap import read_pcap, write_pcap
        directory = tempfile.mkdtemp()
        src = os.path.join(directory, "in.pcap")
        spec = os.path.join(directory, "spec.json")
        out = os.path.join(directory, "out.pcap")
        write_pcap([(f, 0, 0) for f in frames], path=src)
        subprocess.run([sys.executable, "-m", "packeteer", "parse", src, "-o", spec],
                       check=True, capture_output=True)
        subprocess.run([sys.executable, "-m", "packeteer", "build", spec, "--pcap", out],
                       check=True, capture_output=True)
        return [data for data, _, _ in read_pcap(path=out).packets]

    def test_later_fragment_keeps_its_payload_in_the_spec(self):
        # A later fragment has no transport section, so the payload has to be
        # emitted on its own — otherwise its bytes vanish from the spec.
        packet = self._spec(_v4_fragments())["packets"][1]
        self.assertNotIn("transport", packet)
        self.assertIn("payload", packet)
        self.assertGreater(len(packet["payload"]["data"]), 0)

    def test_ipv6_later_fragment_keeps_its_payload_in_the_spec(self):
        packet = self._spec(_v6_fragments())["packets"][1]
        self.assertIn("payload", packet)

    def test_ipv4_later_fragment_rebuilds_byte_for_byte(self):
        frames = _v4_fragments()
        self.assertEqual(self._rebuild(frames)[1:], frames[1:])

    def test_ipv6_later_fragment_rebuilds_byte_for_byte(self):
        frames = _v6_fragments()
        self.assertEqual(self._rebuild(frames)[1:], frames[1:])

    def test_ipv6_fragment_header_survives_the_spec(self):
        packet = self._spec(_v6_fragments())["packets"][1]
        fragment = packet["network"]["fragment"]
        self.assertGreater(fragment["fragment_offset"], 0)
        self.assertIn("identification", fragment)


class TestBuilderLaterFragment(unittest.TestCase):
    """A later fragment legitimately has no transport layer."""

    def test_ipv4_later_fragment_builds_without_a_transport(self):
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2",
                   protocol=socket.IPPROTO_UDP, flags=0, fragment_offset=69)
               .payload(data=b"\xaa" * 40).build())
        pkt = parse_packet(raw)
        self.assertEqual(pkt.ip.protocol, socket.IPPROTO_UDP)
        self.assertEqual(pkt.ip.fragment_offset, 69)
        self.assertIsNone(pkt.transport)
        self.assertEqual(pkt.payload, b"\xaa" * 40)

    def test_ipv6_later_fragment_builds_without_a_transport(self):
        raw = (PacketBuilder().ethernet()
               .ip(src="::1", dst="::2", protocol=socket.IPPROTO_UDP)
               .fragment_header(fragment_offset=66, more_fragments=False,
                                identification=7)
               .payload(data=b"\xbb" * 40).build())
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.ip.fragment)
        self.assertEqual(pkt.ip.fragment.fragment_offset, 66)
        self.assertEqual(pkt.ip.next_header, socket.IPPROTO_UDP)
        self.assertIsNone(pkt.transport)
        self.assertEqual(pkt.payload, b"\xbb" * 40)

    def test_first_fragment_still_requires_a_transport(self):
        builder = (PacketBuilder().ethernet()
                   .ip(src="10.0.0.1", dst="10.0.0.2", flags=1))
        with self.assertRaises(ValueError):
            builder.build()


if __name__ == "__main__":
    unittest.main()


class TestIterPackets(unittest.TestCase):
    """The front door: open, reassemble, and parse in one call."""

    def setUp(self):
        warnings.simplefilter("ignore")

    def _capture(self, frames: list[bytes]) -> io.BytesIO:
        buf = io.BytesIO()
        write_pcap([(f, i, 0) for i, f in enumerate(frames)], file_object=buf)
        buf.seek(0)
        return buf

    def test_fragments_arrive_as_one_packet(self):
        frames = _v4_fragments()
        packets = list(iter_packets(file_object=self._capture(frames)))
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].payload, _PAYLOAD)

    def test_transport_header_available(self):
        packets = list(iter_packets(file_object=self._capture(_v4_fragments())))
        self.assertEqual(packets[0].transport.dst_port, 53)

    def test_source_records_name_every_fragment(self):
        frames = _v4_fragments()
        packets = list(iter_packets(file_object=self._capture(frames)))
        self.assertEqual(len(packets[0].source_records), len(frames))

    def test_unfragmented_packet_has_one_source_record(self):
        packets = list(iter_packets(file_object=self._capture([_plain_packet()])))
        self.assertEqual(len(packets[0].source_records), 1)

    def test_defragment_false_yields_every_record(self):
        frames = _v4_fragments()
        packets = list(iter_packets(
            file_object=self._capture(frames), defragment=False,
        ))
        self.assertEqual(len(packets), len(frames))
        self.assertIsNone(packets[1].transport)      # a later fragment

    def test_timestamp_comes_from_the_completing_fragment(self):
        frames = _v4_fragments()
        packets = list(iter_packets(file_object=self._capture(frames)))
        self.assertEqual(packets[0].ts_sec, len(frames) - 1)
        self.assertEqual(packets[0].source_records[0].ts_sec, 0)

    def test_payload_offset_composes_with_data_offset(self):
        # The point of #71, #72 and #73 together: cite a payload's bytes.
        payload = b"\xde\xad\xbe\xef" * 8
        frame = (PacketBuilder().ethernet()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp().payload(data=payload).build())
        buf = self._capture([frame])
        blob = buf.getvalue()
        buf.seek(0)
        pkt = next(iter(iter_packets(file_object=buf)))
        start = pkt.source_records[0].data_offset + pkt.payload_offset
        self.assertEqual(blob[start: start + len(pkt.payload)], payload)

    def test_incomplete_datagram_is_dropped(self):
        packets = list(iter_packets(
            file_object=self._capture(_v4_fragments()[:-1]),
        ))
        self.assertEqual(packets, [])

    def test_order_preserved_around_a_datagram(self):
        plain = _plain_packet()
        frames = [plain, *_v4_fragments(), plain]
        packets = list(iter_packets(file_object=self._capture(frames)))
        self.assertEqual(len(packets), 3)
        self.assertEqual(packets[1].payload, _PAYLOAD)

    def test_decode_app_is_forwarded(self):
        http = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        frame = (PacketBuilder().ethernet()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .tcp(dst_port=80).payload(data=http).build())
        buf = self._capture([frame])
        self.assertIsNotNone(next(iter(iter_packets(file_object=buf))).http)
        buf.seek(0)
        pkt = next(iter(iter_packets(file_object=buf, decode_app=False)))
        self.assertIsNone(pkt.http)
        self.assertEqual(pkt.payload, http)

    def test_requires_exactly_one_source(self):
        with self.assertRaises(ValueError):
            list(iter_packets())
        with self.assertRaises(ValueError):
            list(iter_packets(path="x.pcap", file_object=io.BytesIO()))


class TestParsePcapFileDefragment(unittest.TestCase):
    """The spec path keeps fragments by default, to stay round-trippable."""

    def setUp(self):
        warnings.simplefilter("ignore")

    def _spec(self, frames: list[bytes], **kwargs: object) -> dict:
        buf = io.BytesIO()
        write_pcap([(f, i, 0) for i, f in enumerate(frames)], file_object=buf)
        buf.seek(0)
        return json.loads(parse_pcap_file(file_object=buf, **kwargs))

    def test_fragments_kept_by_default(self):
        frames = _v4_fragments()
        self.assertEqual(len(self._spec(frames)["packets"]), len(frames))

    def test_defragment_true_yields_whole_datagrams(self):
        spec = self._spec(_v4_fragments(), defragment=True)
        self.assertEqual(len(spec["packets"]), 1)
        self.assertIn("transport", spec["packets"][0])

    def test_default_still_round_trips_byte_for_byte(self):
        # Reassembling by default would end this guarantee, which is why it
        # is opt-in on the spec path.
        import os
        import subprocess
        import sys
        import tempfile

        from packeteer.pcap import read_pcap
        frames = _v4_fragments()
        directory = tempfile.mkdtemp()
        src = os.path.join(directory, "in.pcap")
        spec = os.path.join(directory, "spec.json")
        out = os.path.join(directory, "out.pcap")
        write_pcap([(f, 0, 0) for f in frames], path=src)
        subprocess.run([sys.executable, "-m", "packeteer", "parse", src, "-o", spec],
                       check=True, capture_output=True)
        subprocess.run([sys.executable, "-m", "packeteer", "build", spec, "--pcap", out],
                       check=True, capture_output=True)
        rebuilt = [data for data, _, _ in read_pcap(path=out).packets]
        self.assertEqual(rebuilt[1:], frames[1:])


class TestPacketReader(unittest.TestCase):
    """iter_packets exposes the file header and what reassembly dropped."""

    def setUp(self):
        warnings.simplefilter("ignore")

    def _capture(self, frames: list[bytes]) -> io.BytesIO:
        buf = io.BytesIO()
        write_pcap([(f, i, 0) for i, f in enumerate(frames)], file_object=buf)
        buf.seek(0)
        return buf

    def test_header_available_before_iterating(self):
        capture = iter_packets(file_object=self._capture([_plain_packet()]))
        self.assertEqual(capture.header.link_type, 1)
        self.assertEqual(capture.header.tick_hz, 1_000_000)
        capture.close()

    def test_iteration_is_unchanged(self):
        # The documented one-liner must keep working verbatim.
        packets = list(iter_packets(file_object=self._capture(_v4_fragments())))
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].payload, _PAYLOAD)

    def test_incomplete_is_reported(self):
        capture = iter_packets(file_object=self._capture(_v4_fragments()[:-1]))
        self.assertEqual(list(capture), [])
        self.assertEqual(len(capture.incomplete), 1)
        self.assertEqual(capture.incomplete[0].reason, "timeout")

    def test_incomplete_names_the_records_that_arrived(self):
        capture = iter_packets(file_object=self._capture(_v4_fragments()[:-1]))
        list(capture)
        offsets = [t.data_offset for t in capture.incomplete[0].tokens]
        self.assertEqual(len(offsets), 3)
        self.assertEqual(sorted(offsets), offsets)

    def test_incomplete_empty_without_reassembly(self):
        capture = iter_packets(
            file_object=self._capture(_v4_fragments()[:-1]), defragment=False,
        )
        list(capture)
        self.assertEqual(capture.incomplete, [])

    def test_context_manager(self):
        with iter_packets(file_object=self._capture([_plain_packet()])) as capture:
            self.assertEqual(len(list(capture)), 1)

    def test_close_is_idempotent(self):
        capture = iter_packets(file_object=self._capture([_plain_packet()]))
        capture.close()
        capture.close()

    def test_malformed_capture_raises_on_open_not_on_iteration(self):
        bad = io.BytesIO(b"\x00\x01\x02\x03" + b"\x00" * 40)
        with self.assertRaises(ValueError):
            iter_packets(file_object=bad)

    def test_link_type_override_reaches_the_header(self):
        capture = iter_packets(
            file_object=self._capture([_plain_packet()]), link_type=LINKTYPE_RAW,
        )
        self.assertEqual(capture.header.link_type, LINKTYPE_RAW)
        capture.close()


class TestTimestampErgonomics(unittest.TestCase):
    """A timestamp travels with the unit it is expressed in."""

    def setUp(self):
        warnings.simplefilter("ignore")

    def _ms_capture(self, ticks: int) -> io.BytesIO:
        from tests.test_parser_pcapng import _pcapng_with_tsresol
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2").udp().build())
        return _pcapng_with_tsresol([(raw, ticks)], tsresol_byte=3)

    def test_parsed_packet_carries_tick_hz(self):
        pkt = next(iter(iter_packets(file_object=self._ms_capture(100_250))))
        self.assertEqual(pkt.tick_hz, 1_000)

    def test_parsed_packet_timestamp_in_seconds(self):
        pkt = next(iter(iter_packets(file_object=self._ms_capture(100_250))))
        self.assertAlmostEqual(pkt.timestamp, 100.250, places=9)

    def test_record_carries_tick_hz_and_timestamp(self):
        from packeteer.pcap import open_pcap
        with open_pcap(file_object=self._ms_capture(100_250)) as reader:
            record = next(iter(reader))
        self.assertEqual(record.tick_hz, 1_000)
        self.assertAlmostEqual(record.timestamp, 100.250, places=9)

    def test_record_timestamp_ns_is_exact(self):
        from packeteer.pcap import open_pcap
        with open_pcap(file_object=self._ms_capture(100_250)) as reader:
            record = next(iter(reader))
        self.assertEqual(record.timestamp_ns, 100_250_000_000)

    def test_record_datetime_uses_the_right_unit(self):
        from packeteer.pcap import open_pcap
        with open_pcap(file_object=self._ms_capture(100_250)) as reader:
            record = next(iter(reader))
        self.assertEqual(record.datetime().isoformat(),
                         "1970-01-01T00:01:40.250000+00:00")

    def test_microsecond_capture_unchanged(self):
        packets = list(iter_packets(file_object=self._capture_us()))
        self.assertEqual(packets[0].tick_hz, 1_000_000)
        self.assertAlmostEqual(packets[0].timestamp, 7.000250, places=9)

    def _capture_us(self) -> io.BytesIO:
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2").udp().build())
        buf = io.BytesIO()
        write_pcap([(raw, 7, 250)], file_object=buf)
        buf.seek(0)
        return buf
