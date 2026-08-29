"""Reassembling a TCP byte stream into whole messages (#111)."""
from __future__ import annotations

import unittest

from packeteer.generate import PacketBuilder
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.parse import parse_packet
from packeteer.parse.reassemble import Reassembler

_MACS = {"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"}
_MSG = (6).to_bytes(2, "big") + b"abcdef"          # 8 bytes, length-prefixed


def _frame_length(prefix: bytes) -> int | None:
    """Two bytes of length, then that many bytes of body."""
    return None if len(prefix) < 2 else 2 + int.from_bytes(prefix[:2], "big")


def _segment(payload: bytes, seq: int, *, flags: int = 0x18, ts: int = 0,
             src_port: int = 1000) -> object:
    frame = (PacketBuilder().ethernet(**_MACS)
             .ip(src="10.0.0.1", dst="10.0.0.2")
             .tcp(src_port=src_port, dst_port=53, seq=seq, flags=flags)
             .payload(data=payload).build())
    pkt = parse_packet(frame, decode_app=False)
    pkt.ts_sec = ts
    return pkt


def _run(segments: list[tuple], **kwargs: object) -> tuple[list[bytes], list[str]]:
    """Feed *segments* and return the messages and the abandonment reasons."""
    engine = Reassembler(_frame_length, **kwargs)
    out: list[bytes] = []
    for index, item in enumerate(segments):
        payload, seq = item[0], item[1]
        extra = item[2] if len(item) > 2 else {}
        out += [m.data for m in engine.feed(_segment(payload, seq, **extra),
                                            token=index)]
    engine.flush()
    return out, [i.reason for i in engine.incomplete]


class TestOrdering(unittest.TestCase):
    """Bytes are placed by sequence number, never by arrival order."""

    def test_one_segment(self) -> None:
        self.assertEqual(_run([(_MSG, 1000)])[0], [_MSG])

    def test_split_across_three_segments(self) -> None:
        self.assertEqual(
            _run([(_MSG[:2], 1000), (_MSG[2:5], 1002), (_MSG[5:], 1005)])[0],
            [_MSG])

    def test_out_of_order(self) -> None:
        self.assertEqual(
            _run([(_MSG[5:], 1005), (_MSG[:2], 1000), (_MSG[2:5], 1002)])[0],
            [_MSG])

    def test_fully_reversed(self) -> None:
        """The first segment to arrive is not where the flow starts."""
        self.assertEqual(
            _run([(_MSG[5:], 1005), (_MSG[2:5], 1002), (_MSG[:2], 1000)])[0],
            [_MSG])

    def test_two_messages_in_one_segment(self) -> None:
        self.assertEqual(_run([(_MSG + _MSG, 1000)])[0], [_MSG, _MSG])

    def test_a_message_spanning_a_segment_boundary(self) -> None:
        pair = _MSG + _MSG
        self.assertEqual(_run([(pair[:5], 1000), (pair[5:], 1005)])[0],
                         [_MSG, _MSG])


class TestDuplicatesAndOverlaps(unittest.TestCase):

    def test_a_retransmission_is_dropped(self) -> None:
        messages, _ = _run([(_MSG[:5], 1000), (_MSG[:5], 1000), (_MSG[5:], 1005)])
        self.assertEqual(messages, [_MSG])

    def test_a_retransmission_after_the_message_was_delivered(self) -> None:
        messages, _ = _run([(_MSG, 1000), (_MSG, 1000)])
        self.assertEqual(messages, [_MSG])

    def test_an_overlap_contributes_only_its_new_part(self) -> None:
        self.assertEqual(_run([(_MSG[:5], 1000), (_MSG[3:], 1003)])[0], [_MSG])

    def test_a_syn_sets_where_the_data_starts(self) -> None:
        """A SYN consumes a sequence number, so data begins after it."""
        messages, _ = _run([(b"", 999, {"flags": 0x02}), (_MSG, 1000)])
        self.assertEqual(messages, [_MSG])


class TestGapsAndBounds(unittest.TestCase):
    """A reassembler without bounds is a crafted capture away from a crash."""

    def test_a_permanent_gap_is_reported_as_a_gap(self) -> None:
        messages, reasons = _run([(_MSG[:2], 1000), (_MSG[5:], 1005)])
        self.assertEqual(messages, [])
        self.assertEqual(reasons, ["gap"])

    def test_a_gap_is_not_spliced_over(self) -> None:
        """Joining the two halves would produce a plausible, wrong message."""
        messages, _ = _run([(_MSG[:2], 1000), (_MSG[5:], 1005)])
        self.assertEqual(messages, [])

    def test_a_stalled_flow_times_out(self) -> None:
        _, reasons = _run(
            [(_MSG[:2], 1000, {"ts": 0}), (_MSG[5:], 1005, {"ts": 100})],
            timeout_s=30)
        self.assertEqual(reasons, ["gap"])

    def test_a_message_over_the_size_cap_is_abandoned(self) -> None:
        messages, reasons = _run([(_MSG, 1000)], max_message_bytes=4)
        self.assertEqual(messages, [])
        self.assertEqual(reasons, ["too_large"])

    def test_too_many_flows_abandons_the_oldest(self) -> None:
        engine = Reassembler(_frame_length, max_flows=2)
        for port in (1001, 1002, 1003):
            engine.feed(_segment(_MSG[:2], 1000, src_port=port))
        self.assertIn("too_many_flows", [i.reason for i in engine.incomplete])

    def test_what_was_collected_is_reported(self) -> None:
        engine = Reassembler(_frame_length)
        engine.feed(_segment(_MSG[:5], 1000), token="first")
        engine.flush()
        lost = engine.incomplete[0]
        self.assertEqual(lost.bytes_seen, 5)
        self.assertEqual(lost.expected_bytes, 8)
        self.assertEqual(lost.tokens, ["first"])
        self.assertEqual(lost.flow.dst_port, 53)


class TestTokens(unittest.TestCase):

    def test_a_message_carries_the_packets_that_made_it(self) -> None:
        engine = Reassembler(_frame_length)
        out = []
        for index, (payload, seq) in enumerate(
                [(_MSG[:2], 1000), (_MSG[2:5], 1002), (_MSG[5:], 1005)]):
            out += engine.feed(_segment(payload, seq), token=index)
        self.assertEqual(out[0].tokens, [0, 1, 2])

    def test_tokens_do_not_leak_into_the_next_message(self) -> None:
        engine = Reassembler(_frame_length)
        first = engine.feed(_segment(_MSG, 1000), token="a")
        second = engine.feed(_segment(_MSG, 1008), token="b")
        self.assertEqual(first[0].tokens, ["a"])
        self.assertEqual(second[0].tokens, ["b"])


class TestAgainstPacketeersOwnImpairedStreams(unittest.TestCase):
    """The corpus that decided this had to be sequence-aware.

    `packeteer stream` emits spurious retransmissions and leaves permanent
    gaps where a segment was lost, so a reader trusting arrival order would
    mis-decode packeteer's own output — the first thing anyone would test a
    new spec against.
    """

    @staticmethod
    def _payload(index: int, direction: str) -> bytes:
        body = f"msg-{direction}-{index}".encode()
        return len(body).to_bytes(2, "big") + body

    def _messages(self, **impairments: object) -> tuple[list[str], list[str]]:
        config = TCPStreamConfig(seed=11, payload_fn=self._payload, **impairments)
        stream = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=9300,
            num_data_packets=8, config=config)
        engine = Reassembler(_frame_length)
        out: list[str] = []
        for index, packet in enumerate(stream.packets):
            pkt = parse_packet(packet.raw, decode_app=False)
            pkt.ts_sec = index
            out += [m.data[2:].decode() for m in engine.feed(pkt, token=index)]
        engine.flush()
        return out, [i.reason for i in engine.incomplete]

    def test_a_clean_stream_yields_every_message_once(self) -> None:
        messages, reasons = self._messages()
        self.assertEqual(len(messages), 8)
        self.assertEqual(len(set(messages)), 8)
        self.assertEqual(reasons, [])

    def test_spurious_retransmissions_produce_no_duplicates(self) -> None:
        messages, reasons = self._messages(retransmission_probability=0.6)
        self.assertEqual(len(messages), 8)
        self.assertEqual(len(set(messages)), 8, "a message was delivered twice")
        self.assertEqual(reasons, [])

    def test_a_retransmitted_loss_is_recovered(self) -> None:
        """The retransmission arrives after the FIN, and still fills its gap."""
        messages, reasons = self._messages(packet_loss_probability=0.3,
                                           retransmit_lost=True)
        self.assertEqual(len(set(messages)), 8)
        self.assertEqual(reasons, [])

    def test_a_permanent_loss_is_reported_rather_than_papered_over(self) -> None:
        messages, reasons = self._messages(packet_loss_probability=0.3)
        self.assertLess(len(messages), 8)
        self.assertEqual(reasons, ["gap"])


class TestSequenceWraparound(unittest.TestCase):

    def test_a_message_spanning_the_32_bit_wrap(self) -> None:
        near_end = (1 << 32) - 4
        messages, _ = _run([(_MSG[:4], near_end), (_MSG[4:], 0)])
        self.assertEqual(messages, [_MSG])


if __name__ == "__main__":
    unittest.main()
