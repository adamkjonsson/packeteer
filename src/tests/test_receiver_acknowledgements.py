"""The generated receiver acknowledges only what it received (#163).

`_apply_corruption` corrupts a segment after the connection is emitted, so the
emit-time receiver — the one that answers a *lost* segment with duplicate
ACKs — never saw the corruption.  Every acknowledgement after it was
cumulative and covered the corrupted range, and the one ACK the pass moved
kept a number lower than its predecessors'.  A consumer reading ack numbers
was told the receiver kept bytes it had rejected.

The fix runs the same receiver over the finished timeline.  These tests state
what a receiver says, in the terms `tcp_corrupt_ts.pcap` proved a real one
does — and the last class runs that file's own tests against a generated
stream.
"""
from __future__ import annotations

import io
import unittest
import warnings

from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.http import HTTPRestConfig, generate_http_stream
from packeteer.generate.tcp import TCP_ACK, TCP_FIN, TCP_SYN
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.parse import iter_packets
from packeteer.pcap import write_pcap

from . import test_real_corpus as corpus

_WRAP = 2 ** 32
_BASE = 1_700_000_000.0


def _after(a: int, b: int) -> bool:
    """RFC 1982: whether sequence number *a* is after *b*."""
    return 0 < ((a - b) % _WRAP) < _WRAP // 2


def _stream(**kwargs: object) -> list:
    """Return a low-level stream's packets in time order; config keys pass through."""
    fields = TCPStreamConfig.__dataclass_fields__
    config = {k: kwargs.pop(k) for k in list(kwargs) if k in fields}
    config.setdefault("seed", 2)
    config.setdefault("base_time", _BASE)
    kwargs.setdefault("num_data_packets", 40)
    stream = generate_tcp_stream(
        client_ip="10.0.0.1", server_ip="10.0.0.2",
        config=TCPStreamConfig(**config), **kwargs,
    )
    return sorted(stream.packets, key=lambda p: (p.ts_sec, p.ts_usec))


def _http(**impairments: object) -> list:
    """Return an HTTP stream's packets in time order, both directions carrying data."""
    stream = generate_http_stream(
        client_ip="10.0.0.1", server_ip="10.1.0.1", requests=8, seed=3,
        base_time=_BASE, mss=536,
        config=HTTPRestConfig(error_rate=0.0,
                              impairments=ImpairmentConfig(**impairments)),
    )
    return sorted(stream.packets, key=lambda p: (p.ts_sec, p.ts_usec))


def _seq_len(pkt: object) -> int:
    """Sequence space *pkt* consumes: payload, plus one each for SYN and FIN."""
    return pkt.payload_len + bool(pkt.flags & TCP_SYN) + bool(pkt.flags & TCP_FIN)


def _pairs(packets: list) -> list[tuple[int, int]]:
    """Index pairs (corrupted copy, its clean retransmission)."""
    pairs = []
    for i, pkt in enumerate(packets):
        if not pkt.label.startswith("CORRUPT["):
            continue
        inner = pkt.label[len("CORRUPT"):]
        resend = next(j for j in range(i + 1, len(packets))
                      if packets[j].label == f"RETRANS{inner}"
                      and packets[j].seq == pkt.seq)
        pairs.append((i, resend))
    return pairs


def _acks_between(packets: list, start: int, stop: int, direction: str) -> list:
    """Packets travelling the other way from *direction*, between two indices."""
    return [p for p in packets[start + 1:stop]
            if p.direction != direction and p.flags & TCP_ACK]


class TestACorruptedSegmentIsLostToTheReceiver(unittest.TestCase):
    """The issue's property, on both generators that share the pass."""

    def _streams(self) -> list[tuple[str, list]]:
        return [
            ("tcp_stream", _stream(payload_corruption_probability=0.2,
                                   retransmission_probability=0.3)),
            ("http", _http(payload_corruption_probability=0.3)),
        ]

    def test_no_ack_covers_a_corrupted_segment_before_its_resend(self) -> None:
        """For every CORRUPT[n], no ACK between it and RETRANS[n] has ack > seq."""
        for name, packets in self._streams():
            pairs = _pairs(packets)
            self.assertTrue(pairs, f"{name}: the stream should hold corruptions")
            for damaged, resend in pairs:
                seg = packets[damaged]
                between = _acks_between(packets, damaged, resend, seg.direction)
                with self.subTest(stream=name, label=seg.label):
                    self.assertTrue(between, "the far end kept talking")
                    for ack in between:
                        self.assertFalse(_after(ack.ack, seg.seq),
                                         f"{ack.label} acknowledges past the hole")

    def test_the_first_ack_after_the_resend_covers_it(self) -> None:
        for name, packets in self._streams():
            for damaged, resend in _pairs(packets):
                seg = packets[damaged]
                end = (seg.seq + seg.payload_len) % _WRAP
                after = next((p for p in packets[resend + 1:]
                              if p.direction != seg.direction and p.flags & TCP_ACK), None)
                with self.subTest(stream=name, label=seg.label):
                    self.assertIsNotNone(after, "the resend was acknowledged")
                    self.assertTrue(after.ack == end or _after(after.ack, end))

    def test_duplicate_acks_echo_what_arrived_in_order(self) -> None:
        """RFC 7323 §4.3, as `tcp_lossy_ts.pcap`'s test states it.

        Over a run of acknowledgements repeating one number, the echo does not
        move, though the sender goes on putting newer TSvals on the wire; and
        it never names the TSval of a segment from *behind* the hole — one
        whose sequence number is past the run's — that had arrived by then.
        Holes overlap, so an earlier hole's recovery may legitimately move the
        echo mid-way; that starts a new run.
        """
        packets = _stream(payload_corruption_probability=0.2)
        checked = runs = 0
        for damaged, resend in _pairs(packets):
            seg = packets[damaged]
            run = [p for p in _acks_between(packets, damaged, resend, seg.direction)
                   if p.ack == seg.seq]
            if not run:
                continue
            checked += 1
            with self.subTest(label=seg.label):
                self.assertEqual(len({p.timestamps[1] for p in run}), 1,
                                 "TS.Recent does not move while the hole is open")
                for ack in run:
                    behind = {
                        p.timestamps[0] for p in packets[:packets.index(ack)]
                        if p.direction == seg.direction and p.payload_len
                        and _after(p.seq, seg.seq)
                    }
                    self.assertNotIn(ack.timestamps[1], behind,
                                     "the echo names an out-of-order arrival")
                if len(run) > 1:
                    runs += 1
                    newer = {p.timestamps[0]
                             for p in packets[packets.index(run[0]):packets.index(run[-1])]
                             if p.direction == seg.direction and p.timestamps}
                    self.assertTrue(any(t > run[-1].timestamps[1] for t in newer),
                                    "newer TSvals went on the wire during the run")
        self.assertTrue(checked)
        self.assertTrue(runs, "no run of duplicate ACKs proved TS.Recent was left alone")

    def test_the_recovering_ack_jumps_over_what_was_held(self) -> None:
        """ACK-RECOVER[n] follows RETRANS[n], echoes it, and covers exactly what arrived.

        Everything below its number has a clean copy in the file before it;
        what starts at its number is either nothing or another hole.
        """
        packets = _stream(payload_corruption_probability=0.2)
        pairs = _pairs(packets)
        self.assertTrue(pairs)
        for damaged, resend in pairs:
            seg, copy = packets[damaged], packets[resend]
            inner = seg.label[len("CORRUPT"):]
            recover = next(p for p in packets[resend + 1:] if p.label == f"ACK-RECOVER{inner}")
            with self.subTest(label=seg.label):
                self.assertEqual(recover.timestamps[1], copy.timestamps[0])
                self.assertTrue(_after(recover.ack, seg.seq))
                arrived = [p for p in packets[:packets.index(recover)]
                           if p.direction == seg.direction and _seq_len(p)
                           and not p.label.startswith("CORRUPT[")]
                covered = [p for p in arrived
                           if not _after((p.seq + _seq_len(p)) % _WRAP, recover.ack)]
                self.assertTrue(covered)
                # Contiguous from the first byte to the ack number: no gap.
                edge = min(p.seq for p in covered if not p.flags & TCP_SYN)
                while True:
                    step = [p for p in covered if p.seq == edge and not p.flags & TCP_SYN]
                    if not step:
                        break
                    edge = (edge + _seq_len(step[0])) % _WRAP
                self.assertEqual(edge, recover.ack, "the receiver acknowledged a gap")
                at_edge = [p for p in packets[:packets.index(recover)]
                           if p.direction == seg.direction and p.seq == recover.ack
                           and p.payload_len]
                self.assertTrue(all(p.label.startswith("CORRUPT[") for p in at_edge),
                                "what starts at the ack number is not yet received")


class TestAcknowledgementsNeverGoBackwards(unittest.TestCase):
    """The invariant whose absence let the moved ACK's number fall.

    A cumulative acknowledgement never decreases, whatever the wire did.
    Asserted over every impairment the passes apply, alone and together, on
    both generators, and across a sequence-number wrap.

    Retransmitted copies included: #164 found that a resend carried the
    original's acknowledgement number, stale by the time it went out, and the
    sweep that found it is this test with the carve-out removed.  Strays are
    forged by a third party and say nothing about either receiver.
    """

    _COMBOS = (
        {"payload_corruption_probability": 0.3},
        {"packet_loss_probability": 0.2},
        {"packet_loss_probability": 0.2, "payload_corruption_probability": 0.3},
        {"payload_corruption_probability": 0.3, "retransmission_probability": 0.3},
        {"payload_corruption_probability": 0.3, "duplicate_probability": 0.2},
        {"payload_corruption_probability": 0.3, "stray_packet_count": 3},
        {"packet_loss_probability": 0.2, "payload_corruption_probability": 0.3,
             "retransmission_probability": 0.3, "duplicate_probability": 0.2,
             "stray_packet_count": 2},
    )

    def _assert_monotone(self, packets: list, name: str) -> None:
        for direction in ("c2s", "s2c"):
            acks = [p.ack for p in packets
                    if p.direction == direction and p.flags & TCP_ACK
                    and not p.label.startswith("STRAY")]
            for earlier, later in zip(acks, acks[1:], strict=False):
                with self.subTest(stream=name, direction=direction):
                    self.assertFalse(_after(earlier, later),
                                     f"ack went back from {earlier} to {later}")

    def test_on_the_low_level_generator(self) -> None:
        for seed in (1, 2, 3):
            for combo in self._COMBOS:
                self._assert_monotone(_stream(seed=seed, **combo), f"seed {seed} {combo}")

    def test_on_the_http_generator(self) -> None:
        for combo in self._COMBOS:
            if "packet_loss_probability" in combo:
                continue        # loss is not an ImpairmentConfig field
            self._assert_monotone(_http(**combo), str(combo))

    def test_across_a_sequence_number_wrap(self) -> None:
        """Serial arithmetic, in the model and in `_contiguous_ack`."""
        for combo in ({"payload_corruption_probability": 0.3},
                      {"packet_loss_probability": 0.3, "retransmit_lost": True}):
            packets = _stream(client_isn=_WRAP - 5000, server_isn=_WRAP - 100,
                              num_data_packets=30, **combo)
            self._assert_monotone(packets, str(combo))
            data = [p for p in packets if p.direction == "c2s" and p.payload_len]
            self.assertTrue(any(p.seq < _WRAP // 2 for p in data), "the stream wrapped")
            recover = [p for p in packets if p.label.startswith("ACK-RECOVER")][-1]
            with self.subTest(combo=str(combo)):
                # Before `_contiguous_ack` used serial arithmetic this stalled
                # at the segment straddling 2**32, just below it.
                self.assertLess(recover.ack, _WRAP // 2,
                                "the recovering ACK crossed the wrap")
                first = min(data, key=lambda p: (p.seq - (_WRAP - 5000)) % _WRAP).seq
                sent = max((p.seq + p.payload_len - first) % _WRAP for p in data)
                self.assertGreaterEqual((recover.ack - first) % _WRAP, sent,
                                        "and reached the end of the data")


class TestTheGeneratedReceiverPassesTheRealFilesTests(corpus.TestACorruptedSegmentAndItsResend):
    """`tcp_corrupt_ts.pcap`'s own tests, run against a generated stream.

    The real file is what a receiver does when a segment is corrupted in
    flight: the damaged copy fails its checksum and is the only one that does,
    the clean resend fills the hole with a newer TSval, and the covering ACK
    echoes the resend.  A generated stream is written to a pcap, read back
    through the parser, and held to the same assertions.
    """

    _packets: list | None = None

    def _fields(self, name: str) -> list:
        if self._packets is None:
            stream = generate_tcp_stream(
                client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=40,
                config=TCPStreamConfig(seed=2, base_time=_BASE,
                                       payload_corruption_probability=0.2),
            )
            buf = io.BytesIO()
            write_pcap(stream.to_pcap_tuples(), file_object=buf)
            buf.seek(0)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with iter_packets(file_object=buf, decode_app=False, defragment=False) as cap:
                    type(self)._packets = list(cap)
        return list(self._packets)

    def test_the_damaged_copy_and_its_resend_differ_in_payload(self) -> None:
        """Packeteer flips a whole byte where netem flips a bit; the copies still differ."""
        packets, _, pairs = self._corruptions()
        for damaged, resend in pairs:
            a, b = packets[damaged], packets[resend]
            with self.subTest(seq=a.transport.seq):
                self.assertEqual(len(a.payload), len(b.payload))
                diff = [i for i, (x, y) in enumerate(zip(a.payload, b.payload, strict=True))
                        if x != y]
                self.assertEqual(len(diff), 1, "one byte differs")
                self.assertGreater(self._tsval(b), self._tsval(a))

    def test_both_ends_negotiated_timestamps(self) -> None:
        syns = [p for p in self._fields("") if p.transport.flags & TCP_SYN]
        self.assertEqual(len(syns), 2)
        for syn in syns:
            self.assertIsNotNone(self._tsval(syn))
