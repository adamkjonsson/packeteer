"""The capture-point duplication impairment (#150).

#90 made every generated resend carry the sender's clock at its resend time.
That is what lets an analyser tell a retransmission from a duplicate — and it
left packeteer able to generate only one side of the distinction, because
every repeat it could produce had a *new* TSval.

A duplicate is not the sender acting.  It is one transmission seen twice by
the capture point: a SPAN port mirroring both directions of a trunk, a capture
on two interfaces the packet crossed, a veth pair.  Bytes, sequence numbers,
checksum and TSval are identical; only the capture timestamp differs.

`testcases/real/tcp_dup_ts.pcap` is what ten real ones look like, and the
offset used here is measured from it rather than chosen.
"""
from __future__ import annotations

import unittest
from collections import Counter

from packeteer.generate.impairments import _DUPLICATE_OFFSET_USEC, ImpairmentConfig
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream

_ADDRESSES = {"client_ip": "10.0.0.1", "server_ip": "10.0.0.2"}


def _stream(**config: object) -> list:
    stream = generate_tcp_stream(
        config=TCPStreamConfig(**config), num_data_packets=20, **_ADDRESSES)
    return list(stream.client_packets()) + list(stream.server_packets())


def _tsval(pkt: object) -> int | None:
    stamps = getattr(pkt, "timestamps", None)
    return stamps[0] if stamps else None


def _usec(pkt: object) -> int:
    return pkt.ts_sec * 1_000_000 + pkt.ts_usec


class TestACopyIsTheSameTransmission(unittest.TestCase):

    def setUp(self) -> None:
        self.packets = _stream(seed=42, duplicate_probability=1.0)
        self.duplicates = [p for p in self.packets if p.label.startswith("DUP")]
        self.originals = [p for p in self.packets
                          if not p.label.startswith("DUP")]

    def test_every_packet_appears_twice(self) -> None:
        self.assertEqual(len(self.duplicates), len(self.originals))

    def test_each_pair_is_byte_identical(self) -> None:
        """The property, stated plainly: the sender did not act again."""
        counts = Counter(p.raw for p in self.packets)
        self.assertEqual(
            [raw for raw, n in counts.items() if n != 2], [],
            "every frame should appear exactly twice, unchanged",
        )

    def test_each_pair_carries_the_same_tsval(self) -> None:
        """What distinguishes this from a retransmission, and the whole point.

        #90 rebuilds a resend with a fresh clock.  If a copy went through the
        same path it would get one too, and the two shapes would be
        indistinguishable in a generated capture.
        """
        by_raw: dict[bytes, set] = {}
        for pkt in self.packets:
            by_raw.setdefault(pkt.raw, set()).add(_tsval(pkt))
        for raw, stamps in by_raw.items():
            with self.subTest(seq=len(raw)):
                self.assertEqual(len(stamps), 1)

    def test_acknowledgements_are_duplicated_too(self) -> None:
        """A mirror doubles everything, not just the data segments.

        Every other pass in `impairments.py` works over `data_idx`; this one
        does not, and that difference is the behaviour being asserted.
        """
        carried_no_payload = [p for p in self.duplicates if p.payload_len == 0]
        self.assertTrue(
            carried_no_payload,
            "pure ACKs and handshake packets should be duplicated as well",
        )

    def test_the_copy_is_adjacent_not_an_rto_later(self) -> None:
        """Measured from `tcp_dup_ts.pcap`: 0-2 microseconds, median 1."""
        by_raw: dict[bytes, list[int]] = {}
        for pkt in self.packets:
            by_raw.setdefault(pkt.raw, []).append(_usec(pkt))
        for raw, times in by_raw.items():
            times.sort()
            with self.subTest(size=len(raw)):
                self.assertEqual(times[1] - times[0], _DUPLICATE_OFFSET_USEC)

    def test_no_two_packets_share_a_timestamp(self) -> None:
        """`_alloc_usec`'s job: a copy lands next to its original, not on it."""
        stamps = [_usec(p) for p in self.packets]
        self.assertEqual(len(stamps), len(set(stamps)))


class TestItIsAppliedLast(unittest.TestCase):
    """A mirror sees whatever reached it, including the other impairments.

    So a retransmission can itself be duplicated, and a corrupted copy is
    doubled as corrupted.  The nested label is the evidence.
    """

    def _find_nested(self, kind: str, **impairment: object) -> list[str]:
        for seed in range(80):
            packets = _stream(seed=seed, duplicate_probability=0.5,
                              **impairment)
            nested = [p.label for p in packets
                      if p.label.startswith(f"DUP[{kind}")]
            if nested:
                return nested
        return []

    def test_a_retransmission_can_be_duplicated(self) -> None:
        nested = self._find_nested("RETRANS", retransmission_probability=0.5)
        self.assertTrue(nested, "no duplicated retransmission in 80 seeds")
        self.assertRegex(nested[0], r"^DUP\[RETRANS\[.+\]\]$")

    def test_a_corrupted_segment_can_be_duplicated(self) -> None:
        nested = self._find_nested("CORRUPT",
                                   payload_corruption_probability=0.5)
        self.assertTrue(nested, "no duplicated corrupt segment in 80 seeds")
        self.assertRegex(nested[0], r"^DUP\[CORRUPT\[.+\]\]$")


class TestTheDefaultChangesNothing(unittest.TestCase):
    """`ImpairmentConfig`'s standing guarantee: a zero rate draws no randomness.

    A capture generated without impairments has to reproduce from its seed
    exactly as it did before this field existed, or every test pinned to a
    seeded capture breaks for no reason.
    """

    def test_zero_leaves_the_stream_byte_identical(self) -> None:
        without = [p.raw for p in _stream(seed=7)]
        with_zero = [p.raw for p in _stream(seed=7, duplicate_probability=0.0)]
        self.assertEqual(without, with_zero)

    def test_timestamps_are_untouched_too(self) -> None:
        # base_time is pinned: it defaults to time.time(), so two streams
        # generated a moment apart differ for a reason that is not this field.
        without = [_usec(p) for p in _stream(seed=7, base_time=1_000_000.0)]
        with_zero = [_usec(p) for p in _stream(seed=7, base_time=1_000_000.0,
                                               duplicate_probability=0.0)]
        self.assertEqual(without, with_zero)

    def test_the_same_seed_reproduces(self) -> None:
        first = [p.raw for p in _stream(seed=9, duplicate_probability=0.3)]
        second = [p.raw for p in _stream(seed=9, duplicate_probability=0.3)]
        self.assertEqual(first, second)

    def test_it_counts_as_a_post_pass(self) -> None:
        """Or a stream configured with only this impairment would skip it."""
        self.assertTrue(ImpairmentConfig(duplicate_probability=0.1).any_post_pass)
        self.assertFalse(ImpairmentConfig().any_post_pass)


if __name__ == "__main__":
    unittest.main()
