"""A generated connection negotiates TCP timestamps and carries them (#90).

#88 put a plausible option set on the handshake and deliberately left
timestamps out, because a connection that negotiates them carries one on
every segment and the generators put options on the handshake only.  Now
they do not: both emit loops carry a Timestamps option on every segment once
the SYN and SYN-ACK have both advertised it, with a per-side 1 ms clock and
an echo that follows what actually arrived, and the impairment passes rebuild
a retransmission with the clock at its *re*send time rather than copying the
original — which is how an analyser tells the two apart.

Every assertion here reads the option back through the parser rather than
picking bytes out of the header, so it holds for whatever layout the encoder
chooses.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from packeteer.generate import PacketBuilder
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.http import HTTPRestConfig, generate_http_stream
from packeteer.generate.session import TCPSession
from packeteer.generate.tcp import TCP_ACK, TCP_SYN, TCPOptions, default_syn_options
from packeteer.generate.tcp_stream import TCPStream, TCPStreamConfig, generate_tcp_stream
from packeteer.parse import parse_packet
from packeteer.pcap import read_pcap

_BASE = 1_700_000_000.0
_NO_TS = TCPOptions(mss=1460, sack_permitted=True, window_scale=7)


def _stream(**kwargs: object) -> TCPStream:
    config_fields = TCPStreamConfig.__dataclass_fields__
    config = {k: kwargs.pop(k) for k in list(kwargs) if k in config_fields}
    config.setdefault("seed", 7)
    config.setdefault("base_time", _BASE)
    kwargs.setdefault("num_data_packets", 6)
    return generate_tcp_stream(
        client_ip="10.0.0.1", server_ip="10.0.0.2",
        config=TCPStreamConfig(**config), **kwargs,
    )


def _wire_timestamps(raw: bytes) -> tuple[int, int] | None:
    """Return the Timestamps option as the parser reads it, or None."""
    transport = parse_packet(raw).transport
    return transport.options.timestamps if transport.options else None


def _by_time(stream: TCPStream) -> list:
    return sorted(stream.packets, key=lambda p: (p.ts_sec, p.ts_usec))


class TestEverySegmentCarriesOne(unittest.TestCase):

    def test_negotiated_by_default(self) -> None:
        for pkt in _stream().packets:
            with self.subTest(label=pkt.label):
                self.assertIsNotNone(pkt.timestamps)
                self.assertEqual(_wire_timestamps(pkt.raw), pkt.timestamps,
                                 "the record and the wire agree")

    def test_the_syn_echoes_zero(self) -> None:
        syn = next(p for p in _stream().packets if p.flags == TCP_SYN)
        self.assertEqual(syn.timestamps[1], 0)

    def test_the_syn_ack_echoes_the_syn(self) -> None:
        packets = _stream().packets
        syn = next(p for p in packets if p.flags == TCP_SYN)
        synack = next(p for p in packets if p.flags == TCP_SYN | TCP_ACK)
        self.assertEqual(synack.timestamps[1], syn.timestamps[0])

    def test_the_layout_is_nop_nop_timestamp_after_the_handshake(self) -> None:
        """RFC 7323 A.2, and what every real stack emits."""
        data = next(p for p in _stream().packets if p.label == "DATA[0]")
        ip_start = 14
        tcp_start = ip_start + (data.raw[ip_start] & 0x0F) * 4
        self.assertEqual(data.raw[tcp_start + 12] >> 4, 8, "20 bytes + 12 of options")
        self.assertEqual(data.raw[tcp_start + 20:tcp_start + 24], b"\x01\x01\x08\x0a")
        header = parse_packet(data.raw).transport
        self.assertIsNone(header.options.raw, "the canonical layout round-trips")

    def test_none_without_the_advertisement(self) -> None:
        for pkt in _stream(client_options=_NO_TS, server_options=_NO_TS).packets:
            with self.subTest(label=pkt.label):
                self.assertIsNone(pkt.timestamps)
                self.assertIsNone(_wire_timestamps(pkt.raw))

    def test_none_with_bare_handshakes(self) -> None:
        for pkt in _stream(client_options=None, server_options=None).packets:
            self.assertIsNone(_wire_timestamps(pkt.raw))

    def test_one_side_advertising_is_not_a_negotiation(self) -> None:
        """RFC 7323 §3.2: only what both sides advertised is used.

        A SYN-ACK may carry the option only if the SYN did, and the
        connection carries it after the handshake only when both did.
        """
        packets = _stream(server_options=_NO_TS).packets
        syn = next(p for p in packets if p.flags == TCP_SYN)
        self.assertIsNotNone(_wire_timestamps(syn.raw), "the client still asks")
        for pkt in packets[1:]:
            with self.subTest(label=pkt.label):
                self.assertIsNone(_wire_timestamps(pkt.raw))

        packets = _stream(client_options=_NO_TS).packets
        for pkt in packets:
            with self.subTest(label=pkt.label):
                self.assertIsNone(_wire_timestamps(pkt.raw),
                                  "the server may not offer what was not asked")


class TestTheClock(unittest.TestCase):

    def test_tsval_never_decreases_per_direction(self) -> None:
        for jitter in (0.0, 0.0005, 0.003):
            with self.subTest(jitter=jitter):
                stream = _stream(gap_jitter=jitter, num_data_packets=40)
                for direction in ("c2s", "s2c"):
                    values = [p.timestamps[0] for p in stream.packets
                              if p.direction == direction]
                    self.assertEqual(values, sorted(values))

    def test_tsval_tracks_the_capture_timeline(self) -> None:
        """A 1 ms tick: two segments 50 ms apart differ by about 50."""
        stream = _stream(inter_packet_gap=0.05, gap_jitter=0.0)
        c2s = [p for p in stream.packets if p.direction == "c2s"]
        first, last = c2s[0], c2s[-1]
        elapsed_ms = ((last.ts_sec - first.ts_sec) * 1_000_000
                      + (last.ts_usec - first.ts_usec)) // 1000
        self.assertEqual(last.timestamps[0] - first.timestamps[0], elapsed_ms)

    def test_each_side_starts_at_its_own_seeded_value(self) -> None:
        a, b = _stream(seed=1), _stream(seed=1)
        self.assertEqual([p.timestamps for p in a.packets], [p.timestamps for p in b.packets])
        syn = next(p for p in a.packets if p.flags == TCP_SYN)
        synack = next(p for p in a.packets if p.flags == TCP_SYN | TCP_ACK)
        self.assertNotEqual(syn.timestamps[0], synack.timestamps[0])
        self.assertNotEqual([p.timestamps for p in _stream(seed=2).packets],
                            [p.timestamps for p in a.packets])

    def test_an_advertised_tsval_is_the_clock_start(self) -> None:
        opts = TCPOptions(mss=1460, timestamps=(12345, 0))
        stream = _stream(client_options=opts, server_options=default_syn_options())
        syn = next(p for p in stream.packets if p.flags == TCP_SYN)
        self.assertEqual(syn.timestamps[0], 12345)


class TestTheEcho(unittest.TestCase):
    """TSecr is the latest TSval that arrived from the peer, in order."""

    def test_every_segment_echoes_the_last_delivered_value(self) -> None:
        stream = _stream(gap_jitter=0.0)
        last_seen = {"c2s": 0, "s2c": 0}       # latest TSval sent per direction
        for pkt in _by_time(stream):
            other = "s2c" if pkt.direction == "c2s" else "c2s"
            with self.subTest(label=pkt.label):
                self.assertEqual(pkt.timestamps[1], last_seen[other])
            last_seen[pkt.direction] = pkt.timestamps[0]

    def test_after_a_loss_the_echo_sticks_like_the_ack_number(self) -> None:
        """A receiver echoes only in-order arrivals (RFC 7323 §4.3)."""
        stream = _stream(packet_loss_probability=0.5, num_data_packets=12, gap_jitter=0.0)
        packets = _by_time(stream)
        acks = [p for p in packets if p.direction == "s2c" and p.label.startswith("ACK[")]
        self.assertGreater(len(acks), 1)
        # Find a run of duplicate ACKs (ack number unchanged): their TSecr is
        # unchanged too, however many data segments arrived in between.
        stuck = [(a.ack, a.timestamps[1]) for a in acks]
        by_ack: dict[int, set[int]] = {}
        for ack, echo in stuck:
            by_ack.setdefault(ack, set()).add(echo)
        self.assertTrue(any(len(echoes) == 1 for echoes in by_ack.values()))
        for ack, echoes in by_ack.items():
            with self.subTest(ack=ack):
                self.assertEqual(len(echoes), 1, "same ack number, same echo")


class TestRetransmissionsAreFreshlyStamped(unittest.TestCase):

    def _original_and_copies(self, stream: TCPStream, kind: str) -> list[tuple]:
        pairs = []
        for copy in stream.packets:
            if not copy.label.startswith(kind):
                continue
            index = copy.label[len(kind) + 1:-1]
            original = next(p for p in stream.packets
                            if p.label in (f"DATA[{index}]", f"CORRUPT[{index}]"))
            pairs.append((original, copy))
        self.assertTrue(pairs, f"no {kind} packets")
        return pairs

    def test_a_spurious_retransmission(self) -> None:
        stream = _stream(retransmission_probability=1.0)
        for original, copy in self._original_and_copies(stream, "RETRANS"):
            with self.subTest(label=copy.label):
                self.assertEqual(copy.seq, original.seq)
                self.assertEqual(copy.payload_len, original.payload_len)
                self.assertGreater(copy.timestamps[0], original.timestamps[0])
                self.assertEqual(_wire_timestamps(copy.raw), copy.timestamps)
                self.assertNotEqual(copy.raw, original.raw)

    def test_a_recovered_loss(self) -> None:
        stream = _stream(packet_loss_probability=0.5, retransmit_lost=True, num_data_packets=12)
        recovered = [p for p in stream.packets if p.label.startswith("RETRANS")]
        self.assertTrue(recovered)
        for copy in recovered:
            with self.subTest(label=copy.label):
                self.assertIsNotNone(copy.timestamps)
                self.assertEqual(_wire_timestamps(copy.raw), copy.timestamps)

    def test_the_recovery_ack_echoes_the_retransmission(self) -> None:
        stream = _stream(packet_loss_probability=0.5, retransmit_lost=True, num_data_packets=12)
        packets = _by_time(stream)
        for ack in (p for p in packets if p.label.startswith("ACK-RECOVER")):
            index = ack.label[len("ACK-RECOVER") + 1:-1]
            retrans = next(p for p in packets if p.label == f"RETRANS[{index}]")
            with self.subTest(label=ack.label):
                self.assertEqual(ack.timestamps[1], retrans.timestamps[0])
                self.assertEqual(_wire_timestamps(ack.raw), ack.timestamps)

    def test_a_corrupted_copy_keeps_the_original_stamp(self) -> None:
        """It *is* the original transmission, with a byte flipped in flight."""
        stream = _stream(payload_corruption_probability=1.0)
        for corrupt in (p for p in stream.packets if p.label.startswith("CORRUPT")):
            self.assertEqual(_wire_timestamps(corrupt.raw), corrupt.timestamps)
        for original, copy in self._original_and_copies(stream, "RETRANS"):
            with self.subTest(label=copy.label):
                self.assertGreater(copy.timestamps[0], original.timestamps[0])

    def test_the_moved_ack_echoes_the_clean_retransmission(self) -> None:
        stream = _stream(payload_corruption_probability=1.0, gap_jitter=0.0)
        packets = _by_time(stream)
        for retrans in (p for p in packets if p.label.startswith("RETRANS")):
            index = retrans.label[len("RETRANS") + 1:-1]
            ack = next(p for p in packets if p.label == f"ACK[{index}]")
            with self.subTest(index=index):
                self.assertGreater((ack.ts_sec, ack.ts_usec), (retrans.ts_sec, retrans.ts_usec))
                self.assertEqual(ack.timestamps[1], retrans.timestamps[0])

    def test_a_rebuilt_copy_keeps_a_tiny_payload_exact(self) -> None:
        """A padded frame's payload must be read back, not sliced off the end.

        A frame under 60 bytes is padded after the payload; slicing
        ``raw[-payload_len:]`` would hand the rebuild the padding.
        """
        stream = _stream(retransmission_probability=1.0, num_data_packets=2,
                         payload_sizes=[1, 2])
        for original, copy in self._original_and_copies(stream, "RETRANS"):
            with self.subTest(label=copy.label):
                self.assertEqual(parse_packet(copy.raw).payload,
                                 parse_packet(original.raw).payload)

    def test_without_timestamps_a_copy_is_verbatim(self) -> None:
        """The pre-#90 behaviour, kept for connections that did not negotiate."""
        stream = _stream(retransmission_probability=1.0,
                         client_options=_NO_TS, server_options=_NO_TS)
        for original, copy in self._original_and_copies(stream, "RETRANS"):
            self.assertEqual(copy.raw, original.raw)


class TestSegmentSize(unittest.TestCase):

    def test_a_full_mss_stream_fits_the_mtu(self) -> None:
        """Twelve bytes of option would push a 1460-byte payload over 1514."""
        stream = _stream(payload_distribution="fixed", num_data_packets=4)
        for pkt in stream.packets:
            with self.subTest(label=pkt.label):
                self.assertLessEqual(len(pkt.raw), 1514)
        data = [p for p in stream.packets if p.label.startswith("DATA")]
        self.assertEqual({p.payload_len for p in data}, {1448})

    def test_uncapped_without_timestamps(self) -> None:
        stream = _stream(payload_distribution="fixed", num_data_packets=2,
                         client_options=_NO_TS, server_options=_NO_TS)
        data = [p for p in stream.packets if p.label.startswith("DATA")]
        self.assertEqual({p.payload_len for p in data}, {1460})

    def test_explicit_sizes_are_the_callers_business(self) -> None:
        stream = _stream(payload_sizes=[1460, 1460], num_data_packets=2)
        data = [p for p in stream.packets if p.label.startswith("DATA")]
        self.assertEqual({p.payload_len for p in data}, {1460})

    def test_the_session_segments_at_mss_less_twelve(self) -> None:
        session = TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", mss=1000,
                             base_time=_BASE,
                             client_options=default_syn_options(),
                             server_options=default_syn_options())
        stream = session.send(b"x" * 2500).build()
        data = [p for p in stream.packets if p.payload_len]
        self.assertEqual([p.payload_len for p in data], [988, 988, 524])


class TestTheSessionPath(unittest.TestCase):
    """TCPSession is the second emit loop; the HTTP payloads go through it."""

    def test_the_session_negotiates(self) -> None:
        stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", base_time=_BASE,
                             client_options=default_syn_options(),
                             server_options=default_syn_options())
                  .send(b"hello").recv(b"world").build())
        for pkt in stream.packets:
            with self.subTest(label=pkt.label):
                self.assertIsNotNone(pkt.timestamps)
                self.assertEqual(_wire_timestamps(pkt.raw), pkt.timestamps)
        last_seen = {"c2s": 0, "s2c": 0}
        for pkt in _by_time(stream):
            other = "s2c" if pkt.direction == "c2s" else "c2s"
            self.assertEqual(pkt.timestamps[1], last_seen[other], pkt.label)
            last_seen[pkt.direction] = pkt.timestamps[0]

    def test_a_bare_session_still_carries_none(self) -> None:
        stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", base_time=_BASE)
                  .send(b"hello").build())
        for pkt in stream.packets:
            self.assertIsNone(_wire_timestamps(pkt.raw))

    def test_http_payloads_negotiate_and_restamp(self) -> None:
        stream = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2", requests=3, seed=5, base_time=_BASE,
            config=HTTPRestConfig(impairments=ImpairmentConfig(retransmission_probability=1.0)),
        )
        retrans = [p for p in stream.packets if p.label.startswith("RETRANS")]
        self.assertTrue(retrans)
        for pkt in stream.packets:
            with self.subTest(label=pkt.label):
                self.assertIsNotNone(pkt.timestamps)
                self.assertEqual(_wire_timestamps(pkt.raw), pkt.timestamps)

    def test_http_is_still_seed_deterministic(self) -> None:
        def run() -> list[bytes]:
            return [p.raw for p in generate_http_stream(
                client_ip="10.0.0.1", server_ip="10.0.0.2", requests=3, seed=5,
                base_time=_BASE).packets]
        self.assertEqual(run(), run())


class TestTheCommandLine(unittest.TestCase):

    def _run(self, *extra: str) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "s.pcap"
            done = subprocess.run(
                [sys.executable, "-m", "packeteer", "stream", "--protocol", "tcp",
                 "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
                 "--packets", "3", "--seed", "1", "--pcap", str(out), *extra],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            return [_wire_timestamps(data) for data, _, _ in read_pcap(path=str(out)).packets]

    def test_stream_carries_them_by_default(self) -> None:
        self.assertTrue(all(ts is not None for ts in self._run()))

    def test_no_tcp_options_removes_them_too(self) -> None:
        self.assertTrue(all(ts is None for ts in self._run("--no-tcp-options")))


class TestTheLowLevelBuilderIsUnchanged(unittest.TestCase):

    def test_a_single_syn_carries_what_default_syn_options_says(self) -> None:
        frame = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
                 .tcp(dst_port=80, flags=TCP_SYN, options=default_syn_options()).build())
        self.assertEqual(_wire_timestamps(frame), (0, 0))


if __name__ == "__main__":
    unittest.main()
