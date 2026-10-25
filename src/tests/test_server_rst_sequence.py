"""A server RST carries the server's real sequence state (#218).

The RST a server sends numbers from ``SND.NXT``, the end of everything it
has sent, and acknowledges ``RCV.NXT``, the end of what it has received from
the client in order.  A receiver checking an RST against its own
``RCV.NXT`` (RFC 5961 §3) ignores one that does not match.  Before #218 the
RST copied the server's ACK of the segment the connection was cut at, so
server data sent after that ACK — an HTTP response — was not counted, and
when loss had removed that ACK it fell back to the SYN-ACK's own sequence
number, one short of anything the server could send next.

The expected values here are worked out from the packets themselves, the
way a reader of the capture would, not from the generator's state.
"""
from __future__ import annotations

import unittest

from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.http import HTTPRestConfig, generate_http_stream
from packeteer.generate.tcp import TCP_FIN, TCP_RST, TCP_SYN
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.parse import parse_packet

_WRAP = 2 ** 32
_SEEDS = range(60)


def _usec(pkt: object) -> int:
    return pkt.ts_sec * 1_000_000 + pkt.ts_usec


def _seq_len(pkt: object) -> int:
    return pkt.payload_len + bool(pkt.flags & TCP_SYN) + bool(pkt.flags & TCP_FIN)


def _later(a: int, b: int) -> bool:
    return 0 < (a - b) % _WRAP < _WRAP // 2


def _expected(packets: list, rst: object) -> tuple[int, int]:
    """Return the ``(seq, ack)`` the server's RST should carry.

    The reset happens at the moment the next data segment after the cut is
    sent, which is the last data segment captured before the RST.  If that
    segment is the server's, the server sent it, so it counts.  If it is the
    client's, it is still in flight, so the server has not received it.
    """
    rst_at = _usec(rst)
    reset = max(_usec(p) for p in packets if p.payload_len and _usec(p) <= rst_at)
    # SND.NXT: the end of the furthest server segment sent by the reset.
    snd_nxt = None
    for p in packets:
        if p.direction == "s2c" and p is not rst and _usec(p) <= reset:
            end = (p.seq + _seq_len(p)) % _WRAP
            if snd_nxt is None or _later(end, snd_nxt):
                snd_nxt = end
    # RCV.NXT: the client's bytes the server holds without a gap, from the
    # client's SYN.  A segment past a hole counts once the hole is filled.
    syn = next(p for p in packets if p.direction == "c2s" and p.flags & TCP_SYN)
    edge = (syn.seq + 1) % _WRAP
    pending = [(p.seq, (p.seq + _seq_len(p)) % _WRAP)
               for p in packets
               if p.direction == "c2s" and _seq_len(p) and p is not syn
               and _usec(p) < reset]
    moved = True
    while moved:
        moved = False
        for begin, end in pending:
            if not _later(begin, edge) and _later(end, edge):
                edge, moved = end, True
    return snd_nxt, edge


class _RSTChecks:
    """Shared checks; subclasses say which streams to make."""

    def streams(self) -> list[tuple[str, list]]:
        raise NotImplementedError

    def test_rst_numbers_from_the_servers_state(self) -> None:
        checked = 0
        for name, packets in self.streams():
            rsts = [p for p in packets if p.flags & TCP_RST]
            if not rsts:
                continue
            (rst,) = rsts
            with self.subTest(stream=name):
                self.assertEqual((rst.seq, rst.ack), _expected(packets, rst))
                checked += 1
        self.assertGreater(checked, len(_SEEDS) // 2, "too few streams were reset")

    def test_the_server_sends_nothing_after_its_rst(self) -> None:
        # The ACK of the segment the connection is cut at is found by
        # sequence number.  After a loss a later duplicate ACK names the same
        # byte, and taking it for the real one kept every ACK up to it, the
        # server's included, after the RST.  Jitter is left out: it moves
        # capture times, so a server ACK sent before the RST can be captured
        # after it.
        for name, packets in self.streams():
            if "jitter" in name:
                continue
            for rst in (p for p in packets if p.flags & TCP_RST):
                with self.subTest(stream=name):
                    late = [p.label for p in packets
                            if p.direction == "s2c" and p is not rst
                            and _usec(p) > _usec(rst)]
                    self.assertEqual(late, [])

    def test_the_rst_on_the_wire_says_the_same(self) -> None:
        for name, packets in self.streams():
            for rst in (p for p in packets if p.flags & TCP_RST):
                with self.subTest(stream=name):
                    tcp = parse_packet(rst.raw).transport
                    self.assertEqual((tcp.seq, tcp.ack), (rst.seq, rst.ack))


class TestPlainTCP(_RSTChecks, unittest.TestCase):
    """A plain stream, where only the client sends data."""

    def streams(self) -> list[tuple[str, list]]:
        out = []
        for seed in _SEEDS:
            for label, extra in (
                ("clean", {}),
                ("loss", {"packet_loss_probability": 0.2}),
                ("loss, recovered", {"packet_loss_probability": 0.2, "retransmit_lost": True}),
                ("delay, jitter", {"rst_propagation_delay": 0.003, "gap_jitter": 0.002}),
            ):
                stream = generate_tcp_stream(
                    client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=8,
                    config=TCPStreamConfig(seed=seed, base_time=1e9,
                                           server_rst_probability=1.0, **extra),
                )
                out.append((f"{label}, seed {seed}", stream.packets))
        return out

    def test_a_loss_before_the_cut_no_longer_numbers_from_the_isn(self) -> None:
        # Seed 0 loses DATA[1] and DATA[2], so the server's ACK of DATA[3]
        # is a duplicate, and the old code fell back to the SYN-ACK: its seq
        # (the ISN, one short of the server's next number) and an ack of the
        # client's ISN + 1, as if nothing had arrived.
        stream = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=8,
            config=TCPStreamConfig(seed=0, base_time=1e9, server_rst_probability=1.0,
                                   packet_loss_probability=0.2),
        )
        syn_ack = next(p for p in stream.packets if p.label == "SYN-ACK")
        data0 = next(p for p in stream.packets if p.label == "DATA[0]")
        rst = next(p for p in stream.packets if p.label == "RST")
        self.assertEqual(rst.seq, syn_ack.seq + 1)
        self.assertEqual(rst.ack, data0.seq + data0.payload_len)


class TestHTTP(_RSTChecks, unittest.TestCase):
    """``--payload http``, where the server sends responses."""

    def streams(self) -> list[tuple[str, list]]:
        out = []
        for seed in _SEEDS:
            for label, impairments in (
                ("clean", ImpairmentConfig(server_rst_probability=1.0)),
                ("loss, recovered", ImpairmentConfig(
                    server_rst_probability=1.0, packet_loss_probability=0.2,
                    retransmit_lost=True)),
            ):
                stream = generate_http_stream(
                    client_ip="10.0.0.2", server_ip="10.0.0.1", seed=seed,
                    base_time=1e9, requests=3,
                    config=HTTPRestConfig(impairments=impairments),
                )
                out.append((f"{label}, seed {seed}", stream.packets))
        return out

    def test_the_issues_example(self) -> None:
        # #218: the server had sent a 224-byte response, and the RST numbered
        # from before it.
        stream = generate_http_stream(
            client_ip="10.0.0.2", server_ip="10.0.0.1", seed=0, base_time=1e9,
            requests=3,
            config=HTTPRestConfig(impairments=ImpairmentConfig(server_rst_probability=1.0)),
        )
        response = next(p for p in stream.packets if p.label == "200 OK")
        rst = next(p for p in stream.packets if p.flags & TCP_RST)
        self.assertEqual(response.payload_len, 224)
        self.assertEqual(rst.seq, response.seq + 224)
        self.assertEqual(rst.seq, 3427105026)
        self.assertEqual(rst.ack, 1235478847)


if __name__ == "__main__":
    unittest.main()
