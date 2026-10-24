"""A stray is forged from the side whose segment it copies (#219).

``--stray-packets`` injects a forged segment that collides with a real one,
by copying its sequence and acknowledgement numbers.  Before #219 every
stray was built client → server, so one copying server data carried the
server's sequence numbers from the client's address: not an injection that
could happen.  A plain stream never showed it, since only its client sends
data; ``--payload http`` did.
"""
from __future__ import annotations

import hashlib
import unittest

from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.http import HTTPRestConfig, generate_http_stream
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.parse import parse_packet

_CLIENT = ("10.0.0.2", 54321, "00:00:00:00:00:01")
_SERVER = ("10.0.0.1", 80, "00:00:00:00:00:02")

#: SHA-256 of a seeded plain stream with three strays, from before #219.
_PLAIN_SEED_7 = "9ff7a5fe4e459966367dffac83ffde4c4001dbce6e39996c26b75445dd335c3b"


def _ends(pkt: object) -> tuple[tuple[str, int, str], tuple[str, int, str]]:
    """Return a parsed packet's (source, destination) address, port and MAC."""
    return (
        (pkt.ip.src, pkt.transport.src_port, pkt.ethernet.src_mac),
        (pkt.ip.dst, pkt.transport.dst_port, pkt.ethernet.dst_mac),
    )


def _http(seed: int) -> list:
    return generate_http_stream(
        client_ip=_CLIENT[0], server_ip=_SERVER[0], seed=seed, base_time=1e9,
        requests=3,
        config=HTTPRestConfig(impairments=ImpairmentConfig(stray_packet_count=3)),
    ).packets


class TestStrayDirection(unittest.TestCase):

    def test_a_stray_comes_from_the_side_it_copies(self) -> None:
        directions = set()
        for seed in range(60):
            packets = _http(seed)
            real = [p for p in packets if p.payload_len and not p.label.startswith("STRAY[")]
            for stray in (p for p in packets if p.label.startswith("STRAY[")):
                with self.subTest(seed=seed, stray=stray.label):
                    ends = (_CLIENT, _SERVER) if stray.direction == "c2s" else (_SERVER, _CLIENT)
                    pkt = parse_packet(stray.raw)
                    self.assertEqual(_ends(pkt), ends)
                    # It copies a real segment going the same way, so its
                    # numbers are in that side's sequence space.
                    copied = [p for p in real if (p.seq, p.ack) == (stray.seq, stray.ack)]
                    self.assertTrue(copied, "no real segment has the stray's numbers")
                    self.assertEqual({p.direction for p in copied}, {stray.direction})
                    self.assertEqual((pkt.transport.seq, pkt.transport.ack), (stray.seq, stray.ack))
                    directions.add(stray.direction)
        # Both sides send data on HTTP, so both kinds of stray are made.
        self.assertEqual(directions, {"c2s", "s2c"})

    def test_a_plain_stream_is_unchanged(self) -> None:
        # Every data segment of a plain stream is the client's, so its strays
        # were already right.  The hash was computed on 99fd75f, before #219,
        # where 300 seeds, with and without a timing window and loss, were
        # checked identical before and after.
        stream = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=8,
            config=TCPStreamConfig(seed=7, base_time=1e9, stray_packet_count=3),
        )
        digest = hashlib.sha256(b"".join(p.raw for p in stream.packets)).hexdigest()
        self.assertEqual(digest, _PLAIN_SEED_7)


if __name__ == "__main__":
    unittest.main()
