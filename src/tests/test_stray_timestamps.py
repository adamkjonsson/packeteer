"""A stray can carry a Timestamps option (#228).

A stray used to be forged with no TCP options at all, even on a connection
that negotiated timestamps.  RFC 7323 §3.2 lets a receiver drop exactly that
segment, so a consumer applying the rule made every stray harmless and was
never tested by one.  With ``stray_timestamps`` the stray is stamped as its
impersonated side would have stamped a segment at that moment, which passes
§3.2 and PAWS alike and leaves only content-based defences.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.base import AppMessage
from packeteer.generate.payloads.http import HTTPRestConfig, generate_http_stream
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.parse import parse_packet

_BASE = 1_700_000_000.0

#: SHA-256 of a seeded HTTP stream with three strays, computed on 5d0f46b,
#: before #228.  Plain TCP is pinned by ``test_stray_direction``.
_HTTP_SEED_5 = "afa3617cd47305e71fdc3d5345144b3bb33ae35c868a5d6841816aaec18ac051"

_TWO_WAY = [
    AppMessage("c2s", b"q" * 300, "req0"),
    AppMessage("s2c", b"r" * 3000, "resp0"),
    AppMessage("c2s", b"q" * 120, "req1"),
    AppMessage("s2c", b"r" * 900, "resp1"),
]


def _sorted(packets: list) -> list:
    return sorted(packets, key=lambda p: (p.ts_sec, p.ts_usec))


def _plain(seed: int, **config: object) -> list:
    config.setdefault("stray_packet_count", 3)
    return _sorted(generate_tcp_stream(
        client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=20,
        config=TCPStreamConfig(seed=seed, base_time=_BASE, **config),
    ).packets)


def _two_way(seed: int, **config: object) -> list:
    return _plain(seed, messages=_TWO_WAY, **config)


def _http(seed: int, **impairments: object) -> list:
    impairments.setdefault("stray_packet_count", 3)
    return _sorted(generate_http_stream(
        client_ip="10.0.0.1", server_ip="10.1.0.1", requests=4, seed=seed,
        base_time=_BASE,
        config=HTTPRestConfig(impairments=ImpairmentConfig(**impairments)),
    ).packets)


_GENERATORS = (("plain", _plain), ("two-way", _two_way), ("http", _http))


def _is_stray(pkt: object) -> bool:
    return pkt.label.startswith("STRAY[")


class TestAStrayCarriesTimestamps(unittest.TestCase):

    def test_stamped_as_its_side_would_stamp_it(self) -> None:
        """Its TSval sits in its side's clock; its TSecr is one the peer sent."""
        for name, generate in _GENERATORS:
            for seed in range(60):
                packets = generate(seed, stray_timestamps=True)
                for k, stray in enumerate(packets):
                    if not _is_stray(stray):
                        continue
                    with self.subTest(stream=name, seed=seed, stray=stray.label):
                        options = parse_packet(stray.raw).transport.options
                        self.assertIsNotNone(options)
                        self.assertIsNotNone(options.timestamps, "no Timestamps option")
                        self.assertEqual(options.timestamps, stray.timestamps)
                        tsval, tsecr = stray.timestamps
                        same = [p for p in packets if p.direction == stray.direction
                                and p.timestamps and not _is_stray(p)]
                        before = [p.timestamps[0] for p in same if packets.index(p) < k]
                        after = [p.timestamps[0] for p in same if packets.index(p) > k]
                        self.assertTrue(all(t <= tsval for t in before), "older than its side")
                        self.assertTrue(all(t >= tsval for t in after), "newer than its side")
                        peer = {p.timestamps[0] for p in packets[:k]
                                if p.direction != stray.direction and p.timestamps
                                and not _is_stray(p)}
                        self.assertIn(tsecr, peer, "echoes a TSval the peer never sent")

    def test_the_option_comes_off_the_payload(self) -> None:
        """Each frame is as large as it would be without the option."""
        for name, generate in _GENERATORS:
            for seed in range(20):
                plain = [p for p in generate(seed) if _is_stray(p)]
                stamped = [p for p in generate(seed, stray_timestamps=True) if _is_stray(p)]
                for a, b in zip(plain, stamped, strict=True):
                    with self.subTest(stream=name, seed=seed, stray=a.label):
                        self.assertEqual(len(b.raw), len(a.raw))
                        self.assertEqual(b.payload_len, a.payload_len - 12)

    def test_a_full_size_stray_stays_inside_the_mtu(self) -> None:
        """The case the rule is for: a 1460-byte stray on a timestamped connection.

        The HTTP path takes the range as given, so without the option's bytes
        coming off, the frame would carry 1472 bytes of TCP payload and
        options — past a 1500-byte MTU.  (The plain path already caps its range
        at MSS - 12 when timestamps are negotiated; there the stray is 12
        bytes shorter still, which is what keeping every frame's size buys.)
        """
        for stamped in (False, True):
            packets = _http(1, stray_payload_range=(1460, 1460), stray_timestamps=stamped)
            strays = [p for p in packets if _is_stray(p)]
            with self.subTest(stray_timestamps=stamped):
                self.assertTrue(strays)
                self.assertEqual({p.payload_len for p in strays}, {1448 if stamped else 1460})
                for stray in strays:
                    self.assertLessEqual(parse_packet(stray.raw).ip.total_length, 1500)

    def test_the_strays_are_where_they_were(self) -> None:
        """No new randomness: same strays, same times, and nothing else changes."""
        for name, generate in _GENERATORS:
            for seed in range(20):
                plain = generate(seed)
                stamped = generate(seed, stray_timestamps=True)
                with self.subTest(stream=name, seed=seed):
                    self.assertEqual(
                        [(p.label, p.ts_sec, p.ts_usec, p.direction, p.seq, p.ack)
                         for p in plain],
                        [(p.label, p.ts_sec, p.ts_usec, p.direction, p.seq, p.ack)
                         for p in stamped],
                    )
                    self.assertEqual([p.raw for p in plain if not _is_stray(p)],
                                     [p.raw for p in stamped if not _is_stray(p)])

    def test_no_option_where_none_was_negotiated(self) -> None:
        """A bare handshake gets bare strays: the flag changes nothing."""
        bare = {"client_options": None, "server_options": None}
        for seed in range(10):
            plain = _plain(seed, **bare)
            stamped = _plain(seed, stray_timestamps=True, **bare)
            with self.subTest(seed=seed):
                self.assertEqual([p.raw for p in plain], [p.raw for p in stamped])
                for stray in (p for p in stamped if _is_stray(p)):
                    self.assertIsNone(stray.timestamps)

    def test_off_by_default_and_unchanged(self) -> None:
        packets = _http(5)
        digest = hashlib.sha256(b"".join(p.raw for p in packets)).hexdigest()
        self.assertEqual(digest, _HTTP_SEED_5)
        self.assertTrue(all(p.timestamps is None for p in packets if _is_stray(p)))


class TestTheCommandLine(unittest.TestCase):

    def _strays(self, **over: object) -> list[dict]:
        fd, out = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.remove, out)
        args = argparse.Namespace(
            config=None, client_ip="10.0.0.1", server_ip="10.1.0.1",
            pcap=None, pcapng=None, json=out, seed=7, packets=8,
            stray_packet_count=2,
        )
        for k, v in over.items():
            setattr(args, k, v)
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(args)
        return [p for p in json.loads(Path(out).read_text())["packets"]
                if p["packet_metadata"]["label"].startswith("STRAY[")]

    def test_the_flag_reaches_the_stream(self) -> None:
        for over in ({}, {"payload": "http", "requests": 2}):
            with self.subTest(**over):
                strays = self._strays(stray_timestamps=True, **over)
                self.assertTrue(strays)
                for stray in strays:
                    self.assertIn("timestamps", stray["transport"].get("options") or {})
                for stray in self._strays(**over):
                    self.assertNotIn("timestamps", stray["transport"].get("options") or {})

    def test_the_config_key(self) -> None:
        fd, ini = tempfile.mkstemp(suffix=".ini")
        os.close(fd)
        self.addCleanup(os.remove, ini)
        Path(ini).write_text("[stream]\nstray_timestamps = true\n")
        args = argparse.Namespace(config=ini, client_ip="10.0.0.1", server_ip="10.1.0.1")
        cli._apply_stream_defaults(args)
        self.assertIs(args.stray_timestamps, True)


if __name__ == "__main__":
    unittest.main()
