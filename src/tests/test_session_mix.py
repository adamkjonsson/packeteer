"""Unit tests for multi-session stream generation (packeteer.generate.session_mix)."""
from __future__ import annotations

import argparse
import os
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate import (
    CombinedStream,
    SCTPStreamConfig,
    TCPStreamConfig,
    UDPStreamConfig,
    generate_session_mix,
    generate_tcp_stream,
    merge_streams,
)
from packeteer.generate.session_mix import _ip_plus
from packeteer.parse import parse_packet

_BASE_TIME = 1_700_000_000.0


def _ip_pairs(packets: list) -> set[tuple[str, str]]:
    """Return the set of (src, dst) IP pairs across parsed packets."""
    pairs = set()
    for p in packets:
        pkt = parse_packet(p.raw)
        if pkt.ip is not None:
            pairs.add((str(pkt.ip.src), str(pkt.ip.dst)))
    return pairs


# ── Endpoint helpers ──────────────────────────────────────────────────────────

class TestEndpointHelpers(unittest.TestCase):

    def test_ip_plus_ipv4(self) -> None:
        self.assertEqual(str(_ip_plus("10.0.0.1", 5)), "10.0.0.6")

    def test_ip_plus_ipv6(self) -> None:
        self.assertEqual(str(_ip_plus("2001:db8::1", 1)), "2001:db8::2")

    def test_ip_plus_overflow_raises(self) -> None:
        with self.assertRaises(ValueError):
            _ip_plus("255.255.255.255", 1)


# ── generate_session_mix ──────────────────────────────────────────────────────

class TestGenerateSessionMix(unittest.TestCase):

    def _mix(self, **over: object) -> CombinedStream:
        kwargs: dict = {
            "sessions": 3,
            "client_ip": "10.0.0.1",
            "server_ip": "10.1.0.1",
            "num_data_packets": 2,
            "config": TCPStreamConfig(seed=7, base_time=_BASE_TIME),
        }
        kwargs.update(over)
        return generate_session_mix(**kwargs)

    def test_packet_count_scales_with_sessions(self) -> None:
        # one TCP session with 2 data packets = 2*2 + 7 = 11 packets
        single = len(generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", num_data_packets=2,
            config=TCPStreamConfig(seed=7, base_time=_BASE_TIME)).packets)
        mix = self._mix(sessions=3)
        self.assertEqual(len(mix.packets), 3 * single)

    def test_distinct_ip_pairs(self) -> None:
        pairs = _ip_pairs(self._mix(sessions=3).packets)
        # each session contributes c2s and s2c for its own pair
        clients = {a for a, b in pairs} | {b for a, b in pairs}
        self.assertIn("10.0.0.1", clients)
        self.assertIn("10.0.0.3", clients)
        self.assertIn("10.1.0.1", clients)
        self.assertIn("10.1.0.3", clients)

    def test_macs_shared_across_sessions(self) -> None:
        # MACs model a common L2 next-hop, so all sessions share the same pair
        macs = set()
        for p in self._mix(sessions=3).packets:
            pkt = parse_packet(p.raw)
            macs.add(pkt.ethernet.src_mac)
            macs.add(pkt.ethernet.dst_mac)
        self.assertEqual(len(macs), 2)

    def test_overlapping_ranges_raise(self) -> None:
        with self.assertRaises(ValueError):
            generate_session_mix(
                sessions=5, client_ip="10.0.0.1", server_ip="10.0.0.2",
                config=TCPStreamConfig())

    def test_sessions_below_one_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_session_mix(
                sessions=0, client_ip="10.0.0.1", server_ip="10.1.0.1",
                config=TCPStreamConfig())

    def test_mismatched_ip_family_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_session_mix(
                sessions=2, client_ip="10.0.0.1", server_ip="2001:db8::1",
                config=TCPStreamConfig())

    def test_reproducible_with_seed(self) -> None:
        a = self._mix().to_pcap_tuples()
        b = self._mix().to_pcap_tuples()
        self.assertEqual(a, b)

    def test_different_seed_differs(self) -> None:
        a = self._mix(config=TCPStreamConfig(seed=1, base_time=_BASE_TIME))
        b = self._mix(config=TCPStreamConfig(seed=2, base_time=_BASE_TIME))
        self.assertNotEqual(a.to_pcap_tuples(), b.to_pcap_tuples())

    def test_protocol_selected_by_config_udp(self) -> None:
        mix = self._mix(config=UDPStreamConfig(seed=1, base_time=_BASE_TIME))
        from packeteer.generate import UDPHeader
        self.assertTrue(any(
            isinstance(parse_packet(p.raw).transport, UDPHeader) for p in mix.packets))

    def test_protocol_selected_by_config_sctp(self) -> None:
        mix = self._mix(config=SCTPStreamConfig(seed=1, base_time=_BASE_TIME))
        self.assertGreater(len(mix.packets), 0)

    def test_interleaved_not_block_sequential(self) -> None:
        mix = self._mix(sessions=3, session_stagger=0.05)
        seq = []
        for p in mix.packets:
            pkt = parse_packet(p.raw)
            ips = [str(pkt.ip.src), str(pkt.ip.dst)]
            client = next(i for i in ips if i.startswith("10.0.0."))
            seq.append(client)
        transitions = sum(1 for a, b in zip(seq, seq[1:], strict=False) if a != b)
        self.assertGreater(transitions, 0)

    def test_single_session_matches_plain_generator(self) -> None:
        plain = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", num_data_packets=2,
            config=TCPStreamConfig(seed=7, base_time=_BASE_TIME))
        mix = generate_session_mix(
            sessions=1, client_ip="10.0.0.1", server_ip="10.1.0.1",
            num_data_packets=2,
            config=TCPStreamConfig(seed=7, base_time=_BASE_TIME))
        self.assertEqual(mix.to_pcap_tuples(), plain.to_pcap_tuples())

    def test_unsupported_config_type_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_session_mix(
                sessions=1, client_ip="10.0.0.1", server_ip="10.1.0.1",
                config="not a config")  # type: ignore[arg-type]


# ── merge_streams ─────────────────────────────────────────────────────────────

class TestMergeStreams(unittest.TestCase):

    def test_merge_sorts_by_timestamp(self) -> None:
        s1 = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", num_data_packets=1,
            config=TCPStreamConfig(seed=1, base_time=_BASE_TIME + 10))
        s2 = generate_tcp_stream(
            client_ip="10.0.0.2", server_ip="10.1.0.2", num_data_packets=1,
            config=TCPStreamConfig(seed=2, base_time=_BASE_TIME))
        merged = merge_streams([s1, s2])
        times = [(p.ts_sec, p.ts_usec) for p in merged.packets]
        self.assertEqual(times, sorted(times))
        self.assertEqual(len(merged.packets), len(s1.packets) + len(s2.packets))


# ── CLI ───────────────────────────────────────────────────────────────────────

class TestCmdStreamSessions(unittest.TestCase):

    def _args(self, **over: object) -> argparse.Namespace:
        ns = argparse.Namespace(
            config=None, client_ip="10.0.0.1", server_ip="10.1.0.1",
            pcap=None, pcapng=None, seed=7,
        )
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _tmp(self, suffix: str = ".pcap") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path

    def test_cli_multi_session_writes_distinct_pairs(self) -> None:
        out = self._tmp()
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(pcap=out, sessions=3, packets=2))
        from packeteer.parse import pcap_info
        info = pcap_info(path=out)
        self.assertEqual(info.session_count, 6)  # 3 sessions x 2 directions
        os.remove(out)

    def test_cli_session_count_in_message(self) -> None:
        out = self._tmp()
        with patch("sys.stdout", new=StringIO()) as stdout:
            cli._cmd_stream(self._args(pcap=out, sessions=2, packets=1))
        self.assertIn("2 sessions", stdout.getvalue())
        os.remove(out)

    def test_cli_overlap_exits(self) -> None:
        with patch("sys.stderr", new=StringIO()), self.assertRaises(SystemExit):
            cli._cmd_stream(self._args(
                pcap=self._tmp(), server_ip="10.0.0.2", sessions=5))

    def test_cli_sessions_zero_exits(self) -> None:
        with patch("sys.stderr", new=StringIO()), self.assertRaises(SystemExit):
            cli._cmd_stream(self._args(pcap=self._tmp(), sessions=0))


if __name__ == "__main__":
    unittest.main()
