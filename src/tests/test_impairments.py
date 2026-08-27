"""Tests for wire impairments and their application to the payload paths (#83)."""
from __future__ import annotations

import argparse
import os
import random
import re
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate.impairments import (
    ImpairmentConfig,
    _ack_positions,
    _derive_label,
    apply_packet_loss,
    drop_packet,
)
from packeteer.generate.payloads.http import HTTPRestConfig, generate_http_stream
from packeteer.generate.payloads.vpn import VPNConfig, generate_vpn_stream
from packeteer.generate.session_mix import CombinedStream
from packeteer.generate.tcp import TCP_ACK, TCP_PSH
from packeteer.generate.tcp_stream import TCPStreamPacket

_BASE_TIME = 1_700_000_000.0


def _http(seed: int = 1, requests: int = 8, **over: object) -> CombinedStream:
    """Generate an HTTP stream, with impairment keywords passed through."""
    impairments = ImpairmentConfig(**over) if over else None
    return generate_http_stream(
        client_ip="10.0.0.1", server_ip="10.1.0.1", requests=requests,
        seed=seed, base_time=_BASE_TIME,
        mss=int(over.pop("_mss", 0)) or 1460,
        config=HTTPRestConfig(error_rate=0.0, impairments=impairments),
    )


def _labels(stream: CombinedStream) -> list[str]:
    return [p.label for p in stream.packets]


def _raws(stream: CombinedStream) -> list[bytes]:
    return [p.raw for p in stream.packets]


class TestImpairmentConfig(unittest.TestCase):

    def test_default_config_does_nothing(self) -> None:
        self.assertFalse(ImpairmentConfig().any_post_pass)

    def test_any_post_pass_detects_each_pass(self) -> None:
        for field, value in (
            ("retransmission_probability", 0.5),
            ("payload_corruption_probability", 0.5),
            ("server_rst_probability", 0.5),
            ("stray_packet_count", 1),
        ):
            self.assertTrue(ImpairmentConfig(**{field: value}).any_post_pass, field)

    def test_loss_alone_is_not_a_post_pass(self) -> None:
        """Loss is applied as packets are emitted, not by apply_impairments."""
        self.assertFalse(
            ImpairmentConfig(packet_loss_probability=1.0).any_post_pass
        )

    def test_zero_probability_draws_no_randomness(self) -> None:
        """The guard is what keeps pre-impairment seeds reproducible."""
        rng = random.Random(0)
        for _ in range(20):
            self.assertFalse(drop_packet(rng, 0.0))
        self.assertEqual(rng.random(), random.Random(0).random())

    def test_loss_probability_one_drops_everything(self) -> None:
        packets = [object()] * 10
        self.assertEqual(
            apply_packet_loss(packets, rng=random.Random(0), probability=1.0), []
        )


class TestDerivedLabels(unittest.TestCase):

    def test_low_level_label_keeps_its_index(self) -> None:
        self.assertEqual(_derive_label("RETRANS", "DATA[3]"), "RETRANS[3]")

    def test_application_label_is_carried_whole(self) -> None:
        self.assertEqual(
            _derive_label("CORRUPT", "GET /api/v1/orders [2/5]"),
            "CORRUPT[GET /api/v1/orders [2/5]]",
        )


class TestAckPairing(unittest.TestCase):
    """ACKs pair with segments by sequence number, not by adjacency."""

    @staticmethod
    def _pkt(direction: str, seq: int, ack: int, payload_len: int) -> TCPStreamPacket:
        return TCPStreamPacket(
            raw=b"", ts_sec=0, ts_usec=0, direction=direction,
            flags=TCP_ACK | (TCP_PSH if payload_len else 0),
            seq=seq, ack=ack, payload_len=payload_len, label="",
        )

    def test_adjacent_pairing(self) -> None:
        packets = [
            self._pkt("c2s", 100, 0, 10),
            self._pkt("s2c", 500, 110, 0),
        ]
        self.assertEqual(_ack_positions(packets), {0: 1})

    def test_unrelated_neighbour_is_not_mistaken_for_the_ack(self) -> None:
        """The case packet loss creates: a segment left beside a stranger.

        DATA(seq=100) lost its own ACK, and the next packet is the ACK for a
        different segment.  Adjacency would pair them; sequence numbers do not.
        """
        packets = [
            self._pkt("c2s", 100, 0, 10),
            self._pkt("s2c", 500, 999, 0),
        ]
        self.assertEqual(_ack_positions(packets), {})

    def test_ack_further_down_the_list_still_pairs(self) -> None:
        packets = [
            self._pkt("c2s", 100, 0, 10),
            self._pkt("c2s", 110, 0, 10),
            self._pkt("s2c", 500, 110, 0),
        ]
        self.assertEqual(_ack_positions(packets), {0: 2})


class TestHTTPImpairments(unittest.TestCase):

    def test_clean_stream_unchanged_without_impairments(self) -> None:
        """The promise that pre-existing seeds still reproduce."""
        self.assertEqual(_raws(_http()), _raws(_http(packet_loss_probability=0.0)))

    def test_loss_removes_packets(self) -> None:
        self.assertLess(
            len(_http(packet_loss_probability=0.3).packets), len(_http().packets)
        )

    def test_retransmission_duplicates_segments(self) -> None:
        stream = _http(retransmission_probability=1.0)
        retrans = [p for p in stream.packets if p.label.startswith("RETRANS[")]
        self.assertTrue(retrans)
        originals = {(p.seq, p.payload_len) for p in stream.packets
                     if p.payload_len and not p.label.startswith("RETRANS[")}
        for pkt in retrans:
            self.assertIn((pkt.seq, pkt.payload_len), originals)

    def test_corruption_alters_a_payload_and_retransmits_it_clean(self) -> None:
        stream = _http(payload_corruption_probability=1.0)
        corrupt = [p for p in stream.packets if p.label.startswith("CORRUPT[")]
        self.assertTrue(corrupt)
        clean = {p.raw for p in stream.packets if p.label.startswith("RETRANS[")}
        for pkt in corrupt:
            self.assertNotIn(pkt.raw, clean)

    def test_server_rst_ends_the_connection(self) -> None:
        stream = _http(server_rst_probability=1.0)
        self.assertIn("RST", _labels(stream))
        self.assertNotIn("FIN-ACK", _labels(stream))

    def test_stray_packets_injected(self) -> None:
        stream = _http(stray_packet_count=3)
        self.assertEqual(
            sum(1 for lbl in _labels(stream) if lbl.startswith("STRAY[")), 3
        )

    def test_impairments_apply_per_connection(self) -> None:
        """A RST must cut one connection, not reach across the capture."""
        stream = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=6,
            requests_per_connection=2, sessions=2, seed=5, base_time=_BASE_TIME,
            config=HTTPRestConfig(
                error_rate=0.0,
                impairments=ImpairmentConfig(server_rst_probability=1.0),
            ),
        )
        syns = sum(1 for lbl in _labels(stream) if lbl == "SYN")
        rsts = sum(1 for lbl in _labels(stream) if lbl == "RST")
        self.assertEqual(syns, 6)        # 3 connections x 2 sessions
        self.assertEqual(rsts, syns)     # every connection got its own

    def test_small_mss_and_loss_leave_a_message_part_delivered(self) -> None:
        """The case the issue was filed for.

        At the default MSS a whole message fits in one segment, so losing a
        segment loses the message.  Split across segments, loss punches a gap
        into the middle of a message a decoder is already part-way through.
        """
        segment = re.compile(r"^(?P<msg>.*) \[(?P<n>\d+)/(?P<total>\d+)\]$")
        for seed in range(12):
            stream = generate_http_stream(
                client_ip="10.0.0.1", server_ip="10.1.0.1", requests=6, mss=64,
                seed=seed, base_time=_BASE_TIME,
                config=HTTPRestConfig(
                    error_rate=0.0,
                    impairments=ImpairmentConfig(packet_loss_probability=0.25),
                ),
            )
            seen: dict[str, set[int]] = {}
            for label in _labels(stream):
                match = segment.match(label)
                if match:
                    seen.setdefault(
                        f"{match['msg']}/{match['total']}", set()
                    ).add(int(match["n"]))
            for key, arrived in seen.items():
                total = int(key.rsplit("/", 1)[1])
                if 0 < len(arrived) < total:
                    return      # a message arrived in pieces, with a hole
        self.fail("no partially delivered message across 12 seeds")


class TestVPNImpairments(unittest.TestCase):

    def _vpn(self, **over: object) -> CombinedStream:
        impairments = ImpairmentConfig(**over) if over else None
        return generate_vpn_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", epochs=2,
            packets_per_epoch=8, seed=3, base_time=_BASE_TIME,
            config=VPNConfig(impairments=impairments),
        )

    def test_clean_stream_unchanged_without_impairments(self) -> None:
        self.assertEqual(_raws(self._vpn()), _raws(self._vpn(
            packet_loss_probability=0.0,
        )))

    def test_loss_applies(self) -> None:
        self.assertLess(
            len(self._vpn(packet_loss_probability=0.4).packets),
            len(self._vpn().packets),
        )

    def test_corruption_applies(self) -> None:
        stream = self._vpn(payload_corruption_probability=1.0)
        self.assertTrue(any(lbl.startswith("CORRUPT[") for lbl in _labels(stream)))

    def test_tcp_only_impairments_are_ignored(self) -> None:
        """Retransmission, RST and hijacking have no meaning on a datagram."""
        stream = self._vpn(
            retransmission_probability=1.0,
            server_rst_probability=1.0,
            stray_packet_count=5,
        )
        self.assertEqual(_raws(stream), _raws(self._vpn()))


class TestCmdStreamImpairments(unittest.TestCase):

    def _args(self, **over: object) -> argparse.Namespace:
        ns = argparse.Namespace(
            config=None, client_ip="10.0.0.1", server_ip="10.1.0.1",
            pcap=None, pcapng=None, json=None, seed=7,
        )
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _tmp(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        return path

    def _run(self, **over: object) -> str:
        out = self._tmp()
        err = StringIO()
        with patch("sys.stdout", new=StringIO()), patch("sys.stderr", new=err):
            cli._cmd_stream(self._args(pcap=out, **over))
        os.remove(out)
        return err.getvalue()

    def test_http_no_longer_warns_about_anomaly_options(self) -> None:
        stderr = self._run(payload="http", requests=4, packet_loss_probability=0.5)
        self.assertEqual(stderr, "")

    def test_vpn_warns_only_about_tcp_only_options(self) -> None:
        stderr = self._run(
            payload="vpn", server_rst_probability=0.5, packet_loss_probability=0.2,
        )
        self.assertIn("--server-rst", stderr)
        self.assertNotIn("--packet-loss,", stderr)

    def test_vpn_silent_when_only_applicable_options_given(self) -> None:
        stderr = self._run(
            payload="vpn", packet_loss_probability=0.2,
            payload_corruption_probability=0.2,
        )
        self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
