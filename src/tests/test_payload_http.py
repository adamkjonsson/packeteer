"""Unit tests for HTTP REST payload generation (packeteer.generate.payloads.http)."""
from __future__ import annotations

import argparse
import json
import os
import random
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate import (
    HTTPRestConfig,
    generate_http_conversation,
    generate_http_stream,
)
from packeteer.generate.http import HTTPRequest, HTTPResponse
from packeteer.parse import parse_packet

_BASE_TIME = 1_700_000_000.0


def _http_messages(packets: list) -> list:
    """Return the parsed HTTP messages (requests + responses) in a stream."""
    msgs = []
    for p in packets:
        pkt = parse_packet(p.raw)
        if pkt.http is not None:
            msgs.append(pkt.http)
    return msgs


def _syn_count(packets: list) -> int:
    """Count bare SYN packets — one per TCP connection."""
    return sum(1 for p in packets if p.label == "SYN")


# ── Conversation generator ────────────────────────────────────────────────────

class TestConversation(unittest.TestCase):

    def test_two_messages_per_transaction(self) -> None:
        conv = generate_http_conversation(
            random.Random(1), transactions=3, keepalive=True, config=HTTPRestConfig())
        self.assertEqual(len(conv), 6)

    def test_alternates_request_response(self) -> None:
        conv = generate_http_conversation(
            random.Random(1), transactions=3, keepalive=True, config=HTTPRestConfig())
        self.assertEqual([m.direction for m in conv],
                         ["c2s", "s2c", "c2s", "s2c", "c2s", "s2c"])

    def test_status_correlates_with_method_no_errors(self) -> None:
        cfg = HTTPRestConfig(error_rate=0.0)
        rng = random.Random(0)
        for _ in range(50):
            conv = generate_http_conversation(rng, transactions=1, keepalive=False, config=cfg)
            req_label, resp_label = conv[0].label, conv[1].label
            method = req_label.split()[0]
            status = int(resp_label.split()[0])
            if method == "POST":
                self.assertEqual(status, 201)
            elif method == "DELETE":
                self.assertEqual(status, 204)
            else:
                self.assertIn(status, (200, 204))

    def test_keepalive_header(self) -> None:
        conv = generate_http_conversation(
            random.Random(2), transactions=2, keepalive=True, config=HTTPRestConfig())
        # first request keep-alive, last request close
        self.assertIn(b"Connection: keep-alive", conv[0].data)
        self.assertIn(b"Connection: close", conv[2].data)


# ── generate_http_stream ──────────────────────────────────────────────────────

class TestHTTPStream(unittest.TestCase):

    def test_keepalive_single_connection(self) -> None:
        mix = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=5,
            seed=1, base_time=_BASE_TIME)
        self.assertEqual(_syn_count(mix.packets), 1)

    def test_connection_per_request(self) -> None:
        mix = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=4,
            requests_per_connection=1, seed=1, base_time=_BASE_TIME)
        self.assertEqual(_syn_count(mix.packets), 4)

    def test_requests_per_connection_grouping(self) -> None:
        mix = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=5,
            requests_per_connection=2, seed=1, base_time=_BASE_TIME)
        self.assertEqual(_syn_count(mix.packets), 3)  # ceil(5/2)

    def test_roundtrips_through_parser(self) -> None:
        mix = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=4,
            seed=3, base_time=_BASE_TIME)
        msgs = _http_messages(mix.packets)
        requests = [m for m in msgs if isinstance(m, HTTPRequest)]
        responses = [m for m in msgs if isinstance(m, HTTPResponse)]
        self.assertEqual(len(requests), 4)
        self.assertEqual(len(responses), 4)
        self.assertTrue(all(r.method in
                            ("GET", "POST", "PUT", "PATCH", "DELETE") for r in requests))

    def test_reproducible_with_seed(self) -> None:
        a = generate_http_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                 requests=5, seed=9, base_time=_BASE_TIME)
        b = generate_http_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                 requests=5, seed=9, base_time=_BASE_TIME)
        self.assertEqual(a.to_pcap_tuples(), b.to_pcap_tuples())

    def test_different_seed_differs(self) -> None:
        a = generate_http_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                 requests=5, seed=1, base_time=_BASE_TIME)
        b = generate_http_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                 requests=5, seed=2, base_time=_BASE_TIME)
        self.assertNotEqual(a.to_pcap_tuples(), b.to_pcap_tuples())

    def test_distinct_client_ports_per_connection(self) -> None:
        mix = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=3,
            requests_per_connection=1, client_port=40000, seed=1, base_time=_BASE_TIME)
        client_ports = set()
        for p in mix.packets:
            pkt = parse_packet(p.raw)
            if p.label == "SYN":
                client_ports.add(pkt.transport.src_port)
        self.assertEqual(client_ports, {40000, 40001, 40002})

    def test_sessions_distinct_ip_pairs(self) -> None:
        mix = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=2,
            sessions=3, seed=1, base_time=_BASE_TIME)
        client_ips = set()
        for p in mix.packets:
            pkt = parse_packet(p.raw)
            if p.label == "SYN":
                client_ips.add(str(pkt.ip.src))
        self.assertEqual(client_ips, {"10.0.0.1", "10.0.0.2", "10.0.0.3"})

    def test_requests_below_one_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_http_stream(client_ip="10.0.0.1", server_ip="10.1.0.1", requests=0)

    def test_requests_per_connection_below_one_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_http_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                 requests=3, requests_per_connection=0)

    def test_overlapping_ip_ranges_raise(self) -> None:
        with self.assertRaises(ValueError):
            generate_http_stream(client_ip="10.0.0.1", server_ip="10.0.0.2",
                                 requests=2, sessions=5)

    def test_client_port_overflow_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_http_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                 requests=10, requests_per_connection=1, client_port=65530)

    def test_semantic_labels_present(self) -> None:
        mix = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=3,
            seed=5, base_time=_BASE_TIME)
        labels = [p.label for p in mix.packets]
        self.assertTrue(any(lbl.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE "))
                            for lbl in labels))
        self.assertTrue(any(lbl[:1].isdigit() for lbl in labels))  # e.g. "200 OK"


# ── CLI ───────────────────────────────────────────────────────────────────────

class TestCmdStreamHTTP(unittest.TestCase):

    def _args(self, **over: object) -> argparse.Namespace:
        ns = argparse.Namespace(
            config=None, client_ip="10.0.0.1", server_ip="10.1.0.1",
            pcap=None, pcapng=None, json=None, payload="http", seed=7,
        )
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _tmp(self, suffix: str = ".pcap") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path

    def test_cli_http_writes_pcap(self) -> None:
        out = self._tmp()
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(pcap=out, requests=3))
        self.assertGreater(os.path.getsize(out), 0)
        os.remove(out)

    def test_cli_http_json_has_semantic_labels(self) -> None:
        out = self._tmp(".json")
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(json=out, requests=2))
        data = json.loads(Path(out).read_text())
        labels = [p.get("packet_metadata", {}).get("label", "") for p in data["packets"]]
        self.assertTrue(any(lbl.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE "))
                            for lbl in labels))
        os.remove(out)

    def test_cli_http_requires_tcp(self) -> None:
        with patch("sys.stderr", new=StringIO()), self.assertRaises(SystemExit):
            cli._cmd_stream(self._args(pcap=self._tmp(), protocol="udp"))


if __name__ == "__main__":
    unittest.main()
