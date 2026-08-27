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


def _dechunk(body: bytes) -> tuple[bytes, list[int], dict[str, str]]:
    """Decode a chunked body the way a decoder under test would.

    Returns:
        A tuple of ``(payload, chunk_sizes, trailers)``.  Sizes are decoded
        from the hex size lines, so a body written with decimal sizes would
        come back wrong here rather than silently passing.

    """
    payload = bytearray()
    sizes: list[int] = []
    pos = 0
    while True:
        eol = body.index(b"\r\n", pos)
        size = int(body[pos:eol], 16)
        pos = eol + 2
        if size == 0:
            break
        sizes.append(size)
        payload += body[pos:pos + size]
        pos += size + 2
    trailers: dict[str, str] = {}
    for line in body[pos:].split(b"\r\n"):
        if b":" in line:
            name, _, value = line.decode("latin-1").partition(":")
            trailers[name.strip()] = value.strip()
    return (bytes(payload), sizes, trailers)


def _bodied_responses(conv: list) -> list:
    """Return the server messages in *conv* that carry a body."""
    return [m for m in conv if m.direction == "s2c" and m.data.split(b"\r\n\r\n", 1)[1]]


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


class TestChunkedFraming(unittest.TestCase):
    """Transfer-Encoding: chunked responses (#82)."""

    #: A config that chunks every bodied response, with errors switched off so
    #: every transaction produces one.
    _ALL = HTTPRestConfig(chunked_rate=1.0, error_rate=0.0, methods=("GET",))

    def _conv(self, config: HTTPRestConfig, seed: int = 3, transactions: int = 6) -> list:
        return generate_http_conversation(
            random.Random(seed), transactions=transactions,
            keepalive=True, config=config,
        )

    def test_no_chunking_by_default(self) -> None:
        for msg in self._conv(HTTPRestConfig()):
            self.assertNotIn(b"Transfer-Encoding", msg.data)

    def test_every_bodied_response_chunked_at_rate_one(self) -> None:
        bodied = _bodied_responses(self._conv(self._ALL))
        self.assertTrue(bodied)
        for msg in bodied:
            self.assertIn(b"Transfer-Encoding: chunked\r\n", msg.data)

    def test_chunked_response_has_no_content_length(self) -> None:
        """The two together are the smuggling construction #81 removed."""
        for msg in _bodied_responses(self._conv(self._ALL)):
            self.assertNotIn(b"Content-Length", msg.data)

    def test_requests_are_never_chunked(self) -> None:
        """The knob frames responses; request bodies stay counted."""
        cfg = HTTPRestConfig(chunked_rate=1.0, error_rate=0.0, methods=("POST",))
        for msg in self._conv(cfg):
            if msg.direction == "c2s" and msg.data.split(b"\r\n\r\n", 1)[1]:
                self.assertIn(b"Content-Length", msg.data)
                self.assertNotIn(b"Transfer-Encoding", msg.data)

    def test_body_splits_into_several_chunks(self) -> None:
        """A single-chunk body would not exercise walking the size lines."""
        for msg in _bodied_responses(self._conv(self._ALL)):
            _, sizes, _ = _dechunk(msg.data.split(b"\r\n\r\n", 1)[1])
            self.assertGreater(len(sizes), 1)

    def test_chunk_sizes_within_configured_range(self) -> None:
        cfg = HTTPRestConfig(chunked_rate=1.0, error_rate=0.0,
                             methods=("GET",), chunk_size=(4, 9))
        for msg in _bodied_responses(self._conv(cfg)):
            _, sizes, _ = _dechunk(msg.data.split(b"\r\n\r\n", 1)[1])
            for size in sizes[:-1]:      # the last chunk is whatever remains
                self.assertGreaterEqual(size, 4)
                self.assertLessEqual(size, 9)

    def test_body_is_terminated(self) -> None:
        for msg in _bodied_responses(self._conv(self._ALL)):
            self.assertTrue(msg.data.endswith(b"0\r\n\r\n"))

    def test_dechunks_back_to_the_json_body(self) -> None:
        """Sizes are hex per RFC 7230 4.1, and the payload survives framing."""
        for msg in _bodied_responses(self._conv(self._ALL)):
            payload, _, _ = _dechunk(msg.data.split(b"\r\n\r\n", 1)[1])
            self.assertIn("id", json.loads(payload))

    def test_no_trailers_by_default(self) -> None:
        for msg in _bodied_responses(self._conv(self._ALL)):
            self.assertNotIn(b"Trailer:", msg.data)

    def test_trailers_announced_and_emitted(self) -> None:
        cfg = HTTPRestConfig(chunked_rate=1.0, trailer_rate=1.0,
                             error_rate=0.0, methods=("GET",))
        bodied = _bodied_responses(self._conv(cfg))
        self.assertTrue(bodied)
        for msg in bodied:
            head, body = msg.data.split(b"\r\n\r\n", 1)
            announced = [
                n.strip() for n in
                head.decode("latin-1").split("Trailer:", 1)[1].split("\r\n", 1)[0].split(",")
            ]
            _, _, trailers = _dechunk(body)
            self.assertEqual(sorted(announced), sorted(trailers))

    def test_trailer_rate_without_chunking_does_nothing(self) -> None:
        cfg = HTTPRestConfig(chunked_rate=0.0, trailer_rate=1.0)
        for msg in self._conv(cfg):
            self.assertNotIn(b"Trailer", msg.data)

    def test_zero_rates_draw_no_randomness(self) -> None:
        """Output for a seed is unchanged by knobs that are switched off.

        The framing draws are guarded, so a capture generated before these
        knobs existed still reproduces from its seed.
        """
        plain = self._conv(HTTPRestConfig())
        for config in (
            HTTPRestConfig(chunked_rate=0.0),
            HTTPRestConfig(chunked_rate=0.0, trailer_rate=1.0),
            HTTPRestConfig(chunked_rate=0.0, chunk_size=(1, 2)),
        ):
            self.assertEqual([m.data for m in self._conv(config)],
                             [m.data for m in plain])

    def test_chunked_stream_roundtrips_through_parser(self) -> None:
        stream = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=4, seed=5,
            base_time=_BASE_TIME, config=self._ALL,
        )
        chunked = [m for m in _http_messages(stream.packets)
                   if m.headers.get("Transfer-Encoding") == "chunked"]
        self.assertTrue(chunked)
        for msg in chunked:
            self.assertNotIn("Content-Length", msg.headers)
            payload, _, _ = _dechunk(msg.body)
            self.assertIn("id", json.loads(payload))

    def test_zero_minimum_chunk_size_raises(self) -> None:
        """A zero-size chunk is the terminator: the body would end early."""
        with self.assertRaises(ValueError):
            generate_http_stream(
                client_ip="10.0.0.1", server_ip="10.1.0.1", requests=1,
                config=HTTPRestConfig(chunked_rate=1.0, chunk_size=(0, 32)),
            )

    def test_inverted_chunk_size_range_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_http_stream(
                client_ip="10.0.0.1", server_ip="10.1.0.1", requests=1,
                config=HTTPRestConfig(chunk_size=(40, 20)),
            )


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

    def test_cli_chunked_rate_reaches_the_generator(self) -> None:
        out = self._tmp()
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(pcap=out, requests=20, chunked_rate=1.0,
                                       error_rate=0.0))
        self.assertIn(b"Transfer-Encoding: chunked", Path(out).read_bytes())
        os.remove(out)

    def test_cli_trailer_rate_reaches_the_generator(self) -> None:
        out = self._tmp()
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(pcap=out, requests=20, chunked_rate=1.0,
                                       trailer_rate=1.0, error_rate=0.0))
        self.assertIn(b"Trailer:", Path(out).read_bytes())
        os.remove(out)

    def test_cli_error_rate_reaches_the_generator(self) -> None:
        out = self._tmp()
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(pcap=out, requests=10, error_rate=1.0))
        raw = Path(out).read_bytes()
        self.assertNotIn(b"HTTP/1.1 200 OK", raw)

    def test_cli_chunk_size_range_validated(self) -> None:
        with patch("sys.stderr", new=StringIO()), self.assertRaises(SystemExit):
            cli._cmd_stream(self._args(pcap=self._tmp(), min_chunk=0,
                                       chunked_rate=1.0))

    def test_cli_http_requires_tcp(self) -> None:
        with patch("sys.stderr", new=StringIO()), self.assertRaises(SystemExit):
            cli._cmd_stream(self._args(pcap=self._tmp(), protocol="udp"))


if __name__ == "__main__":
    unittest.main()
