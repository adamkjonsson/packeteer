"""`stream --payload http` sends the messages it is given (#169).

`--protocol-messages` was accepted with `--payload http` and dropped: the
capture held generated REST traffic and nothing from the file.  It now sends
the file's messages over the same conversation generated traffic uses, so
they keep what `--payload http` has and a one-field `blob` spec does not:
both directions, the handshake, and segmentation at `--mss`.
"""
from __future__ import annotations

import gzip
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from packeteer import protocols
from packeteer.app import http, protocol_messages
from packeteer.generate import HTTPRestConfig, generate_http_stream
from packeteer.generate.http import HTTPRequest, HTTPResponse
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.parse import parse_packet

_BASE_TIME = 1_700_000_000.0

#: A body that does not compress, gzipped, so it is larger than any MSS the
#: tests use and has to arrive in pieces.
_BODY = gzip.compress(random.Random(169).randbytes(3000), mtime=0)

_SECTIONS = [
    {"http": {"type": "request", "method": "GET", "path": "/doc",
              "headers": {"Host": "h", "Accept-Encoding": "gzip"}}},
    {"http": {"type": "response", "status_code": 200, "reason": "OK",
              "headers": {"Content-Encoding": "gzip",
                          "Content-Length": str(len(_BODY))},
              "body": _BODY.hex()}},
]


def _stream(messages: list, **kwargs: object) -> list:
    """Return the packets of a stream carrying *messages*."""
    impairments = kwargs.pop("impairments", None)
    kwargs.setdefault("client_ip", "10.0.0.2")
    kwargs.setdefault("server_ip", "10.0.1.1")
    return generate_http_stream(
        seed=1, base_time=_BASE_TIME,
        config=HTTPRestConfig(messages=messages, impairments=impairments),
        **kwargs,
    ).packets


def _direction(packets: list, direction: str) -> bytes:
    """Reassemble one direction's payload, a retransmission counted once."""
    segments = {p.seq: p.raw[-p.payload_len:] for p in packets
                if p.direction == direction and p.payload_len}
    return b"".join(segments[seq] for seq in sorted(segments))


def _small() -> list:
    return [
        HTTPRequest(method="GET", path="/a", headers={"Host": "h"}),
        HTTPResponse(headers={"Content-Type": "text/plain"}, body=b"one"),
    ]


class TestTheMessagesAreSent(unittest.TestCase):
    """What the file says goes on the wire, and nothing generated does."""

    def test_sections_round_trip_through_a_capture(self) -> None:
        """Sections in, parsed back out: the same sections, in order."""
        sections = [
            {"http": {"type": "request", "method": "POST", "path": "/p",
                      "version": "1.1", "headers": {"Host": "h"},
                      "body": b"hi".hex()}},
            {"http": {"type": "response", "version": "1.1", "status_code": 201,
                      "reason": "Created", "headers": {"X-Id": "7"},
                      "body": b"ok".hex()}},
        ]
        messages = protocol_messages(protocols.for_section("http"), sections, "tcp")
        packets = _stream(messages, requests=1)
        parsed = [parse_packet(p.raw) for p in packets]
        out = [http.to_spec(pkt.http) for pkt in parsed if pkt.http is not None]
        # The encoder adds the Content-Length a body needs, so it is on the
        # wire and in what is parsed back; everything else is as given.
        for section in out:
            section["headers"].pop("Content-Length")
        self.assertEqual(out, [s["http"] for s in sections])

    def test_both_directions(self) -> None:
        packets = _stream(_small(), requests=1)
        self.assertIn(b"GET /a HTTP/1.1", _direction(packets, "c2s"))
        self.assertIn(b"HTTP/1.1 200 OK", _direction(packets, "s2c"))

    def test_no_generated_traffic(self) -> None:
        """The issue: the capture held generated REST traffic instead."""
        wire = b"".join(p.raw for p in _stream(_small(), requests=3))
        self.assertNotIn(b"/api/v1", wire)

    def test_a_body_larger_than_the_mss_arrives_whole(self) -> None:
        """What kober's transform phase needs: exact gzip bytes, segmented."""
        messages = protocol_messages(protocols.for_section("http"), _SECTIONS, "tcp")
        packets = _stream(messages, requests=2, mss=500)
        s2c = [p for p in packets if p.direction == "s2c" and p.payload_len]
        self.assertGreater(len(s2c), 2 * (len(_BODY) // 500))
        self.assertTrue(all(p.payload_len <= 500 for p in s2c))
        self.assertEqual(_direction(packets, "s2c").count(_BODY), 2)

    def test_and_with_loss_recovered(self) -> None:
        """Retransmission fills what loss takes; the body is still exact.

        Loss alone leaves a permanent gap, which is what a lossy corpus
        wants; `retransmit_lost` is what recovers it.
        """
        messages = protocol_messages(protocols.for_section("http"), _SECTIONS, "tcp")
        packets = _stream(messages, requests=2, mss=500,
                          impairments=ImpairmentConfig(packet_loss_probability=0.2,
                                                       retransmit_lost=True))
        self.assertTrue(any(p.label.startswith("RETRANS") for p in packets),
                        "the seed should lose something, or this tests nothing")
        self.assertEqual(_direction(packets, "s2c").count(_BODY), 2)

    def test_the_content_knobs_do_not_apply(self) -> None:
        """Given messages go as written, whatever the generator's knobs say."""
        plain = _stream(_small(), requests=2)
        knobbed = generate_http_stream(
            client_ip="10.0.0.2", server_ip="10.0.1.1", seed=1,
            base_time=_BASE_TIME, requests=2,
            config=HTTPRestConfig(messages=_small(), chunked_rate=1.0,
                                  error_rate=1.0, trailer_rate=1.0),
        ).packets
        self.assertEqual([p.raw for p in plain], [p.raw for p in knobbed])


class TestTheListMakesUpTheConversation(unittest.TestCase):
    """How a list becomes transactions, connections and sessions."""

    def test_it_repeats_to_make_up_requests(self) -> None:
        """As `--payload <protocol>` repeats its messages (Q1)."""
        c2s = _direction(_stream(_small(), requests=5), "c2s")
        self.assertEqual(c2s.count(b"GET /a HTTP/1.1"), 5)

    def test_a_transaction_is_a_request_and_the_responses_after_it(self) -> None:
        """Two transactions, cut across two connections at their requests."""
        messages = [
            HTTPRequest(path="/1"), HTTPResponse(reason="first"),
            HTTPRequest(path="/2"), HTTPResponse(reason="second"),
        ]
        packets = _stream(messages, requests=2, requests_per_connection=1)
        self.assertEqual(sum(p.label == "SYN" for p in packets), 2)
        by_port: dict[int, bytes] = {}
        for p in packets:
            if p.payload_len and p.direction == "s2c":
                pkt = parse_packet(p.raw)
                by_port[pkt.transport.dst_port] = (
                    by_port.get(pkt.transport.dst_port, b"") + p.raw[-p.payload_len:])
        self.assertEqual(sorted(by_port.values()), sorted([
            b"HTTP/1.1 200 first\r\n\r\n", b"HTTP/1.1 200 second\r\n\r\n"]))

    def test_pipelined_requests_keep_their_order(self) -> None:
        messages = [
            HTTPRequest(path="/1"), HTTPRequest(path="/2"),
            HTTPResponse(reason="first"), HTTPResponse(reason="second"),
        ]
        c2s = _direction(_stream(messages, requests=2), "c2s")
        self.assertLess(c2s.index(b"GET /1 "), c2s.index(b"GET /2 "))

    def test_every_session_replays_the_list_from_its_start(self) -> None:
        messages = [HTTPRequest(path="/1"), HTTPRequest(path="/2")]
        packets = _stream(messages, requests=1, sessions=2)
        firsts = [p.raw for p in packets if p.payload_len and p.direction == "c2s"]
        self.assertEqual(len(firsts), 2)
        self.assertTrue(all(b"GET /1 " in raw for raw in firsts))

    def test_a_list_that_starts_with_a_response_is_refused(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            _stream([HTTPResponse(), HTTPRequest()])
        self.assertIn("message 0 is a response", str(ctx.exception))

    def test_an_empty_list_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            _stream([])

    def test_something_that_is_not_a_message_is_refused(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            _stream([HTTPRequest(), "GET / HTTP/1.1"])
        self.assertIn("message 1 is a str", str(ctx.exception))


class TestProtocolMessages(unittest.TestCase):
    """The API the CLI reads a file through: `protocol_payload_fn`'s first half."""

    def test_it_takes_a_parse_document(self) -> None:
        """A capture's messages replay through the same call (#137's shape)."""
        packets = [parse_packet(p.raw) for p in _stream(_small(), requests=1)]
        # The shape `packeteer parse` writes: every packet has a network
        # layer, and only those carrying a message have an `http` section.
        document = {"packets": [
            {"network": {}, **({"http": http.to_spec(pkt.http)} if pkt.http else {})}
            for pkt in packets
        ]}
        messages = protocol_messages(protocols.for_section("http"), document, "tcp")
        self.assertEqual([type(m) for m in messages], [HTTPRequest, HTTPResponse])

    def test_a_bad_section_names_its_index(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            protocol_messages(protocols.for_section("http"),
                              [{"http": {"type": "request"}}, {"nope": 1}], "tcp")
        self.assertIn("message 1", str(ctx.exception))


def _packeteer(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "packeteer", *args],
        capture_output=True, text=True, check=False,
    )


class TestTheCLI(unittest.TestCase):
    """The issue's own command, and the flags that no longer pass in silence."""

    def setUp(self) -> None:
        import shutil

        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.messages = self.dir / "m.json"
        self.messages.write_text(json.dumps(_SECTIONS))

    def _stream(self, *extra: str) -> subprocess.CompletedProcess:
        return _packeteer(
            "stream", "--payload", "http", "--client-ip", "10.0.0.2",
            "--server-ip", "10.0.0.1", "--seed", "1",
            "--pcap", str(self.dir / "t.pcap"), *extra,
        )

    def test_the_issues_command(self) -> None:
        done = self._stream("--protocol-messages", str(self.messages),
                            "--requests", "2", "--mss", "600")
        self.assertEqual(done.returncode, 0, done.stderr)
        raw = (self.dir / "t.pcap").read_bytes()
        self.assertIn(b"GET /doc HTTP/1.1", raw)
        self.assertNotIn(b"/api/v1", raw)

    def test_a_content_flag_is_refused_by_name(self) -> None:
        done = self._stream("--protocol-messages", str(self.messages),
                            "--error-rate", "0.2", "--trailer-rate", "0.1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("--error-rate, --trailer-rate shape generated HTTP traffic",
                      done.stderr)

    def test_a_content_key_in_a_config_file_is_refused_by_name(self) -> None:
        """A value from a file is as much the user's as a flag (Q2)."""
        config = self.dir / "s.ini"
        config.write_text("[stream]\nchunked_rate = 0.5\n")
        done = self._stream("--protocol-messages", str(self.messages),
                            "--config", str(config))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(f"'chunked_rate' in {config}", done.stderr)

    def test_generated_http_still_takes_its_flags(self) -> None:
        done = self._stream("--chunked-rate", "0.5", "--requests", "2")
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
