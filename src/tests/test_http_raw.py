"""Exact HTTP bytes: `raw`, and a repeated header combined (#178).

#169 sent the messages it was given, but through the structured `http`
section, which the encoder rebuilds: a repeated header was dropped, spacing
normalised, a missing reason phrase given a trailing space.  An `http`
section now carries `raw`, as a `dns` section does, and `parse` writes it
when the fields would not rebuild the message.
"""
from __future__ import annotations

import gzip
import random
import unittest
from pathlib import Path

from packeteer import protocols
from packeteer.app import http, protocol_messages
from packeteer.generate import HTTPRestConfig, generate_http_stream
from packeteer.generate.http import HTTPRequest, HTTPResponse
from packeteer.parse import iter_packets
from packeteer.parse.http import parse_http
from packeteer.sanitise import SanitiseOptions

_CORPUS = Path(__file__).resolve().parents[2] / "testcases" / "real"

#: The issue's table, plus a line ending it did not list.
_NON_CANONICAL = {
    "a repeated header": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"),
    "no space after the colon": b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH:2\r\n\r\nhi",
    "whitespace around a value": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:  Gzip,  Chunked \r\n\r\n0\r\n\r\n"),
    "no reason phrase": b"HTTP/1.0 204\r\n\r\n",
    "bare LF line endings": b"GET / HTTP/1.1\nHost: h\n\n",
}


def _round_trip(wire: bytes) -> tuple[bytes, dict]:
    """Run the issue's path: decode, to_spec, from_spec, encode."""
    section = http.to_spec(http.decode(wire))
    return http.encode(http.from_spec(section)), section


class TestAMessageRoundTripsExactly(unittest.TestCase):

    def test_each_shape_the_fields_cannot_rebuild(self) -> None:
        for name, wire in _NON_CANONICAL.items():
            with self.subTest(name):
                out, section = _round_trip(wire)
                self.assertEqual(out, wire)
                self.assertIn("raw", section)

    def test_a_canonical_message_gets_no_raw(self) -> None:
        """Most messages, and all a generator writes."""
        wire = b"GET /x HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nhi"
        out, section = _round_trip(wire)
        self.assertEqual(out, wire)
        self.assertNotIn("raw", section)

    def test_raw_is_the_message_not_the_rest_of_the_segment(self) -> None:
        """What follows a Content-Length body belongs to the next message."""
        msg = parse_http(b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nhiNEXT")
        self.assertEqual(msg.raw, b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nhi")

    def test_the_real_corpus_is_unchanged(self) -> None:
        """Every HTTP message in it is canonical, so none gains a `raw`."""
        seen = 0
        for name in ("http_body.pcap", "tcp_v4.pcapng"):
            for pkt in iter_packets(path=_CORPUS / name):
                if pkt.http is not None:
                    seen += 1
                    self.assertEqual(pkt.http.raw, b"", name)
        self.assertEqual(seen, 4)


class TestARepeatedHeaderIsCombined(unittest.TestCase):
    """RFC 7230 §3.2.2: one list, in order, where it used to keep the last."""

    def test_two_transfer_encodings_are_one_list(self) -> None:
        msg = parse_http(_NON_CANONICAL["a repeated header"])
        self.assertEqual(msg.headers, {"Transfer-Encoding": "gzip, chunked"})

    def test_names_match_whatever_their_case(self) -> None:
        msg = parse_http(b"GET / HTTP/1.1\r\nAccept: a\r\naccept: b\r\n\r\n")
        self.assertEqual(msg.headers, {"Accept": "a, b"})

    def test_content_length_trims_however_it_is_spelled(self) -> None:
        """`CONTENT-LENGTH` went unread, so the body was not trimmed."""
        msg = parse_http(b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 2\r\n\r\nhiXX")
        self.assertEqual(msg.body, b"hi")


class TestARawSection(unittest.TestCase):
    """What `--protocol-messages` reads: the bytes, and nothing else needed."""

    def test_its_fields_come_from_the_bytes(self) -> None:
        msg = http.from_spec({"raw": _NON_CANONICAL["no reason phrase"].hex()})
        self.assertIsInstance(msg, HTTPResponse)
        self.assertEqual((msg.version, msg.status_code), ("1.0", 204))

    def test_its_bytes_win_over_the_other_fields(self) -> None:
        wire = b"GET /real HTTP/1.1\r\n\r\n"
        msg = http.from_spec({"raw": wire.hex(), "method": "POST", "path": "/no"})
        self.assertEqual(http.encode(msg), wire)

    def test_a_type_beside_it_decides(self) -> None:
        msg = http.from_spec({"raw": b"HTTP/1.1 200 OK\r\n\r\n".hex(),
                              "type": "request"})
        self.assertIsInstance(msg, HTTPRequest)

    def test_bytes_that_do_not_parse_are_still_sent(self) -> None:
        """A decoder's test wants malformed input too."""
        for wire, kind in ((b"\x00junk", HTTPRequest),
                           (b"HTTP/1.1 garbage", HTTPResponse)):
            with self.subTest(wire=wire):
                msg = http.from_spec({"raw": wire.hex()})
                self.assertIsInstance(msg, kind)
                self.assertEqual(http.encode(msg), wire)


class TestTypeIsRequestOrResponse(unittest.TestCase):
    """Anything else was read as a request, in silence (#180).

    With `raw`, `type` overrides the start line, so a misspelt `response`
    sent a response's exact bytes from the client.
    """

    _RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nR1".hex()

    def test_a_misspelling_is_refused_by_name(self) -> None:
        for section in ({"raw": self._RESPONSE, "type": "respnse"},
                        {"type": "reqest", "method": "GET"},
                        {"type": "Response", "status_code": 200}):
            with self.subTest(type=section["type"]), \
                    self.assertRaises(ValueError) as ctx:
                http.from_spec(section)
            self.assertIn(f"type must be 'request' or 'response', not "
                          f"{section['type']!r}", str(ctx.exception))

    def test_it_names_the_message_in_a_list(self) -> None:
        """What `--protocol-messages` reports: which message, and why."""
        with self.assertRaises(ValueError) as ctx:
            protocol_messages(protocols.for_section("http"), [
                {"http": {"raw": b"GET /a HTTP/1.1\r\n\r\n".hex()}},
                {"http": {"raw": self._RESPONSE, "type": "respnse"}},
            ], "tcp")
        self.assertIn("message 1", str(ctx.exception))
        self.assertIn("'respnse'", str(ctx.exception))

    def test_left_out_it_keeps_its_meaning(self) -> None:
        """The start line decides for `raw`; a structured section is a request."""
        self.assertIsInstance(http.from_spec({"raw": self._RESPONSE}), HTTPResponse)
        self.assertIsInstance(http.from_spec({"method": "GET"}), HTTPRequest)

    def test_both_spellings_still_work(self) -> None:
        self.assertIsInstance(http.from_spec({"type": "request"}), HTTPRequest)
        self.assertIsInstance(http.from_spec({"type": "response"}), HTTPResponse)


class TestSanitiseDropsRawWhenItRedacts(unittest.TestCase):
    """`raw` wins on build, so a redaction that left it would redact nothing."""

    _SECRET = b"GET / HTTP/1.1\r\nAuthorization:Bearer s3cret\r\n\r\n"

    def _sanitised(self, wire: bytes, **opts: bool) -> dict:
        section = http.to_spec(http.decode(wire))
        self.assertIn("raw", section)
        http.sanitise(section, None, SanitiseOptions(**opts))
        return section

    def test_a_redacted_header_takes_raw_with_it(self) -> None:
        section = self._sanitised(self._SECRET, http_headers=True)
        self.assertNotIn("raw", section)
        self.assertEqual(section["headers"]["Authorization"], "[redacted]")
        self.assertNotIn(b"s3cret", http.encode(http.from_spec(section)))

    def test_nothing_redacted_keeps_raw(self) -> None:
        section = self._sanitised(b"GET / HTTP/1.1\r\nX-Trace:1\r\n\r\n",
                                  http_headers=True)
        self.assertIn("raw", section)

    def test_header_redaction_off_changes_nothing(self) -> None:
        """Off by default: the section is untouched, so `raw` stays with it."""
        self.assertIn("raw", self._sanitised(self._SECRET))


class TestExactBytesInAStream(unittest.TestCase):
    """The issue's purpose: exact HTTP bytes into an impaired stream."""

    def test_raw_sections_arrive_byte_exact_in_both_directions(self) -> None:
        body = gzip.compress(random.Random(178).randbytes(900), mtime=0)
        request = b"GET /z HTTP/1.1\r\nHost:h\r\n\r\n"
        response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                    + b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")
        messages = protocol_messages(protocols.for_section("http"), [
            {"http": {"raw": request.hex()}}, {"http": {"raw": response.hex()}},
        ], "tcp")
        packets = generate_http_stream(
            client_ip="10.0.0.2", server_ip="10.0.1.1", requests=3, mss=200,
            seed=1, base_time=1_700_000_000.0,
            config=HTTPRestConfig(messages=messages),
        ).packets

        def direction(which: str) -> bytes:
            segments = {p.seq: p.raw[-p.payload_len:] for p in packets
                        if p.direction == which and p.payload_len}
            return b"".join(segments[s] for s in sorted(segments))

        self.assertEqual(direction("c2s").count(request), 3)
        self.assertEqual(direction("s2c").count(response), 3)


if __name__ == "__main__":
    unittest.main()
