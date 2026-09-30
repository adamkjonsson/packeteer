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
from packeteer.app import dns, http, protocol_messages
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


class TestTheEdgesOfRaw(unittest.TestCase):
    """An empty `raw`, and hex that is not hex (#181)."""

    def test_an_empty_raw_is_refused(self) -> None:
        """It sent a default `GET /` nobody wrote, though `raw` wins."""
        with self.assertRaises(ValueError) as ctx:
            http.from_spec({"raw": ""})
        self.assertIn("http: raw is empty", str(ctx.exception))

    def test_bad_hex_names_its_protocol_and_key(self) -> None:
        cases = (
            (http, {"raw": "zz"}, "http: raw is not hex: 'z' at position 0"),
            (http, {"body": "4g"}, "http: body is not hex: 'g' at position 1"),
            (dns, {"raw": "zz"}, "dns: raw is not hex: 'z' at position 0"),
            (http, {"raw": "abc"}, "http: raw is not hex: an odd number"),
            (http, {"raw": 5}, "http: raw must be a hex string, not int"),
        )
        for module, section, expected in cases:
            with self.subTest(section=section), self.assertRaises(ValueError) as ctx:
                module.from_spec(section)
            self.assertIn(expected, str(ctx.exception))

    def test_section_bytes_reads_what_fromhex_reads(self) -> None:
        """Whitespace between digits is allowed, and absent is empty."""
        self.assertEqual(protocols.section_bytes("t", {"k": "de ad"}, "k"),
                         b"\xde\xad")
        self.assertEqual(protocols.section_bytes("t", {}, "k"), b"")


class TestSetCookieIsKeptApart(unittest.TestCase):
    """RFC 7230's one field that cannot be combined, as a list (#181).

    A cookie's `Expires` has a comma in it, so a folded value is ambiguous,
    and `sanitise`, which drops `raw` as it redacts, rebuilt two lines as one.
    """

    _WIRE = (b"HTTP/1.1 200 OK\r\n"
             b"Set-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\n"
             b"Set-Cookie: b=2\r\nContent-Length: 0\r\n\r\n")

    def test_a_repeated_set_cookie_is_a_list(self) -> None:
        self.assertEqual(parse_http(self._WIRE).headers["Set-Cookie"],
                         ["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "b=2"])

    def test_the_fields_alone_rebuild_it(self) -> None:
        """So it needs no `raw`, and nothing is lost when `raw` goes."""
        section = http.to_spec(http.decode(self._WIRE))
        self.assertNotIn("raw", section)
        self.assertEqual(http.encode(http.from_spec(section)), self._WIRE)

    def test_sanitise_keeps_the_number_of_lines(self) -> None:
        section = http.to_spec(http.decode(self._WIRE))
        http.sanitise(section, None, SanitiseOptions(http_headers=True))
        out = http.encode(http.from_spec(section))
        self.assertEqual(out.count(b"Set-Cookie: [redacted]\r\n"), 2)

    def test_one_set_cookie_is_still_a_string(self) -> None:
        msg = parse_http(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\n\r\n")
        self.assertEqual(msg.headers["Set-Cookie"], "a=1")

    def test_any_header_may_be_written_as_a_list(self) -> None:
        """Two Transfer-Encoding lines, without `raw`."""
        msg = http.from_spec({"type": "response", "headers": {
            "Transfer-Encoding": ["gzip", "chunked"]}})
        self.assertEqual(http.encode(msg), b"HTTP/1.1 200 OK\r\n"
                         b"Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n")


class TestAHeaderValueIsAStringOrAListOfThem(unittest.TestCase):
    """Anything else went on the wire as Python spells it (#182)."""

    def _lines(self, value: object) -> list[bytes]:
        msg = http.from_spec({"type": "response", "headers": {"Set-Cookie": value}})
        return http.encode(msg).split(b"\r\n")[1:-2]

    def test_what_is_not_a_header_value_is_refused_by_name(self) -> None:
        cases = (
            ([["a=1"]], "header 'Set-Cookie' item 0 must be a string, not list"),
            ([{"x": 1}], "header 'Set-Cookie' item 0 must be a string, not dict"),
            (["a=1", True], "header 'Set-Cookie' item 1 must be a string, not bool"),
            (True, "header 'Set-Cookie' must be a string, not bool"),
            (None, "header 'Set-Cookie' must be a string, not NoneType"),
            (1.5, "header 'Set-Cookie' must be a string, not float"),
        )
        for value, expected in cases:
            with self.subTest(value=value), self.assertRaises(ValueError) as ctx:
                self._lines(value)
            self.assertIn(f"http: {expected}", str(ctx.exception))

    def test_headers_must_be_an_object(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            http.from_spec({"type": "response", "headers": ["Set-Cookie: a=1"]})
        self.assertIn("http: headers must be an object, not list", str(ctx.exception))

    def test_what_always_worked_still_does(self) -> None:
        """A string, an integer as its digits, and a list of those."""
        self.assertEqual(self._lines("a=1"), [b"Set-Cookie: a=1"])
        self.assertEqual(self._lines(2), [b"Set-Cookie: 2"])
        self.assertEqual(self._lines(["a=1", 2]),
                         [b"Set-Cookie: a=1", b"Set-Cookie: 2"])
        self.assertEqual(self._lines([]), [])


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
