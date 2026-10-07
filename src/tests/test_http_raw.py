"""Exact HTTP bytes: `raw`, and a repeated header combined (#178).

#169 sent the messages it was given, but through the structured `http`
section, which the encoder rebuilds: a repeated header was dropped, spacing
normalised, a missing reason phrase given a trailing space.  An `http`
section now carries `raw`, as a `dns` section does, and `parse` writes it
when the fields would not rebuild the message.
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


def _r(original: bytes) -> bytes:
    """Return a redacted value as on the wire: ``[redacted]`` at *original*'s length (#191)."""
    from packeteer.sanitise import _redaction

    return _redaction(len(original)).encode()


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

    def test_an_empty_dns_raw_is_refused_too(self) -> None:
        """A `raw` that is present sends exactly its bytes, in either protocol (#183).

        It was read as absent, and a message built from `id` went out in its
        place.
        """
        with self.assertRaises(ValueError) as ctx:
            dns.from_spec({"raw": "", "id": 7})
        self.assertIn("dns: raw is empty", str(ctx.exception))

    def test_an_absent_raw_means_what_it_did(self) -> None:
        self.assertEqual(dns.from_spec({"id": 7}).raw, b"")
        self.assertEqual(http.from_spec({"method": "GET"}).raw, b"")

    def test_section_raw_is_the_one_check(self) -> None:
        """What a protocol with a `raw` key calls, now or later."""
        self.assertIsNone(protocols.section_raw("t", {}))
        self.assertEqual(protocols.section_raw("t", {"raw": "00ff"}), b"\x00\xff")
        with self.assertRaises(ValueError) as ctx:
            protocols.section_raw("t", {"raw": ""})
        self.assertIn("t: raw is empty", str(ctx.exception))

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
        self.assertEqual(out.count(b"Set-Cookie: "), 2)
        for value in (b"a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", b"b=2"):
            self.assertIn(b"Set-Cookie: " + _r(value) + b"\r\n", out)

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


class TestSanitiseRedactsInsideRaw(unittest.TestCase):
    """A redacted header is redacted in `raw` too, and `raw` stays (#184).

    `raw` wins on build, so a redaction that left it would redact nothing.
    #178 dropped it, and the rebuilt message lost the capture's shape:
    repeated headers regrouped, repeated `Transfer-Encoding` lines merged.
    A sanitised capture stands in for a real one, and a decoder's tests are
    about exactly that shape.
    """

    _SECRET = b"GET / HTTP/1.1\r\nAuthorization:Bearer s3cret\r\n\r\n"

    def _sanitised(self, wire: bytes, **opts: bool) -> dict:
        section = http.to_spec(http.decode(wire))
        self.assertIn("raw", section)
        http.sanitise(section, None, SanitiseOptions(**opts))
        return section

    def _wire(self, section: dict) -> bytes:
        return http.encode(http.from_spec(section))

    def test_a_redacted_value_is_redacted_in_raw(self) -> None:
        section = self._sanitised(self._SECRET, http_headers=True)
        self.assertEqual(section["headers"]["Authorization"],
                         _r(b"Bearer s3cret").decode())
        self.assertEqual(self._wire(section),
                         b"GET / HTTP/1.1\r\nAuthorization:" + _r(b"Bearer s3cret")
                         + b"\r\n\r\n")

    def test_the_issues_two_shapes_are_kept(self) -> None:
        """Every byte but the sensitive values, as captured."""
        cases = (
            (b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Expires=Wed, 21 Oct 2026"
             b" 07:28:00 GMT\r\nContent-Length: 2\r\nSet-Cookie: theme=dark\r\n\r\nok",
             b"HTTP/1.1 200 OK\r\nSet-Cookie: "
             + _r(b"session=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
             + b"\r\nContent-Length: 2\r\nSet-Cookie: " + _r(b"theme=dark")
             + b"\r\n\r\nok"),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: "
             b"chunked\r\nSet-Cookie: s=1\r\n\r\n0\r\n\r\n",
             b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: "
             b"chunked\r\nSet-Cookie: " + _r(b"s=1") + b"\r\n\r\n0\r\n\r\n"),
        )
        for wire, expected in cases:
            with self.subTest(wire=wire[:40]):
                section = self._sanitised(wire, http_headers=True)
                self.assertIn("raw", section)
                self.assertEqual(self._wire(section), expected)

    def test_spacing_and_line_endings_are_kept(self) -> None:
        cases = (
            (b"GET / HTTP/1.1\r\nHost:  h\r\nX:y\r\n\r\n",
             b"GET / HTTP/1.1\r\nHost:  " + _r(b"h") + b"\r\nX:y\r\n\r\n"),
            (b"GET / HTTP/1.1\nCookie: a=1\nX: y\n\n",
             b"GET / HTTP/1.1\nCookie: " + _r(b"a=1") + b"\nX: y\n\n"),
        )
        for wire, expected in cases:
            with self.subTest(wire=wire):
                self.assertEqual(self._wire(self._sanitised(wire, http_headers=True)),
                                 expected)

    def test_a_head_it_cannot_read_falls_back_to_dropping_raw(self) -> None:
        """A folded line above all: a secret continued onto it would survive."""
        cases = (
            b"GET / HTTP/1.1\r\nAuthorization: Bearer s3\r\n cret\r\n\r\n",
            b"GET / HTTP/1.1\r\nAuthorization: Bearer s3cret\r\nno colon\r\n\r\n",
        )
        for wire in cases:
            with self.subTest(wire=wire):
                section = self._sanitised(wire, http_headers=True)
                self.assertNotIn("raw", section)
                out = self._wire(section)
                self.assertNotIn(b"s3", out)
                self.assertNotIn(b"cret", out)

    def test_nothing_redacted_keeps_raw_as_it_was(self) -> None:
        wire = b"GET / HTTP/1.1\r\nX-Trace:1\r\n\r\n"
        section = self._sanitised(wire, http_headers=True)
        self.assertEqual(bytes.fromhex(section["raw"]), wire)

    def test_header_redaction_off_changes_nothing(self) -> None:
        """Off by default: the section is untouched, so `raw` stays with it."""
        section = self._sanitised(self._SECRET)
        self.assertEqual(bytes.fromhex(section["raw"]), self._SECRET)


class TestPayloadZeroesTheBody(unittest.TestCase):
    """`--payload` zeroes an HTTP body, and `--scan-pii` reads one (#185).

    Once `parse` decoded a message into an `http` section, its body went back
    on the wire as captured: `--payload` touched only a packet's top-level
    payload, and the scan read strings, where a body is hex.
    """

    _LOGIN = (b"POST /login HTTP/1.1\r\nHost: shop.example.com\r\n"
              b"Content-Length: 29\r\n\r\nuser=alice&password=hunter2!!")
    _CHUNKED = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n")

    def _payload(self, wire: bytes, *, structured: bool = False) -> dict:
        section = http.to_spec(http.decode(wire))
        if structured:
            section.pop("raw", None)
        http.sanitise(section, None, SanitiseOptions(payload=True))
        return section

    def test_a_length_framed_body_is_zeroed_at_its_length(self) -> None:
        out = http.encode(http.from_spec(self._payload(self._LOGIN)))
        head, body = out.split(b"\r\n\r\n", 1)
        self.assertEqual(body, bytes(29))
        self.assertIn(b"Content-Length: 29", head)

    def test_a_chunked_body_keeps_its_framing(self) -> None:
        """Only what can carry data goes, so the message still parses.

        Chunk data is zeroed; since #189 an extension's value and a trailer
        field's value go too, and the names, sizes and CRLFs stay.
        """
        for structured in (False, True):
            with self.subTest(structured=structured):
                section = self._payload(self._CHUNKED, structured=structured)
                out = http.encode(http.from_spec(section))
                self.assertEqual(out.split(b"\r\n\r\n", 1)[1],
                                 b"5\r\n" + bytes(5) + b"\r\n6;ext=0\r\n" + bytes(6)
                                 + b"\r\n0\r\nX-Trailer: " + _r(b"t") + b"\r\n\r\n")
                parse_http(out)

    def test_a_chunked_body_it_cannot_walk_is_zeroed_whole(self) -> None:
        wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"zz\r\nsecret-data\r\n")
        out = http.encode(http.from_spec(self._payload(wire)))
        body = out.split(b"\r\n\r\n", 1)[1]
        self.assertEqual(body, bytes(len(body)))
        self.assertNotIn(b"secret", out)

    def test_a_structured_body_is_zeroed_too(self) -> None:
        section = self._payload(self._LOGIN, structured=True)
        self.assertEqual(bytes.fromhex(section["body"]), bytes(29))

    def test_without_payload_the_body_is_left(self) -> None:
        section = http.to_spec(http.decode(self._LOGIN))
        http.sanitise(section, None, SanitiseOptions())
        self.assertIn(b"hunter2", http.encode(http.from_spec(section)))

    def test_the_scan_reads_a_body_as_text(self) -> None:
        """The email in a response body is found, and named by packet."""
        from packeteer.sanitise import PersonalDataWarning, _scan_http_body

        wire = (b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"
                b'{"email":"a@b.com"}\n')
        for structured in (False, True):
            section = http.to_spec(http.decode(wire))
            section["raw"] = wire.hex()
            if structured:
                section.pop("raw")
            with self.subTest(structured=structured), \
                    self.assertWarns(PersonalDataWarning) as ctx:
                _scan_http_body(section, 6)
            self.assertIn("in packet 6", str(ctx.warning))

    def test_with_payload_it_is_scanned_first_and_zeroed(self) -> None:
        """As a payload is: the warning says what was there, and it goes."""
        from packeteer.sanitise import PersonalDataWarning, sanitise

        wire = (b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"
                b'{"email":"a@b.com"}\n')
        config = {"packets": [{"network": {}, "http": http.to_spec(http.decode(wire))}]}
        with self.assertWarns(PersonalDataWarning):
            out = sanitise(config, SanitiseOptions(payload=True))
        self.assertNotIn(b"a@b.com",
                         http.encode(http.from_spec(out["packets"][0]["http"])))

    def test_a_body_that_is_not_text_is_not_scanned(self) -> None:
        """A gzip body, say: packeteer inflates bodies nowhere."""
        body = gzip.compress(b'{"email":"a@b.com"}', mtime=0)
        section = {"type": "response", "headers": {"Content-Encoding": "gzip"},
                   "body": body.hex()}
        self.assertIsNone(http.body_text(section))


class TestAWalkThatFailsDoesNotEndTheRun(unittest.TestCase):
    """A body that cannot be walked is zeroed whole, and the run goes on (#186).

    A chunked body cut after its last-chunk line raised "negative count",
    and `sanitise` ended the whole run, writing nothing.
    """

    _HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    _BODY = (b"8\r\nSECRETA1\r\n8;ext=v\r\nSECRETB2\r\n0\r\n"
             b"X-Trail: t\r\n\r\n")

    def test_the_issues_tails(self) -> None:
        from packeteer.app.http import _zeroed

        for body in (b"7\r\nSECRETA\r\n0\r\n", b"7\r\nSECRETA\r\n0\r\nXY",
                     b"7\r\nSECRETA\r\n0\r\nX-Trail: SECRETB-no-end",
                     b"-5\r\nABCDE\r\n0\r\n\r\n"):
            with self.subTest(body=body):
                out = _zeroed(body, True)
                self.assertEqual(len(out), len(body))
                for secret in (b"SECRET", b"ABCDE"):
                    self.assertNotIn(secret, out)

    def test_a_body_cut_at_every_offset(self) -> None:
        """What kober asked for: none raises, and no chunk data is kept."""
        from packeteer.sanitise import sanitise

        for cut in range(len(self._BODY) + 1):
            body = self._BODY[:cut]
            section = {"type": "response",
                       "headers": {"Transfer-Encoding": "chunked"},
                       "body": body.hex(), "raw": (self._HEAD + body).hex()}
            with self.subTest(cut=cut):
                out = sanitise({"packets": [{"network": {}, "http": section}]},
                               SanitiseOptions(payload=True, scan_pii=False))
                result = out["packets"][0]["http"]
                for key in ("body", "raw"):
                    kept = bytes.fromhex(result[key])
                    for secret in (b"SECRETA1", b"SECRETB2"):
                        for start in range(len(secret) - 3):
                            self.assertNotIn(secret[start:start + 4], kept)

    def test_hex_that_is_not_hex_is_zeroed_not_raised(self) -> None:
        from packeteer.app.http import _zero_bodies

        section = {"type": "response", "body": "zz11", "raw": "zz11"}
        _zero_bodies(section)
        self.assertEqual((section["body"], section["raw"]), ("0000", "0000"))


class TestTheHeadEndsAtTheFirstBlankLine(unittest.TestCase):
    """Whichever of CRLF CRLF and LF LF comes first ends the head (#188).

    The separator was chosen by whether CRLF CRLF occurred anywhere, so a
    bare-LF head ran on into a body that held a CRLF pair.  `--payload` kept
    the body's first line, and `parse_http` read it as a header.
    """

    _LF_HEAD = (b"HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 30"
                b"\n\nSECRETC\r\n\r\nSECRETD-more-text")

    def test_parse_reads_the_body_from_its_first_byte(self) -> None:
        msg = parse_http(self._LF_HEAD)
        self.assertEqual(msg.body, b"SECRETC\r\n\r\nSECRETD-more-text")
        self.assertEqual(set(msg.headers), {"Content-Type", "Content-Length"})

    def test_payload_keeps_no_byte_of_the_body(self) -> None:
        section = {"type": "response", "raw": self._LF_HEAD.hex()}
        http.sanitise(section, None, SanitiseOptions(payload=True))
        out = bytes.fromhex(section["raw"])
        self.assertNotIn(b"SECRET", out)
        self.assertEqual(len(out), len(self._LF_HEAD))

    def test_headers_are_redacted_in_place_by_the_same_split(self) -> None:
        wire = (b"HTTP/1.1 200 OK\nSet-Cookie: s=1\nContent-Length: 14\n\n"
                b"a\r\n\r\nb: secret")
        section = http.to_spec(http.decode(wire))
        http.sanitise(section, None, SanitiseOptions(http_headers=True))
        self.assertEqual(bytes.fromhex(section["raw"]),
                         b"HTTP/1.1 200 OK\nSet-Cookie: " + _r(b"s=1") + b"\n"
                         b"Content-Length: 14\n\na\r\n\r\nb: secret")

    def test_the_other_way_round(self) -> None:
        """A CRLF head with an LF pair in its body."""
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nab\n\ncd"
        self.assertEqual(parse_http(wire).body, b"ab\n\ncd")

    def test_split_head(self) -> None:
        from packeteer.parse.http import split_head

        self.assertEqual(split_head(b"H\r\nA: 1\r\n\r\nB"),
                         (b"H\r\nA: 1", b"\r\n\r\n", b"B"))
        self.assertEqual(split_head(b"H\nA: 1\n\nB\r\n\r\nC"),
                         (b"H\nA: 1", b"\n\n", b"B\r\n\r\nC"))
        self.assertIsNone(split_head(b"H\r\nA: 1"))


class TestPayloadTakesWhatCanCarryTheBody(unittest.TestCase):
    """A chunk extension's value and a trailer field's value go too (#189).

    A trailer is where a checksum or signature over the body is sent, and a
    digest survived zeroing: enough to confirm a guessed body.
    """

    def test_the_issues_before_and_after(self) -> None:
        from packeteer.app.http import _zeroed

        before = (b"7;ext=SECRET1\r\nSECRET2\r\n6\r\nSECRE3\r\n0\r\n"
                  b"X-Checksum: SECRET4-digest\r\n\r\n")
        self.assertEqual(_zeroed(before, True),
                         b"7;ext=0000000\r\n" + bytes(7) + b"\r\n6\r\n" + bytes(6)
                         + b"\r\n0\r\nX-Checksum: " + _r(b"SECRET4-digest") + b"\r\n\r\n")

    def test_extensions(self) -> None:
        from packeteer.app.http import _zero_extensions

        cases = (
            (b"7", b"7"),
            (b"7;ext", b"7;ext"),
            (b'7;ext="SECRET"', b'7;ext="000000"'),
            (b"7; a=1 ;b= v ", b"7; a=0 ;b= 0 "),
            (b'7;q="a;b"', b"7;0000000"),        # a ";" inside quotes: all of it
            (b'7;x="open', b"7;0000000"),        # an unclosed quote: all of it
        )
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(_zero_extensions(line), expected)

    def test_several_trailer_fields_each_redacted(self) -> None:
        from packeteer.app.http import _zeroed

        out = _zeroed(b"1\r\nA\r\n0\r\nX-A: one\r\nX-B:two\r\n\r\n", True)
        self.assertEqual(out, b"1\r\n\x00\r\n0\r\nX-A: " + _r(b"one") + b"\r\n"
                              b"X-B:" + _r(b"two") + b"\r\n\r\n")

    def test_a_trailer_it_cannot_read_is_zeroed_whole(self) -> None:
        """A folded line, or one with no colon, could carry the rest of a value."""
        from packeteer.app.http import _zeroed

        for trailer in (b"X-A: sec\r\n ret", b"no colon secret"):
            with self.subTest(trailer=trailer):
                out = _zeroed(b"1\r\nA\r\n0\r\n" + trailer + b"\r\n\r\n", True)
                self.assertNotIn(b"sec", out)
                self.assertTrue(out.endswith(bytes(len(trailer)) + b"\r\n\r\n"))


class TestEverySpellingOfTheEmptyLine(unittest.TestCase):
    """The head ends at its first empty line, however it is spelled (#190).

    #188 searched for two fixed pairs and missed the third spelling, a last
    header ended by LF and an empty line by CRLF, which ran the head into the
    body.  A property over every spelling and every kind of body, rather than
    the one case, since this round's faults were in earlier rounds' fixes.
    """

    _SPELLINGS = (b"\r\n\r\n", b"\n\n", b"\n\r\n", b"\r\n\n")
    _BODIES = (b"SECRETG-and-more", b"SECRETG\r\n\r\nSECRETH",
               b"SECRETG\n\nSECRETH", b"SECRETG\n\n\r\n\r\nSECRETH")

    def _cases(self) -> list[tuple[bytes, bytes, bytes]]:
        head = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1"
        return [(spelling, body,
                 head.replace(b"\r\nSet", b"\r\nContent-Length: %d\r\nSet" % len(body))
                 + spelling + body)
                for spelling in self._SPELLINGS for body in self._BODIES]

    def test_split_head_and_parse(self) -> None:
        from packeteer.parse.http import split_head

        for spelling, body, wire in self._cases():
            with self.subTest(spelling=spelling, body=body):
                head, sep, rest = split_head(wire)
                self.assertEqual(sep, spelling)
                self.assertFalse(head.endswith(b"\r"))
                self.assertEqual(rest, body)
                self.assertEqual(parse_http(wire).body, body)

    def test_payload_keeps_no_body_byte(self) -> None:
        for spelling, body, wire in self._cases():
            with self.subTest(spelling=spelling, body=body):
                section = {"type": "response", "raw": wire.hex()}
                http.sanitise(section, None, SanitiseOptions(payload=True))
                out = bytes.fromhex(section["raw"])
                self.assertNotIn(b"SECRET", out)
                self.assertTrue(out.endswith(spelling + bytes(len(body))))

    def test_headers_are_redacted_in_place(self) -> None:
        for spelling, body, wire in self._cases():
            with self.subTest(spelling=spelling, body=body):
                section = http.to_spec(http.decode(wire))
                section["raw"] = wire.hex()
                http.sanitise(section, None, SanitiseOptions(http_headers=True))
                out = bytes.fromhex(section["raw"])
                self.assertNotIn(b"s=1", out)
                self.assertTrue(out.endswith(spelling + body), out)


def _cli(*args: str) -> None:
    done = subprocess.run([sys.executable, "-m", "packeteer", *args],
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr


class TestNoBodyByteSurvivesSanitise(unittest.TestCase):
    """The pin kober asked for, through the CLI as the issue reproduced it (#185)."""

    _BODIES = (b"user=alice&password=hunter2!!", b'{"email":"a@b.com","n":123456}',
               b"first-chunk-of-secrets", b"second-chunk-of-secrets",
               b"digest-of-the-secrets")

    def test_payload_leaves_no_run_of_any_original_body(self) -> None:
        login, email, one, two, digest = self._BODIES
        messages = [
            b"POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n" % len(login)
            + login,
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(email) + email,
            b"GET /c HTTP/1.1\r\nHost: h\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + b"%x\r\n" % len(one) + one + b"\r\n" + b"%x\r\n" % len(two) + two
            + b"\r\n0\r\nX-Checksum: " + digest + b"\r\n\r\n",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for form in ("raw", "structured"):
                with self.subTest(form=form):
                    sections = [
                        {"http": {"raw": m.hex()} if form == "raw"
                         else {k: v for k, v in http.to_spec(http.decode(m)).items()
                               if k != "raw"}}
                        for m in messages
                    ]
                    src, out = Path(tmp, f"{form}.pcap"), Path(tmp, f"{form}-out.pcap")
                    Path(tmp, "m.json").write_text(json.dumps(sections))
                    _cli("stream", "--payload", "http", "--protocol-messages",
                         str(Path(tmp, "m.json")), "--requests", "2", "--mss", "200",
                         "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
                         "--seed", "1", "--pcap", str(src))
                    self.assertIn(login, src.read_bytes())
                    _cli("sanitise", str(src), "--payload", "--pcap", str(out))
                    wire = b"".join(bytes(p.payload or b"")
                                    for p in iter_packets(path=out, decode_app=False))
                    for body in self._BODIES:
                        for start in range(len(body) - 7):
                            self.assertNotIn(body[start:start + 8], wire, body)


class TestABodyThatSpansSegments(unittest.TestCase):
    """Framing is kept only within one TCP segment; nothing of the body is (#187).

    `sanitise` works packet by packet, and keeping a chunked body's framing
    across segments would mean reassembling each TCP direction, which is out
    of scope for packeteer.  A body that spans segments is zeroed whole,
    framing included: its shape is lost, and none of its content is kept.
    """

    def test_no_byte_of_a_spanning_body_survives(self) -> None:
        chunk = b"A" * 299 + b"Z"
        response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12c\r\n"
                    + chunk + b"\r\n12c\r\n" + chunk
                    + b"\r\n0\r\nX-Checksum: digest-of-it\r\n\r\n")
        with tempfile.TemporaryDirectory() as tmp:
            messages = Path(tmp, "m.json")
            messages.write_text(json.dumps([
                {"http": {"raw": b"GET / HTTP/1.1\r\n\r\n".hex()}},
                {"http": {"raw": response.hex()}},
            ]))
            src, out = Path(tmp, "span.pcap"), Path(tmp, "out.pcap")
            _cli("stream", "--payload", "http", "--protocol-messages", str(messages),
                 "--requests", "1", "--mss", "200", "--client-ip", "10.0.0.2",
                 "--server-ip", "10.0.0.1", "--seed", "1", "--pcap", str(src))
            _cli("sanitise", str(src), "--payload", "--no-scan-pii", "--pcap", str(out))

            def server(path: Path) -> list[bytes]:
                return [bytes(p.payload) for p in iter_packets(path=path, decode_app=False)
                        if p.payload and p.transport.src_port == 80]

            self.assertGreater(len(server(src)), 2, "the body must span segments")
            wire = b"".join(server(out))
            self.assertNotIn(b"AAAA", wire)
            self.assertNotIn(b"digest", wire)
            self.assertTrue(wire.startswith(b"HTTP/1.1 200 OK\r\n"))


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
