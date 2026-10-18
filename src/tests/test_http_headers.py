"""An HTTP message's header lines, in order, where a name may repeat (#172).

`HTTPRequest.headers` and `HTTPResponse.headers` were a `dict`, and an
`http` section's `headers` an object, so `A: 1`, `B: 2`, `A: 3` could not
be written without `raw` and came out of `parse` as `{"A": "1, 3", "B":
"2"}`.  They are `HTTPHeaders` now, and a section writes `[name, value]`
pairs; the object form is still read.
"""
from __future__ import annotations

import unittest

from packeteer.app import http
from packeteer.generate import HTTPHeaders, HTTPRequest, HTTPResponse
from packeteer.generate.http import encode_http_message
from packeteer.sanitise import SanitiseOptions, _redaction


class TestHTTPHeaders(unittest.TestCase):

    def setUp(self) -> None:
        self.h = HTTPHeaders([("Transfer-Encoding", "gzip"), ("Host", "a"),
                              ("transfer-encoding", "chunked")])

    def test_the_lines_in_order(self) -> None:
        self.assertEqual(self.h.items(), [("Transfer-Encoding", "gzip"), ("Host", "a"),
                                          ("transfer-encoding", "chunked")])

    def test_a_lookup_is_case_insensitive_and_joins(self) -> None:
        self.assertEqual(self.h["TRANSFER-ENCODING"], "gzip, chunked")
        self.assertEqual(self.h.get_all("transfer-encoding"), ["gzip", "chunked"])
        self.assertEqual(self.h.get("missing", "x"), "x")
        self.assertIn("host", self.h)
        with self.assertRaises(KeyError):
            self.h["missing"]

    def test_set_cookie_gives_its_first_line(self) -> None:
        h = HTTPHeaders({"Set-Cookie": ["a=1; Expires=Wed, 21 Oct 2026", "b=2"]})
        self.assertEqual(h["Set-Cookie"], "a=1; Expires=Wed, 21 Oct 2026")
        self.assertEqual(len(h.get_all("set-cookie")), 2)

    def test_names_once_as_first_spelt(self) -> None:
        self.assertEqual(list(self.h), ["Transfer-Encoding", "Host"])
        self.assertEqual(len(self.h), 2)
        self.assertEqual(dict(self.h), {"Transfer-Encoding": "gzip, chunked", "Host": "a"})

    def test_setting_replaces_every_line_where_the_first_was(self) -> None:
        self.h["TRANSFER-ENCODING"] = "identity"
        self.assertEqual(self.h.items(), [("TRANSFER-ENCODING", "identity"), ("Host", "a")])
        self.h["New"] = ["x", "y"]
        self.assertEqual(self.h.items()[-2:], [("New", "x"), ("New", "y")])

    def test_add_and_delete(self) -> None:
        self.h.add("Host", "b")
        self.assertEqual(self.h.get_all("host"), ["a", "b"])
        del self.h["HOST"]
        self.assertNotIn("Host", self.h)
        with self.assertRaises(KeyError):
            del self.h["Host"]

    def test_built_from_a_mapping_pairs_or_another(self) -> None:
        pairs = [("Host", "a"), ("Set-Cookie", "x"), ("Set-Cookie", "y")]
        self.assertEqual(HTTPHeaders({"Host": "a", "Set-Cookie": ["x", "y"]}), pairs)
        self.assertEqual(HTTPHeaders(HTTPHeaders(pairs)).items(), pairs)
        self.assertEqual(HTTPHeaders(pairs), {"Host": "a", "Set-Cookie": ["x", "y"]})
        self.assertNotEqual(HTTPHeaders(pairs), HTTPHeaders(reversed(pairs)))

    def test_a_value_is_a_string(self) -> None:
        with self.assertRaises(TypeError):
            HTTPHeaders([("Host", 1)])
        with self.assertRaises(TypeError):
            self.h["X"] = [1]


class TestTheMessageClasses(unittest.TestCase):

    def test_a_dict_is_still_accepted(self) -> None:
        req = HTTPRequest(headers={"Host": "a"})
        self.assertIsInstance(req.headers, HTTPHeaders)
        self.assertEqual(req.headers["Host"], "a")

    def test_the_encoder_writes_every_line_in_order(self) -> None:
        rsp = HTTPResponse(headers=[("A", "1"), ("B", "2"), ("A", "3")], body=b"hi")
        self.assertEqual(encode_http_message(rsp),
                         b"HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\nA: 3\r\n"
                         b"Content-Length: 2\r\n\r\nhi")

    def test_a_framing_header_in_any_case_suppresses_content_length(self) -> None:
        req = HTTPRequest(headers=[("transfer-ENCODING", "chunked")], body=b"0\r\n\r\n")
        self.assertNotIn(b"Content-Length", encode_http_message(req))


class TestTheSection(unittest.TestCase):

    def test_pairs_are_read_in_order(self) -> None:
        msg = http.from_spec({"headers": [["A", "1"], ["B", "2"], ["A", 3]]})
        self.assertEqual(msg.headers.items(), [("A", "1"), ("B", "2"), ("A", "3")])

    def test_the_object_form_is_still_read(self) -> None:
        msg = http.from_spec({"headers": {"Host": "a", "Set-Cookie": ["x", "y"]}})
        self.assertEqual(msg.headers.items(),
                         [("Host", "a"), ("Set-Cookie", "x"), ("Set-Cookie", "y")])

    def test_to_spec_writes_pairs(self) -> None:
        section = http.to_spec(HTTPRequest(headers={"Host": "a"}))
        self.assertEqual(section["headers"], [["Host", "a"]])

    def test_a_chunked_body_is_recognised_in_either_shape(self) -> None:
        from packeteer.app.http import _is_chunked

        for headers in ({"Transfer-Encoding": ["gzip", "chunked"]},
                        [["Transfer-Encoding", "gzip"], ["transfer-encoding", "chunked"]],
                        HTTPHeaders([("Transfer-Encoding", "gzip, chunked")])):
            with self.subTest(headers=headers):
                self.assertTrue(_is_chunked(headers))
        self.assertFalse(_is_chunked([["Transfer-Encoding", "chunked"],
                                      ["Transfer-Encoding", "gzip"]]))


class TestSanitise(unittest.TestCase):

    def test_each_sensitive_line_is_redacted_where_it_stands(self) -> None:
        section = {"type": "response", "headers": [
            ["Set-Cookie", "a=1"], ["Content-Type", "text/plain"], ["set-cookie", "bb=22"]]}
        http.sanitise(section, None, SanitiseOptions(http_headers=True))
        self.assertEqual(section["headers"], [
            ["Set-Cookie", _redaction(3)], ["Content-Type", "text/plain"],
            ["set-cookie", _redaction(5)]])

    def test_the_fallback_no_longer_regroups(self) -> None:
        """#184's fallback rebuilt from fields, which grouped repeated names.

        A folded continuation line makes the head unreadable line by line, so
        `raw` is dropped; the lines rebuilt from the pairs keep their order.
        """
        wire = (b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nX-Folded: one\r\n two\r\n"
                b"Content-Type: text/plain\r\nSet-Cookie: b=2\r\n\r\n")
        section = http.to_spec(http.decode(wire))
        self.assertIn("raw", section)
        http.sanitise(section, None, SanitiseOptions(http_headers=True))
        self.assertNotIn("raw", section)
        names = [name for name, _ in section["headers"]]
        self.assertEqual(names, ["Set-Cookie", "X-Folded", "Content-Type", "Set-Cookie"])


if __name__ == "__main__":
    unittest.main()
