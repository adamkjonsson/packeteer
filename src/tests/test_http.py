"""Tests for HTTP encode/decode, sanitisation, builder, and CLI integration."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from typing import Any

from packeteer.generate import TCP_ACK, TCP_PSH
from packeteer.generate.http import (
    HTTP_ALT_PORT,
    HTTP_PORT,
    HTTPMessage,
    HTTPRequest,
    HTTPResponse,
    _build_http_message,
)
from packeteer.parse.http import parse_http

_HTML_BODY = b"<html><body>Hello</body></html>"


class TestHTTPEncode(unittest.TestCase):
    def test_get_request_wire(self):
        wire = _build_http_message(HTTPRequest(
            method="GET", path="/index.html",
            headers={"Host": "example.com"},
        ))
        assert wire.startswith(b"GET /index.html HTTP/1.1\r\n")
        assert b"Host: example.com\r\n" in wire
        assert wire.endswith(b"\r\n\r\n")

    def test_post_request_content_length_added(self):
        body = b"name=Alice"
        wire = _build_http_message(HTTPRequest(
            method="POST", path="/submit",
            headers={"Host": "example.com", "Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        ))
        assert b"Content-Length: 10\r\n" in wire
        assert wire.endswith(body)

    def test_content_length_not_duplicated(self):
        wire = _build_http_message(HTTPRequest(
            method="POST", path="/",
            headers={"Content-Length": "3"},
            body=b"abc",
        ))
        assert wire.count(b"Content-Length") == 1

    def test_response_wire(self):
        wire = _build_http_message(HTTPResponse(
            status_code=200, reason="OK",
            headers={"Content-Type": "text/html"},
            body=_HTML_BODY,
        ))
        assert wire.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"Content-Type: text/html\r\n" in wire
        assert b"Content-Length:" in wire
        assert wire.endswith(_HTML_BODY)

    def test_response_no_body_no_content_length(self):
        wire = _build_http_message(HTTPResponse(status_code=204, reason="No Content"))
        assert b"Content-Length" not in wire

    def test_empty_body_no_content_length(self):
        wire = _build_http_message(HTTPRequest())
        assert b"Content-Length" not in wire

    def test_custom_http_version(self):
        wire = _build_http_message(HTTPRequest(version="1.0"))
        assert b"HTTP/1.0" in wire

    def test_header_order_preserved(self):
        req = HTTPRequest(headers={"Host": "a", "Accept": "b", "Cookie": "c"})
        wire = _build_http_message(req)
        host_pos = wire.index(b"Host:")
        accept_pos = wire.index(b"Accept:")
        cookie_pos = wire.index(b"Cookie:")
        assert host_pos < accept_pos < cookie_pos


class TestHTTPDecodeRoundTrip(unittest.TestCase):
    def _rt_req(self, req: HTTPRequest) -> HTTPRequest:
        return parse_http(_build_http_message(req))  # type: ignore[return-value]

    def _rt_rsp(self, rsp: HTTPResponse) -> HTTPResponse:
        return parse_http(_build_http_message(rsp))  # type: ignore[return-value]

    def test_get_request_roundtrip(self):
        req = HTTPRequest(method="GET", path="/page", headers={"Host": "example.com"})
        rt = self._rt_req(req)
        assert isinstance(rt, HTTPRequest)
        assert rt.method == "GET"
        assert rt.path == "/page"
        assert rt.headers["Host"] == "example.com"
        assert rt.body == b""

    def test_post_request_with_body_roundtrip(self):
        body = b"hello=world"
        req = HTTPRequest(
            method="POST", path="/submit",
            headers={"Host": "h", "Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        rt = self._rt_req(req)
        assert rt.method == "POST"
        assert rt.body == body

    def test_response_200_roundtrip(self):
        rsp = HTTPResponse(
            status_code=200, reason="OK",
            headers={"Content-Type": "text/plain"},
            body=b"hello",
        )
        rt = self._rt_rsp(rsp)
        assert isinstance(rt, HTTPResponse)
        assert rt.status_code == 200
        assert rt.reason == "OK"
        assert rt.body == b"hello"

    def test_response_404_roundtrip(self):
        rsp = HTTPResponse(status_code=404, reason="Not Found")
        rt = self._rt_rsp(rsp)
        assert rt.status_code == 404
        assert rt.reason == "Not Found"

    def test_response_no_body_roundtrip(self):
        rsp = HTTPResponse(status_code=204, reason="No Content")
        rt = self._rt_rsp(rsp)
        assert rt.body == b""

    def test_multiple_headers_roundtrip(self):
        req = HTTPRequest(headers={
            "Host": "example.com",
            "Accept": "text/html",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
        })
        rt = self._rt_req(req)
        assert rt.headers["Accept"] == "text/html"
        assert rt.headers["Connection"] == "keep-alive"

    def test_binary_body_roundtrip(self):
        body = bytes(range(256))
        rsp = HTTPResponse(body=body)
        rt = self._rt_rsp(rsp)
        assert rt.body == body

    def test_http10_version_roundtrip(self):
        req = HTTPRequest(version="1.0", headers={"Host": "h"})
        rt = self._rt_req(req)
        assert rt.version == "1.0"

    def test_body_trimmed_to_content_length(self):
        # Manually craft a wire message with trailing garbage past Content-Length
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloGARBAGE"
        rt = parse_http(wire)
        assert rt.body == b"hello"


class TestHTTPParserEdgeCases(unittest.TestCase):
    def test_no_separator_raises(self):
        with self.assertRaises(ValueError):
            parse_http(b"GET / HTTP/1.1\r\nHost: example.com\r\n")

    def test_invalid_request_line_raises(self):
        with self.assertRaises(ValueError):
            parse_http(b"NOTHTTP\r\n\r\n")

    def test_invalid_status_code_raises(self):
        with self.assertRaises(ValueError):
            parse_http(b"HTTP/1.1 OK\r\n\r\n")

    def test_bare_lf_accepted(self):
        wire = b"GET / HTTP/1.1\nHost: example.com\n\n"
        rt = parse_http(wire)
        assert isinstance(rt, HTTPRequest)

    def test_response_without_reason(self):
        wire = b"HTTP/1.1 200\r\n\r\n"
        rt = parse_http(wire)
        assert isinstance(rt, HTTPResponse)
        assert rt.status_code == 200
        assert rt.reason == ""


class TestBuilderHTTPMethod(unittest.TestCase):
    def test_builder_get_request(self):
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet

        req = HTTPRequest(
            method="GET", path="/",
            headers={"Host": "example.com"},
        )
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(src_port=54321, dst_port=HTTP_PORT, flags=TCP_PSH | TCP_ACK)
            .http(req)
            .build()
        )
        pkt = parse_packet(raw)
        assert pkt.http is not None
        assert isinstance(pkt.http, HTTPRequest)
        assert pkt.http.method == "GET"
        assert pkt.http.path == "/"

    def test_builder_response(self):
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet

        rsp = HTTPResponse(
            status_code=200, reason="OK",
            headers={"Content-Type": "text/html"},
            body=_HTML_BODY,
        )
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.2", dst="10.0.0.1")
            .tcp(src_port=HTTP_PORT, dst_port=54321, flags=TCP_PSH | TCP_ACK)
            .http(rsp)
            .build()
        )
        pkt = parse_packet(raw)
        assert pkt.http is not None
        assert isinstance(pkt.http, HTTPResponse)
        assert pkt.http.status_code == 200
        assert pkt.http.body == _HTML_BODY

    def test_builder_alt_port(self):
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet

        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(src_port=54321, dst_port=HTTP_ALT_PORT, flags=TCP_PSH | TCP_ACK)
            .http(HTTPRequest(headers={"Host": "example.com"}))
            .build()
        )
        pkt = parse_packet(raw)
        assert pkt.http is not None


class TestParsePacketHTTPDispatch(unittest.TestCase):
    def _make_raw(
        self, dst_port: int, msg: HTTPMessage | None = None, use_udp: bool = False,
    ) -> bytes:
        from packeteer.generate import PacketBuilder
        if msg is None:
            msg = HTTPRequest(headers={"Host": "h"})
        b = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
        )
        if use_udp:
            b = b.udp(src_port=54321, dst_port=dst_port)
            return b.payload(data=_build_http_message(msg)).build()
        b = b.tcp(src_port=54321, dst_port=dst_port, flags=TCP_PSH | TCP_ACK)
        return b.http(msg).build()

    def test_dispatch_on_port_80(self):
        from packeteer.parse import parse_packet
        pkt = parse_packet(self._make_raw(HTTP_PORT))
        assert pkt.http is not None

    def test_dispatch_on_port_8080(self):
        from packeteer.parse import parse_packet
        pkt = parse_packet(self._make_raw(HTTP_ALT_PORT))
        assert pkt.http is not None

    def test_dispatch_on_src_port_80(self):
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.2", dst="10.0.0.1")
            .tcp(src_port=HTTP_PORT, dst_port=54321, flags=TCP_PSH | TCP_ACK)
            .http(HTTPResponse(status_code=200, reason="OK"))
            .build()
        )
        pkt = parse_packet(raw)
        assert pkt.http is not None

    def test_no_dispatch_on_other_port(self):
        from packeteer.parse import parse_packet
        pkt = parse_packet(self._make_raw(9999))
        assert pkt.http is None
        assert pkt.payload != b""

    def test_http_not_parsed_over_udp(self):
        from packeteer.parse import parse_packet
        pkt = parse_packet(self._make_raw(HTTP_PORT, use_udp=True))
        assert pkt.http is None


class TestToConfigHTTP(unittest.TestCase):
    def _config(self, msg: HTTPMessage) -> dict[str, Any]:
        from packeteer.parse.to_config import update_config
        cfg: dict = {}
        update_config(cfg, msg)
        return cfg["http"]

    def test_request_fields(self):
        req = HTTPRequest(
            method="POST", path="/api",
            headers={"Host": "example.com", "Content-Type": "application/json"},
            body=b'{"k":"v"}',
        )
        h = self._config(req)
        assert h["type"] == "request"
        assert h["method"] == "POST"
        assert h["path"] == "/api"
        assert h["version"] == "1.1"
        assert h["headers"]["Host"] == "example.com"
        assert h["body"] == b'{"k":"v"}'.hex()

    def test_response_fields(self):
        rsp = HTTPResponse(
            status_code=404, reason="Not Found",
            headers={"Content-Type": "text/plain"},
            body=b"nope",
        )
        h = self._config(rsp)
        assert h["type"] == "response"
        assert h["status_code"] == 404
        assert h["reason"] == "Not Found"
        assert h["body"] == b"nope".hex()

    def test_empty_body_serialised_as_empty_hex(self):
        h = self._config(HTTPRequest())
        assert h["body"] == ""

    def test_headers_dict_is_copy(self):
        req = HTTPRequest(headers={"Host": "h"})
        h = self._config(req)
        h["headers"]["Host"] = "mutated"
        assert req.headers["Host"] == "h"


class TestSanitiseHTTP(unittest.TestCase):
    def _spec(self, msg: HTTPMessage) -> dict[str, Any]:
        from packeteer.parse.to_config import update_config
        cfg: dict = {}
        update_config(cfg, msg)
        return {"packets": [cfg]}

    def test_host_redacted(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPRequest(headers={"Host": "secret.example.com"}))
        clean = sanitise(spec, SanitiseOptions(http_headers=True))
        assert clean["packets"][0]["http"]["headers"]["Host"] == "[redacted]"

    def test_cookie_redacted(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPRequest(headers={"Cookie": "session=abc123"}))
        clean = sanitise(spec, SanitiseOptions(http_headers=True))
        assert clean["packets"][0]["http"]["headers"]["Cookie"] == "[redacted]"

    def test_set_cookie_redacted(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPResponse(headers={"Set-Cookie": "token=xyz; Path=/"}))
        clean = sanitise(spec, SanitiseOptions(http_headers=True))
        assert clean["packets"][0]["http"]["headers"]["Set-Cookie"] == "[redacted]"

    def test_authorization_redacted(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPRequest(headers={"Authorization": "Bearer tok"}))
        clean = sanitise(spec, SanitiseOptions(http_headers=True))
        assert clean["packets"][0]["http"]["headers"]["Authorization"] == "[redacted]"

    def test_non_sensitive_header_kept(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPRequest(headers={
            "Host": "secret.com", "Content-Type": "text/html",
        }))
        clean = sanitise(spec, SanitiseOptions(http_headers=True))
        h = clean["packets"][0]["http"]["headers"]
        assert h["Content-Type"] == "text/html"
        assert h["Host"] == "[redacted]"

    def test_http_headers_false_keeps_headers(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPRequest(headers={"Host": "secret.com", "Cookie": "s=1"}))
        clean = sanitise(spec, SanitiseOptions(http_headers=False))
        h = clean["packets"][0]["http"]["headers"]
        assert h["Host"] == "secret.com"
        assert h["Cookie"] == "s=1"

    def test_original_not_mutated(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPRequest(headers={"Host": "secret.com"}))
        sanitise(spec, SanitiseOptions(http_headers=True))
        assert spec["packets"][0]["http"]["headers"]["Host"] == "secret.com"

    def test_location_redacted(self):
        from packeteer.sanitise import SanitiseOptions, sanitise
        spec = self._spec(HTTPResponse(
            status_code=302, reason="Found",
            headers={"Location": "https://secret.example.com/"},
        ))
        clean = sanitise(spec, SanitiseOptions(http_headers=True))
        assert clean["packets"][0]["http"]["headers"]["Location"] == "[redacted]"


class TestCLIHTTPHeaders(unittest.TestCase):
    def test_http_headers_flag_redacts(self):
        import sys

        from packeteer.__main__ import main
        spec = {
            "metadata": {"nanoseconds": False},
            "packets": [{
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp"},
                "transport": {"src_port": 54321, "dst_port": 80},
                "http": {
                    "type": "request",
                    "method": "GET",
                    "path": "/",
                    "version": "1.1",
                    "headers": {"Host": "secret.example.com"},
                    "body": "",
                },
            }],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False,
        ) as f:
            json.dump(spec, f)
            fname = f.name
        out_file = fname + ".out.json"
        try:
            sys.argv = ["packeteer", "sanitise", fname,
                        "--http-headers", "--output", out_file]
            main()
            with open(out_file) as f:
                result = json.load(f)
            host = result["packets"][0]["http"]["headers"]["Host"]
            assert host == "[redacted]", host
        finally:
            os.unlink(fname)
            if os.path.exists(out_file):
                os.unlink(out_file)


if __name__ == "__main__":
    unittest.main()
