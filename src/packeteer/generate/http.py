"""HTTP/1.x message construction (RFC 7230).

This module provides dataclasses for HTTP request and response messages
and a wire-format encoder.  HTTP messages are carried over TCP; the
conventional ports are 80 (HTTP) and 8080 (alternative).

Only HTTP/1.0 and HTTP/1.1 are supported.  HTTP/2 binary framing is out
of scope.

The encoder adds a ``Content-Length`` header automatically when the body
is non-empty and the message does not already frame itself — that is, when
neither ``Content-Length`` nor ``Transfer-Encoding`` is present.  Header
names are matched case-insensitively, per RFC 7230 §3.2.

Supported usage::

    from packeteer.generate.http import (
        HTTPRequest, HTTPResponse, _build_http_message,
        HTTP_PORT, HTTP_ALT_PORT,
    )
    wire = _build_http_message(HTTPRequest(
        method="GET",
        path="/index.html",
        headers={"Host": "example.com"},
    ))
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Port constants ────────────────────────────────────────────────────────────

HTTP_PORT:     int = 80
HTTP_ALT_PORT: int = 8080

# ── Message dataclasses ───────────────────────────────────────────────────────


@dataclass
class HTTPRequest:
    """An HTTP/1.x request message.

    Attributes:
        method: HTTP method verb (e.g. ``"GET"``, ``"POST"``, ``"PUT"``).
        path: Request-target path including any query string
            (e.g. ``"/search?q=hello"``).
        version: HTTP version without the ``HTTP/`` prefix: ``"1.0"`` or
            ``"1.1"``.
        headers: Ordered mapping of header name to header value.  A value
            that is a list is one line per item, in order, under the same
            name — how ``Set-Cookie`` repeats (#181).
            ``Content-Length`` is added automatically by the encoder when
            the body is non-empty and neither ``Content-Length`` nor
            ``Transfer-Encoding`` is present (matched case-insensitively).
        body: Optional request body bytes (e.g. a POST body).
        raw: The message exactly as sent, when re-encoding the fields
            would not reproduce it: a repeated header, a header without the
            space after its colon, a status line with no reason phrase.
            Written out verbatim, so such a message round-trips; empty
            otherwise.  Same reasoning as
            :attr:`~packeteer.generate.dns.DNSMessage.raw`.

            It takes precedence over the fields, so **editing them has no
            effect while it is set** — clear it to hand-edit a captured
            message.  ``packeteer sanitise`` redacts a header inside it as
            well as in *headers*, keeping every other byte (#184), and drops
            it when the head cannot be read line by line, since a header
            redacted while still in *raw* would not be redacted at all.

    """

    method:  str = "GET"
    path:    str = "/"
    version: str = "1.1"
    headers: dict[str, str | list[str]] = field(default_factory=dict)
    body:    bytes = b""
    raw:     bytes = b""


@dataclass
class HTTPResponse:
    """An HTTP/1.x response message.

    Attributes:
        version: HTTP version without the ``HTTP/`` prefix: ``"1.0"`` or
            ``"1.1"``.
        status_code: Three-digit numeric status code (e.g. ``200``,
            ``404``).
        reason: Human-readable reason phrase (e.g. ``"OK"``,
            ``"Not Found"``).
        headers: Ordered mapping of header name to header value.  A value
            that is a list is one line per item, in order, under the same
            name — how ``Set-Cookie`` repeats (#181).
            ``Content-Length`` is added automatically by the encoder when
            the body is non-empty and neither ``Content-Length`` nor
            ``Transfer-Encoding`` is present (matched case-insensitively).
        body: Optional response body bytes.
        raw: The message exactly as sent, when re-encoding the fields
            would not reproduce it: a repeated header, a header without the
            space after its colon, a status line with no reason phrase.
            Written out verbatim, so such a message round-trips; empty
            otherwise.  Same reasoning as
            :attr:`~packeteer.generate.dns.DNSMessage.raw`.

            It takes precedence over the fields, so **editing them has no
            effect while it is set** — clear it to hand-edit a captured
            message.  ``packeteer sanitise`` redacts a header inside it as
            well as in *headers*, keeping every other byte (#184), and drops
            it when the head cannot be read line by line, since a header
            redacted while still in *raw* would not be redacted at all.

    """

    version:     str = "1.1"
    status_code: int = 200
    reason:      str = "OK"
    headers:     dict[str, str | list[str]] = field(default_factory=dict)
    body:        bytes = b""
    raw:         bytes = b""


# Type alias for the message union.
HTTPMessage = HTTPRequest | HTTPResponse


# ── Wire encoder ──────────────────────────────────────────────────────────────

def _build_http_message(msg: HTTPMessage) -> bytes:  # type: ignore[valid-type]
    r"""Encode an :class:`HTTPRequest` or :class:`HTTPResponse` to wire bytes.

    ``Content-Length`` is added automatically when the body is non-empty
    and the message does not already frame itself.  A message carrying
    ``Transfer-Encoding`` frames itself by chunk sizes, so no
    ``Content-Length`` is added to it — RFC 7230 §3.3.3 requires a recipient
    to ignore ``Content-Length`` when both are present, and the two together
    are the classic request-smuggling construction.  Header names are matched
    case-insensitively, per RFC 7230 §3.2.

    The body is written out verbatim; the encoder never chunks it.  A caller
    who sets ``Transfer-Encoding: chunked`` is responsible for supplying an
    already-chunked body.

    A message carrying :attr:`~HTTPRequest.raw` is returned as those bytes,
    and none of the above applies.

    Args:
        msg: The HTTP message to encode.

    Returns:
        Wire-format bytes suitable for use as a TCP payload.

    Example:
        ::

            from packeteer.generate.http import (
                HTTPRequest, HTTPResponse, _build_http_message,
            )
            # GET request
            req = _build_http_message(HTTPRequest(
                method="GET",
                path="/index.html",
                headers={"Host": "example.com", "Connection": "close"},
            ))
            # 200 response with HTML body
            body = b"<html><body>Hello</body></html>"
            rsp = _build_http_message(HTTPResponse(
                status_code=200,
                reason="OK",
                headers={"Content-Type": "text/html"},
                body=body,
            ))

    """
    if msg.raw:
        # Exact bytes win over the fields — see `HTTPRequest.raw`.
        return msg.raw
    headers = dict(msg.headers)
    present = {name.lower() for name in headers}
    if msg.body and "content-length" not in present and "transfer-encoding" not in present:
        headers["Content-Length"] = str(len(msg.body))

    if isinstance(msg, HTTPRequest):
        start_line = f"{msg.method} {msg.path} HTTP/{msg.version}\r\n"
    else:
        start_line = f"HTTP/{msg.version} {msg.status_code} {msg.reason}\r\n"

    header_block = "".join(
        f"{name}: {line}\r\n"
        for name, value in headers.items()
        for line in (value if isinstance(value, list) else [value])
    )
    head = (start_line + header_block + "\r\n").encode("latin-1")
    return head + msg.body


def encode_http_message(msg: HTTPMessage) -> bytes:  # type: ignore[valid-type]
    """Encode an :class:`HTTPRequest` or :class:`HTTPResponse` to wire bytes.

    ``Content-Length`` is added automatically when the body is non-empty and
    the message does not already frame itself with ``Content-Length`` or
    ``Transfer-Encoding`` (matched case-insensitively).  The body is written
    out verbatim; the encoder never chunks it.

    Args:
        msg: The HTTP message to encode.

    Returns:
        Wire-format bytes suitable for use as a TCP payload.

    """
    return _build_http_message(msg)
