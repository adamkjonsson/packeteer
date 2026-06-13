"""HTTP/1.x message construction (RFC 7230).

This module provides dataclasses for HTTP request and response messages
and a wire-format encoder.  HTTP messages are carried over TCP; the
conventional ports are 80 (HTTP) and 8080 (alternative).

Only HTTP/1.0 and HTTP/1.1 are supported.  HTTP/2 binary framing is out
of scope.

The encoder adds a ``Content-Length`` header automatically when the body
is non-empty and the caller has not already set it.

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
        headers: Ordered mapping of header name to header value.
            ``Content-Length`` is added automatically by the encoder when
            the body is non-empty and this key is absent.
        body: Optional request body bytes (e.g. a POST body).

    """

    method:  str = "GET"
    path:    str = "/"
    version: str = "1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body:    bytes = b""


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
        headers: Ordered mapping of header name to header value.
            ``Content-Length`` is added automatically by the encoder when
            the body is non-empty and this key is absent.
        body: Optional response body bytes.

    """

    version:     str = "1.1"
    status_code: int = 200
    reason:      str = "OK"
    headers:     dict[str, str] = field(default_factory=dict)
    body:        bytes = b""


# Type alias for the message union.
HTTPMessage = HTTPRequest | HTTPResponse


# ── Wire encoder ──────────────────────────────────────────────────────────────

def _build_http_message(msg: HTTPMessage) -> bytes:  # type: ignore[valid-type]
    r"""Encode an :class:`HTTPRequest` or :class:`HTTPResponse` to wire bytes.

    ``Content-Length`` is added automatically when the body is non-empty
    and the caller has not already set it.

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
    headers = dict(msg.headers)
    if msg.body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(msg.body))

    if isinstance(msg, HTTPRequest):
        start_line = f"{msg.method} {msg.path} HTTP/{msg.version}\r\n"
    else:
        start_line = f"HTTP/{msg.version} {msg.status_code} {msg.reason}\r\n"

    header_block = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    head = (start_line + header_block + "\r\n").encode("latin-1")
    return head + msg.body


def encode_http_message(msg: HTTPMessage) -> bytes:  # type: ignore[valid-type]
    """Encode an :class:`HTTPRequest` or :class:`HTTPResponse` to wire bytes.

    ``Content-Length`` is added automatically when the body is non-empty and
    the caller has not already set it.

    Args:
        msg: The HTTP message to encode.

    Returns:
        Wire-format bytes suitable for use as a TCP payload.

    """
    return _build_http_message(msg)
