r"""HTTP/1.x message parser (RFC 7230).

Decodes HTTP request and response messages from raw TCP payload bytes.
Both CRLF (``\r\n``) and bare-LF (``\n``) line endings are accepted.

Only HTTP/1.0 and HTTP/1.1 are supported.  Chunked transfer encoding is
not decoded — the body bytes are returned verbatim in that case.
"""
from __future__ import annotations

import contextlib

from packeteer.generate.http import HTTPMessage, HTTPRequest, HTTPResponse

_CRLF2 = b"\r\n\r\n"
_LF2   = b"\n\n"


def parse_http(data: bytes) -> HTTPMessage:  # type: ignore[valid-type]
    """Parse an HTTP/1.x message from raw TCP payload bytes.

    Args:
        data: Raw bytes from a TCP segment containing an HTTP message.

    Returns:
        An :class:`~packeteer.generate.http.HTTPRequest` or
        :class:`~packeteer.generate.http.HTTPResponse`.

    Raises:
        ValueError: If the message has no header/body separator, the
            start line is missing, or the start line is not a valid HTTP
            request or response line.

    Example:
        ::

            from packeteer.parse.http import parse_http
            from packeteer.generate.http import HTTPRequest, _build_http_message
            msg = parse_http(_build_http_message(HTTPRequest(
                headers={"Host": "example.com"},
            )))
            print(msg.method, msg.path)   # GET /

    """
    sep = _CRLF2 if _CRLF2 in data else _LF2
    if sep not in data:
        raise ValueError("HTTP message has no header/body separator")

    head_bytes, body = data.split(sep, 1)
    lines = head_bytes.decode("latin-1").splitlines()
    if not lines:
        raise ValueError("HTTP message has no start line")

    start = lines[0]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()

    # Trim body to Content-Length when present.
    cl = headers.get("Content-Length") or headers.get("content-length")
    if cl is not None:
        with contextlib.suppress(ValueError):
            body = body[:int(cl)]

    # Response: first token starts with "HTTP/"
    if start.upper().startswith("HTTP/"):
        parts = start.split(None, 2)
        if len(parts) < 2:
            raise ValueError(f"Invalid HTTP response line: {start!r}")
        version = parts[0][5:]  # strip "HTTP/"
        try:
            status_code = int(parts[1])
        except ValueError as exc:
            raise ValueError(f"Invalid HTTP status code: {parts[1]!r}") from exc
        reason = parts[2] if len(parts) > 2 else ""
        return HTTPResponse(
            version=version, status_code=status_code, reason=reason,
            headers=headers, body=body,
        )

    # Request: METHOD SP path SP HTTP/version
    parts = start.split(None, 2)
    if len(parts) < 3:
        raise ValueError(f"Invalid HTTP request line: {start!r}")
    method, path, http_ver = parts
    if not http_ver.upper().startswith("HTTP/"):
        raise ValueError(f"Invalid HTTP version token: {http_ver!r}")
    return HTTPRequest(
        method=method, path=path, version=http_ver[5:],
        headers=headers, body=body,
    )
