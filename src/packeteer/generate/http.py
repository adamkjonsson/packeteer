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

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field

# ── Port constants ────────────────────────────────────────────────────────────

HTTP_PORT:     int = 80
HTTP_ALT_PORT: int = 8080

# ── Header lines ──────────────────────────────────────────────────────────────

#: The one header whose lines cannot be combined into one, so a lookup by
#: name gives its first line rather than every line joined (RFC 6265 §3).
_UNCOMBINED = "set-cookie"


class HTTPHeaders:
    """A message's header lines, in order, where a name may repeat (#172).

    An HTTP head is a list of lines, not a mapping: ``Transfer-Encoding: gzip``
    then ``Transfer-Encoding: chunked`` is one list split over two lines
    (RFC 7230 §3.2.2), ``Set-Cookie`` repeats and cannot be folded, and the
    order across names is part of what was sent.  This keeps every line, in
    order, with its name as spelt, and offers lookups by name on top,
    case-insensitively, as RFC 7230 §3.2 reads names.

    It is built from another one, from a mapping, or from ``(name, value)``
    pairs.  A mapping's value may be a list, one line per item, which is how
    ``headers={"Set-Cookie": ["a=1", "b=2"]}`` has always written two lines.

    - :meth:`items` gives every line as a ``(name, value)`` pair, in order.
    - ``headers[name]`` and :meth:`get` give one value: a repeated name's
      values joined with ``", "``, as RFC 7230 §3.2.2 allows, except
      ``Set-Cookie``, which gives its first.
    - :meth:`get_all` gives every value of a name, in order.
    - ``headers[name] = value`` replaces every line of that name with
      *value*, where its first line was (or at the end), and :meth:`add`
      appends a line.
    - Iterating gives each name once, as first spelt, so ``dict(headers)``
      is the old one-value-per-name view.

    It compares equal to another one with the same lines, and to anything
    it can be built from that gives those lines.

    Example::

        from packeteer.generate import HTTPHeaders

        h = HTTPHeaders([("Transfer-Encoding", "gzip"), ("Host", "a"),
                         ("Transfer-Encoding", "chunked")])
        h["transfer-encoding"]          # 'gzip, chunked'
        h.get_all("Transfer-Encoding")  # ['gzip', 'chunked']
        h.items()                       # all three lines, in order

    """

    __slots__ = ("_lines",)

    def __init__(self, source: HeadersLike = None) -> None:
        self._lines: list[tuple[str, str]] = []
        if source is None:
            return
        if isinstance(source, HTTPHeaders):
            self._lines = source.items()
        elif isinstance(source, Mapping):
            for name, value in source.items():
                for line in (value if isinstance(value, list) else [value]):
                    self.add(name, line)
        else:
            for pair in source:
                name, value = pair
                self.add(name, value)

    def add(self, name: str, value: str) -> None:
        """Append one line, after every other.

        Raises:
            TypeError: If *name* or *value* is not a string.

        """
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError(
                f"a header line is a name and a value, both strings; got "
                f"{type(name).__name__} and {type(value).__name__}"
            )
        self._lines.append((name, value))

    def items(self) -> list[tuple[str, str]]:
        """Return every line as a ``(name, value)`` pair, in order."""
        return list(self._lines)

    def get_all(self, name: str) -> list[str]:
        """Return every value of *name*, matched case-insensitively, in order."""
        key = name.lower()
        return [value for line, value in self._lines if line.lower() == key]

    def get(self, name: str, default: str | None = None) -> str | None:
        """Return ``headers[name]``, or *default* when no line has that name."""
        values = self.get_all(name)
        if not values:
            return default
        return values[0] if name.lower() == _UNCOMBINED else ", ".join(values)

    def keys(self) -> list[str]:
        """Return each name once, as first spelt, in order of its first line."""
        seen: dict[str, str] = {}
        for name, _ in self._lines:
            seen.setdefault(name.lower(), name)
        return list(seen.values())

    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __setitem__(self, name: str, value: str | list[str]) -> None:
        key = name.lower()
        new = [(name, line) for line in (value if isinstance(value, list) else [value])]
        for _, line in new:
            if not isinstance(line, str):
                raise TypeError(f"header {name!r}: a value is a string, not "
                                f"{type(line).__name__}")
        at = next((i for i, (n, _) in enumerate(self._lines) if n.lower() == key),
                  len(self._lines))
        rest = [line for line in self._lines if line[0].lower() != key]
        self._lines = rest[:at] + new + rest[at:]

    def __delitem__(self, name: str) -> None:
        key = name.lower()
        if not any(n.lower() == key for n, _ in self._lines):
            raise KeyError(name)
        self._lines = [line for line in self._lines if line[0].lower() != key]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and bool(self.get_all(name))

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self.keys())

    def __bool__(self) -> bool:
        return bool(self._lines)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, HTTPHeaders):
            return self._lines == other.items()
        if isinstance(other, (Mapping, list, tuple)):
            try:
                return self._lines == HTTPHeaders(other).items()
            except (TypeError, ValueError):
                return False
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"HTTPHeaders({self._lines!r})"


#: What :class:`HTTPHeaders` is built from: another one, a mapping whose
#: value is one line or a list of lines, or the lines as ``(name, value)``
#: pairs.
HeadersLike = (
    HTTPHeaders | Mapping[str, str | list[str]] | Iterable[tuple[str, str]] | None
)


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
        headers: The header lines, in order, as :class:`HTTPHeaders`: a name
            may repeat, and its lines keep their place among the others
            (#172).  A mapping or ``(name, value)`` pairs given here are
            converted, so ``headers={"Host": "example.com"}`` still works,
            and a mapping's list value is one line per item.
            ``Content-Length`` is added automatically by the encoder when
            the body is non-empty and neither ``Content-Length`` nor
            ``Transfer-Encoding`` is present (matched case-insensitively).
        body: Optional request body bytes (e.g. a POST body).
        raw: The message exactly as sent, when re-encoding the fields
            would not reproduce it: a header without the space after its
            colon, a folded continuation line, a status line with no reason
            phrase.
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
    headers: HTTPHeaders = field(default_factory=HTTPHeaders)
    body:    bytes = b""
    raw:     bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.headers, HTTPHeaders):
            self.headers = HTTPHeaders(self.headers)


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
        headers: The header lines, in order, as :class:`HTTPHeaders`: a name
            may repeat, and its lines keep their place among the others
            (#172).  A mapping or ``(name, value)`` pairs given here are
            converted, so ``headers={"Host": "example.com"}`` still works,
            and a mapping's list value is one line per item.
            ``Content-Length`` is added automatically by the encoder when
            the body is non-empty and neither ``Content-Length`` nor
            ``Transfer-Encoding`` is present (matched case-insensitively).
        body: Optional response body bytes.
        raw: The message exactly as sent, when re-encoding the fields
            would not reproduce it: a header without the space after its
            colon, a folded continuation line, a status line with no reason
            phrase.
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
    headers:     HTTPHeaders = field(default_factory=HTTPHeaders)
    body:        bytes = b""
    raw:         bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.headers, HTTPHeaders):
            self.headers = HTTPHeaders(self.headers)


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
    headers = HTTPHeaders(msg.headers)
    if msg.body and "content-length" not in headers and "transfer-encoding" not in headers:
        headers.add("Content-Length", str(len(msg.body)))

    if isinstance(msg, HTTPRequest):
        start_line = f"{msg.method} {msg.path} HTTP/{msg.version}\r\n"
    else:
        start_line = f"HTTP/{msg.version} {msg.status_code} {msg.reason}\r\n"

    header_block = "".join(f"{name}: {value}\r\n" for name, value in headers.items())
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
