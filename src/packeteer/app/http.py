"""HTTP/1.x as an :class:`~packeteer.protocols.AppProtocol`.

:func:`from_spec` moved here from ``packeteer.__main__``.
"""
from __future__ import annotations

import json
from typing import Any

from packeteer.generate.http import (
    HTTP_ALT_PORT,
    HTTP_PORT,
    HTTPRequest,
    HTTPResponse,
    _build_http_message,
)
from packeteer.protocols import (
    AppProtocol,
    check_section,
    section_bytes,
    section_raw,
)


def encode(msg: object, transport: str = "tcp") -> bytes:
    """Encode an HTTP request or response to wire bytes.

    Args:
        msg: The :class:`~packeteer.generate.http.HTTPRequest` or
            :class:`~packeteer.generate.http.HTTPResponse` to encode.
        transport: Unused — HTTP/1.x runs over TCP only.

    Returns:
        The encoded message.

    """
    assert isinstance(msg, (HTTPRequest, HTTPResponse))
    return _build_http_message(msg)


def decode(payload: bytes, transport: str = "tcp") -> HTTPRequest | HTTPResponse:
    """Decode wire bytes into an HTTP request or response.

    Args:
        payload: TCP payload bytes holding one whole message.
        transport: Unused — HTTP/1.x runs over TCP only.

    Returns:
        The decoded message.

    Raises:
        ValueError: If *payload* is not a well-formed HTTP/1.x message.
        UnicodeDecodeError: If the start line or headers are not text.

    """
    from packeteer.parse.http import parse_http

    return parse_http(payload)


def to_spec(msg: object) -> dict[str, Any]:
    """Return the ``http`` packet-spec section for *msg*.

    Args:
        msg: The HTTP message to serialise.

    Returns:
        The section, as it appears under ``"http"`` in a packet spec.

    """
    from packeteer.parse.to_config import _apply_http

    config: dict[str, Any] = {}
    _apply_http(config, msg)
    return config["http"]


#: Every key ``from_spec`` reads.  A non-empty section with none of them is
#: not a section — see :func:`packeteer.protocols.check_section`.
_SECTION_KEYS: frozenset[str] = frozenset({
    "type", "method", "path", "version", "status_code", "reason", "headers",
    "body", "raw",
})


def from_spec(section: dict[str, Any]) -> HTTPRequest | HTTPResponse:
    """Build an HTTP message from a spec section.

    A ``raw`` key, in hex, is the message exactly as it is to be sent, and
    **wins over the other fields** when it is encoded — see
    :attr:`~packeteer.generate.http.HTTPRequest.raw` (#178).  Its fields are
    read from the bytes, so a label or a status is the message's own, and
    ``type`` beside it says which it is, or else the bytes do: a start line
    beginning ``HTTP/`` is a response.  Bytes that do not parse as HTTP are
    still sent as given, as the type their start line names.

    Args:
        section: The object found under ``"http"`` in a packet spec.
            ``type`` is ``"request"`` or ``"response"``.  Left out, it is a
            request, unless ``raw``'s start line says response.

    Returns:
        The message it describes.

    Raises:
        ValueError: If *section* is non-empty and none of its keys is one an
            HTTP section has — most often a whole packet spec passed where
            its ``"http"`` object was meant — or if ``type`` is anything but
            ``"request"`` or ``"response"``.

    """
    check_section("http", section, _SECTION_KEYS)
    kind = section.get("type")
    if kind is not None and kind not in ("request", "response"):
        # Read as a request, a misspelt `response` sent a response's bytes
        # from the client, and with `raw` it overrides the start line (#180).
        raise ValueError(
            f"http: type must be 'request' or 'response', not {kind!r}"
        )
    raw = section_raw("http", section)
    if raw is not None:
        return _from_raw(raw, kind)
    headers = _headers(section.get("headers", {}))
    body = section_bytes("http", section, "body")
    if section.get("type") == "response":
        return HTTPResponse(
            version=section.get("version", "1.1"),
            status_code=section.get("status_code", 200),
            reason=section.get("reason", "OK"),
            headers=headers,
            body=body,
        )
    return HTTPRequest(
        method=section.get("method", "GET"),
        path=section.get("path", "/"),
        version=section.get("version", "1.1"),
        headers=headers,
        body=body,
    )


def _headers(value: Any) -> dict[str, str | list[str]]:
    """Return a section's headers, each value a string or a list of strings.

    An integer is taken as its digits, which is what it always meant.
    Anything else is refused naming the header, and the item in a list: it
    went on the wire as Python spells it — ``['a=1']``, ``True`` — which is
    bytes the section did not say (#182).
    """
    if not isinstance(value, dict):
        raise ValueError(
            f"http: headers must be an object, not {type(value).__name__}"
        )
    return {
        name: ([_header_line(name, item, index) for index, item in enumerate(line)]
               if isinstance(line, list) else _header_line(name, line, None))
        for name, line in value.items()
    }


def _header_line(name: str, value: Any, index: int | None) -> str:
    """Return one header line's value as text, or refuse it by name."""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    where = f"header {name!r}" if index is None else f"header {name!r} item {index}"
    raise ValueError(
        f"http: {where} must be a string, not {type(value).__name__}"
    )


def _from_raw(raw: bytes, kind: str | None) -> HTTPRequest | HTTPResponse:
    """Build the message *raw* is, carrying *raw* to be sent as it is."""
    from packeteer.parse.http import parse_http

    response = kind == "response" if kind is not None else raw[:5].upper() == b"HTTP/"
    wanted = HTTPResponse if response else HTTPRequest
    try:
        msg = parse_http(raw)
    except (ValueError, UnicodeDecodeError):
        msg = None
    if not isinstance(msg, wanted):
        # Deliberately malformed bytes, or a `type` that overrides what they
        # look like: the bytes still go as given, as the type asked for.
        msg = wanted()
    msg.raw = raw
    return msg


def sanitise(section: dict[str, Any], replacer: Any, options: Any) -> None:
    """Redact *section* in place.

    A redacted header is redacted **inside** ``raw`` too, which keeps it: the
    value of each sensitive header line becomes ``[redacted]``, and every
    other byte stays as captured — the order and repetition of headers, the
    spacing, the line endings, the body.  A sanitised capture stands in for
    a real one, and a decoder's tests are about exactly that shape (#184).

    When the head cannot be read line by line with certainty — a folded
    continuation line above all, which could carry the rest of a secret —
    ``raw`` is dropped instead, as DNS drops its own, and the message is
    rebuilt from the redacted fields: repeated headers grouped, and every one
    but ``Set-Cookie`` combined into one line.

    Args:
        section: An ``http`` packet-spec section.
        replacer: Unused — HTTP redaction needs no consistent replacement map.
        options: The :class:`~packeteer.sanitise.SanitiseOptions` in force.

    """
    from packeteer.sanitise import _sanitise_http

    before = json.dumps(section, sort_keys=True, default=str)
    _sanitise_http(section, options)
    if "raw" not in section or json.dumps(section, sort_keys=True, default=str) == before:
        return
    try:
        redacted = _redact_raw(section_bytes("http", section, "raw"))
    except ValueError:
        redacted = None
    if redacted is None:
        # `raw` wins on build, so leaving it would put every redacted value
        # straight back on the wire.
        del section["raw"]
    else:
        section["raw"] = redacted.hex()


def _redact_raw(raw: bytes) -> bytes | None:
    """Return *raw* with each sensitive header's value redacted, or ``None``.

    ``None`` means the head could not be read line by line with certainty,
    and the caller drops ``raw`` rather than risk a secret left in it: no
    header/body separator, a start line that does not parse, a line without
    a colon, or one beginning with whitespace — an obs-fold continuation,
    which a line-by-line rewrite would leave as it was.
    """
    from packeteer.parse.http import parse_http
    from packeteer.sanitise import _HTTP_REDACTED, _HTTP_SENSITIVE_HEADERS

    try:
        parse_http(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    # The separator `parse_http` splits on, so both read the same head.
    sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    head, rest = raw.split(sep, 1)
    lines = head.split(b"\n")
    out = [lines[0]]
    for line in lines[1:]:
        text, ending = (line[:-1], b"\r") if line.endswith(b"\r") else (line, b"")
        if not text or text[:1] in b" \t" or b":" not in text:
            return None
        name, value = text.split(b":", 1)
        if name.strip().decode("latin-1").lower() in _HTTP_SENSITIVE_HEADERS:
            spacing = value[:len(value) - len(value.lstrip(b" \t"))]
            text = name + b":" + spacing + _HTTP_REDACTED.encode()
        out.append(text + ending)
    return b"\n".join(out) + sep + rest


PROTOCOL = AppProtocol(
    name="http",
    over="tcp",
    ports=frozenset({HTTP_PORT, HTTP_ALT_PORT}),
    messages=(HTTPRequest, HTTPResponse),
    decode=decode,
    encode=encode,
    to_spec=to_spec,
    from_spec=from_spec,
    sanitise=sanitise,
)
