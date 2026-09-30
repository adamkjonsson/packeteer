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

    Drops ``raw`` if anything changed, as DNS does: it is written out in
    preference to the fields, so a header redacted while still in ``raw``
    would go back on the wire unredacted.

    Args:
        section: An ``http`` packet-spec section.
        replacer: Unused — HTTP redaction needs no consistent replacement map.
        options: The :class:`~packeteer.sanitise.SanitiseOptions` in force.

    """
    from packeteer.sanitise import _sanitise_http

    before = json.dumps(section, sort_keys=True, default=str)
    _sanitise_http(section, options)
    if "raw" in section and json.dumps(section, sort_keys=True, default=str) != before:
        # The rebuilt message loses what made it non-canonical — a repeated
        # header becomes one combined line — which is the right trade.
        del section["raw"]


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
