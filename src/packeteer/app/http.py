"""HTTP/1.x as an :class:`~packeteer.protocols.AppProtocol`.

:func:`from_spec` moved here from ``packeteer.__main__``.
"""
from __future__ import annotations

from typing import Any

from packeteer.generate.http import (
    HTTP_ALT_PORT,
    HTTP_PORT,
    HTTPRequest,
    HTTPResponse,
    _build_http_message,
)
from packeteer.protocols import AppProtocol


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


def from_spec(section: dict[str, Any]) -> HTTPRequest | HTTPResponse:
    """Build an HTTP message from a spec section.

    Args:
        section: The object found under ``"http"`` in a packet spec.
            ``type`` of ``"response"`` selects
            :class:`~packeteer.generate.http.HTTPResponse`; anything else is
            read as a request.

    Returns:
        The message it describes.

    """
    headers = section.get("headers", {})
    body = bytes.fromhex(section.get("body", ""))
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


def sanitise(section: dict[str, Any], replacer: Any, options: Any) -> None:
    """Redact *section* in place.

    Args:
        section: An ``http`` packet-spec section.
        replacer: Unused — HTTP redaction needs no consistent replacement map.
        options: The :class:`~packeteer.sanitise.SanitiseOptions` in force.

    """
    from packeteer.sanitise import _sanitise_http

    _sanitise_http(section, options)


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
