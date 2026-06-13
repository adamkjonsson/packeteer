"""Application-layer payload generators for stream traffic.

Each payload type describes a connection's traffic as a list of
:class:`~packeteer.generate.payloads.base.AppMessage` objects and renders it
onto TCP via :func:`~packeteer.generate.payloads.base.render_tcp_session`.

Currently available types (selectable as ``--payload <name>`` in
``packeteer stream``):

* ``http`` — random HTTP/1.1 REST client traffic
  (:func:`~packeteer.generate.payloads.http.generate_http_stream`).
* ``vpn`` — a fictive binary VPN protocol with a key-exchange channel and a
  CTR-mode data channel (:func:`~packeteer.generate.payloads.vpn.generate_vpn_stream`).
"""
from __future__ import annotations

from collections.abc import Callable

from ..session_mix import CombinedStream
from .base import AppMessage, Direction, render_tcp_session, render_udp_session
from .http import HTTPRestConfig, generate_http_conversation, generate_http_stream
from .vpn import VPNConfig, generate_vpn_stream

# Registry mapping a payload-type name to a builder that returns a stream.
# Each builder accepts the keyword arguments assembled by the CLI.
PAYLOAD_TYPES: dict[str, Callable[..., CombinedStream]] = {
    "http": generate_http_stream,
    "vpn": generate_vpn_stream,
}

__all__ = [
    "AppMessage",
    "Direction",
    "render_tcp_session",
    "render_udp_session",
    "HTTPRestConfig",
    "generate_http_conversation",
    "generate_http_stream",
    "VPNConfig",
    "generate_vpn_stream",
    "PAYLOAD_TYPES",
]
