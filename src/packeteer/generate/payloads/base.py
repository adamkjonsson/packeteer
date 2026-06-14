"""Building blocks shared by application-layer payload generators.

A payload generator describes a single connection's traffic as an ordered list
of :class:`AppMessage` objects — each a chunk of application bytes flowing in
one direction (``"c2s"`` client→server or ``"s2c"`` server→client).  The
:func:`render_tcp_session` helper turns such a conversation into a complete
:class:`~packeteer.generate.tcp_stream.TCPStream` (handshake, MSS-segmented data
with correct sequence/ack numbers, and teardown) via
:class:`~packeteer.generate.session.TCPSession`.

HTTP is the first payload type (see :mod:`packeteer.generate.payloads.http`);
other types plug in by producing their own :class:`AppMessage` lists.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..session import TCPSession, UDPSession
from ..stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
)
from ..tcp_stream import TCPStream
from ..udp_stream import UDPStream

Direction = Literal["c2s", "s2c"]


@dataclass
class AppMessage:
    """One application-layer message flowing in a single direction.

    Attributes:
        direction: ``"c2s"`` (client→server) or ``"s2c"`` (server→client).
        data: Application bytes (e.g. an encoded HTTP request or response).
        label: Human-readable label carried onto the resulting data segment(s)
            (e.g. ``"GET /api/v1/orders/42"`` or ``"200 OK"``).

    """

    direction: Direction
    data: bytes
    label: str


def render_tcp_session(
    messages: list[AppMessage],
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    mss: int = 1460,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    inter_packet_gap: float = 0.001,
    base_time: float | None = None,
    encap: EncapSpec = None,
    client_isn: int | None = None,
    server_isn: int | None = None,
) -> TCPStream:
    """Render a conversation onto a TCP connection.

    Each message becomes one application send in its direction (segmented by
    *mss*), carrying its :attr:`AppMessage.label`.  The handshake, ACKs, and
    teardown are produced by :class:`~packeteer.generate.session.TCPSession`.

    Args:
        messages: The ordered conversation to render.
        client_ip: Client IP address.
        server_ip: Server IP address.
        client_port: Client source port.
        server_port: Server destination port.
        client_mac: Client MAC address.
        server_mac: Server MAC address.
        mss: Maximum segment size for splitting large payloads.
        include_ethernet: Whether to include Ethernet headers.
        ip_ttl: IP TTL / hop limit.
        inter_packet_gap: Seconds between consecutive packets.
        base_time: Unix timestamp of the first packet.
        encap: Optional encapsulation layer(s).
        client_isn: Client initial sequence number (random when ``None``).
        server_isn: Server initial sequence number (random when ``None``).

    Returns:
        A :class:`~packeteer.generate.tcp_stream.TCPStream` for the connection.

    """
    session = TCPSession(
        client_ip=client_ip, server_ip=server_ip,
        client_port=client_port, server_port=server_port,
        client_mac=client_mac, server_mac=server_mac,
        mss=mss, include_ethernet=include_ethernet, ip_ttl=ip_ttl,
        inter_packet_gap=inter_packet_gap, base_time=base_time, encap=encap,
        client_isn=client_isn, server_isn=server_isn,
    )
    for message in messages:
        if message.direction == "c2s":
            session.send(message.data, label=message.label)
        else:
            session.recv(message.data, label=message.label)
    return session.build()


def render_udp_session(
    messages: list[AppMessage],
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    inter_packet_gap: float = 0.001,
    base_time: float | None = None,
    encap: EncapSpec = None,
) -> UDPStream:
    """Render a conversation onto a UDP flow.

    Each message becomes one UDP datagram in its direction, carrying its
    :attr:`AppMessage.label`.

    Args:
        messages: The ordered conversation to render.
        client_ip: Client IP address.
        server_ip: Server IP address.
        client_port: Client source port.
        server_port: Server destination port.
        client_mac: Client MAC address.
        server_mac: Server MAC address.
        include_ethernet: Whether to include Ethernet headers.
        ip_ttl: IP TTL / hop limit.
        inter_packet_gap: Seconds between consecutive datagrams.
        base_time: Unix timestamp of the first datagram.
        encap: Optional encapsulation layer(s).

    Returns:
        A :class:`~packeteer.generate.udp_stream.UDPStream` for the flow.

    """
    session = UDPSession(
        client_ip=client_ip, server_ip=server_ip,
        client_port=client_port, server_port=server_port,
        client_mac=client_mac, server_mac=server_mac,
        include_ethernet=include_ethernet, ip_ttl=ip_ttl,
        inter_packet_gap=inter_packet_gap, base_time=base_time, encap=encap,
    )
    for message in messages:
        if message.direction == "c2s":
            session.send(message.data, label=message.label)
        else:
            session.recv(message.data, label=message.label)
    return session.build()
