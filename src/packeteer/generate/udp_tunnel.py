"""A UDP tunnel whose outer payload is computed by the caller's code (#197).

A generated stream's packets become the payloads of UDP datagrams between
two tunnel endpoints, as in WireGuard or OpenVPN over UDP.  What goes in each
datagram is the caller's business: packeteer does no cryptography, so a
:class:`TunnelWrapper` the caller writes turns each inner packet into the
outer datagrams to send — sealed, framed, preceded by a handshake, whatever
the protocol under test does.

**It is not an encapsulation layer**, and it does not go in ``encap=``.  An
encap is applied as each packet is built, before any impairment has run,
which is too early for a stateful tunnel: a retransmitted inner segment
must be sealed again with a fresh counter, and a lost one never sealed at
all.  :func:`tunnel_stream` runs on the finished stream instead.  So:

1. **The wrapper sees each inner packet once per time it is sent, in wire
   order**, after the inner stream's own impairments: a retransmission
   again, a lost packet never.
2. **Outer impairments apply after wrapping**, so corruption lands on the
   sealed bytes, and losing an outer datagram loses everything it carried.
3. **Direction maps to the endpoints**: a datagram the wrapper returns as
   ``c2s`` travels ``src_ip → dst_ip``, and ``s2c`` the reverse.
4. **It is seeded and reproducible.**  The outer impairments draw from an
   RNG of their own, so enabling them never changes the inner stream; the
   wrapper gets nothing random from packeteer.

Typical usage::

    from packeteer.generate import (
        UDPTunnel, UDPStreamConfig, generate_udp_stream, tunnel_stream,
    )

    class Counted:
        def __init__(self) -> None:
            self.sent = {"c2s": 0, "s2c": 0}

        def wrap(self, inner, direction, timestamp):
            n = self.sent[direction]
            self.sent[direction] += 1
            return [(direction, n.to_bytes(8, "big") + inner)]

    inner = generate_udp_stream(
        client_ip="10.0.0.2", server_ip="10.0.0.1", include_ethernet=False,
        config=UDPStreamConfig(seed=7, base_time=1_700_000_000.0),
    )
    outer = tunnel_stream(inner, UDPTunnel(
        src_ip="198.51.100.7", dst_ip="203.0.113.9", port=51820,
        wrapper=Counted(),
    ), seed=7)
"""
from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from random import Random
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ._stream_common import _pkt_usec
from .impairments import ImpairmentConfig, apply_datagram_impairments
from .stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
)
from .udp_stream import UDPStream, UDPStreamPacket, _build_directed_udp_packet

if TYPE_CHECKING:  # pragma: no cover - session_mix imports the stream modules
    from .sctp_stream import SCTPStream
    from .session_mix import CombinedStream
    from .tcp_stream import TCPStream

#: The name a tunnel module defines its wrapper factory under.
WRAPPER_FACTORY = "make_wrapper"

_DIRECTIONS = ("c2s", "s2c")


@runtime_checkable
class TunnelWrapper(Protocol):
    """What turns an inner packet into the outer datagrams that carry it.

    Called once per inner packet, in wire order, and only for packets that
    were sent: see :func:`tunnel_stream`.  A wrapper keeps whatever state the
    protocol needs — keys, counters, when it last rekeyed — between calls.
    """

    def wrap(
        self, inner: bytes, direction: str, timestamp: float,
    ) -> Sequence[tuple[str, bytes]]:
        """Return the outer datagrams to send at this point, in order.

        Args:
            inner: The inner packet, from its IP header on.
            direction: ``"c2s"`` or ``"s2c"``, the way the inner packet
                travels.
            timestamp: When the inner packet was sent, in seconds since the
                epoch: what a wrapper needs to rekey after a time or send a
                keepalive after an idle period.

        Returns:
            ``(direction, payload)`` pairs, one per outer datagram.  Usually
            one ``(direction, sealed)``; more to send a handshake or a rekey
            first, each in its own direction; none to swallow the packet.

        """
        ...


@dataclass
class UDPTunnel:
    """The two endpoints of a UDP tunnel, and the code that fills it.

    Attributes:
        src_ip: The tunnel endpoint on the client's side.  A ``c2s`` outer
            datagram leaves from here.
        dst_ip: The tunnel endpoint on the server's side.
        port: The UDP port at *dst_ip*, and at *src_ip* too unless
            *src_port* says otherwise — as WireGuard runs.
        wrapper: The :class:`TunnelWrapper` that computes each outer payload.
        src_port: The UDP port at *src_ip*.  ``None`` (the default) uses
            *port*.
        ttl: The outer IP TTL / hop limit.  Defaults to ``64``.

    """

    src_ip: str
    dst_ip: str
    port: int
    wrapper: TunnelWrapper
    src_port: int | None = None
    ttl: int = 64


def _sealed(
    result: object, label: str,
) -> list[tuple[str, bytes]]:
    """Return what ``wrap`` returned as checked pairs, or refuse it naming *label*."""
    where = f"the tunnel wrapper's return for {label}"
    if isinstance(result, (str, bytes, bytearray)) or not isinstance(result, Sequence):
        raise ValueError(
            f"{where} must be a sequence of (direction, payload) pairs, "
            f"not {type(result).__name__}"
        )
    pairs: list[tuple[str, bytes]] = []
    for index, item in enumerate(result):
        if not (isinstance(item, (tuple, list)) and len(item) == 2):
            raise ValueError(f"{where}, item {index}, must be a (direction, payload) pair")
        direction, payload = item
        if direction not in _DIRECTIONS:
            raise ValueError(
                f"{where}, item {index}: direction must be 'c2s' or 's2c', "
                f"not {direction!r}"
            )
        if not isinstance(payload, (bytes, bytearray)):
            raise ValueError(
                f"{where}, item {index}: payload must be bytes, "
                f"not {type(payload).__name__}"
            )
        pairs.append((direction, bytes(payload)))
    return pairs


def tunnel_stream(
    stream: TCPStream | UDPStream | SCTPStream | CombinedStream,
    tunnel: UDPTunnel,
    *,
    include_ethernet: bool = True,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    encap: EncapSpec = None,
    impairments: ImpairmentConfig | None = None,
    seed: int | None = None,
) -> UDPStream:
    """Carry *stream* through a UDP tunnel whose payloads *tunnel*'s wrapper computes.

    The inner packets are taken in timestamp order — wire order, after
    whatever impairments the inner stream already had — and each is handed
    to ``tunnel.wrapper.wrap`` once.  Every pair it returns becomes one
    outer UDP datagram between the tunnel endpoints, in the direction the
    pair names.  The first takes the inner packet's timestamp and each
    further one the next microsecond, so the outer datagrams are in the
    order the wrapper returned them.  Each is labelled ``TUNNEL[<inner
    label>]``, and further ones from the same call ``TUNNEL[<inner
    label>]+1``, ``+2``.

    Args:
        stream: The inner stream.  Its packets must start at the IP header,
            so generate it with ``include_ethernet=False`` and no tunnel
            encap.  Any stream works, several sessions included: one tunnel
            carries them all, as a VPN does.
        tunnel: The endpoints and the wrapper.
        include_ethernet: Whether each outer datagram has an Ethernet header.
        client_mac: Ethernet source of a ``c2s`` outer datagram.
        server_mac: Ethernet source of an ``s2c`` outer datagram.
        encap: Layer-2 tags (VLAN, QinQ, MPLS, PPPoE) for the **outer**
            packets.  A tunnel encap here would put a tunnel round a tunnel.
        impairments: Datagram impairments for the **outer** datagrams —
            loss, corruption, reordering, duplication — applied after
            wrapping, so corruption lands on the sealed bytes.  The inner
            stream's own impairments are the inner stream's business.
        seed: Seeds the outer impairments' RNG, which is derived from it and
            separate from the inner stream's, so outer impairments never
            change what the wrapper is given.

    Returns:
        The outer datagrams, in timestamp order.

    Raises:
        ValueError: If an inner packet is not an IP packet, or the wrapper
            returns anything but a sequence of ``(direction, bytes)`` pairs.

    """
    src_port = tunnel.port if tunnel.src_port is None else tunnel.src_port
    packets: list[UDPStreamPacket] = []
    last_usec = -1
    for inner in sorted(stream.packets, key=_pkt_usec):
        if not inner.raw or inner.raw[0] >> 4 not in (4, 6):
            raise ValueError(
                f"inner packet {inner.label} does not start with an IP header; "
                f"generate the inner stream with include_ethernet=False and no "
                f"tunnel encap"
            )
        usec = _pkt_usec(inner)
        sealed = _sealed(
            tunnel.wrapper.wrap(inner.raw, inner.direction, usec / 1_000_000),
            inner.label,
        )
        for index, (direction, payload) in enumerate(sealed):
            last_usec = max(usec, last_usec + 1)
            label = f"TUNNEL[{inner.label}]" + (f"+{index}" if index else "")
            packets.append(UDPStreamPacket(
                raw=_build_directed_udp_packet(
                    direction,
                    client_ip=tunnel.src_ip, server_ip=tunnel.dst_ip,
                    client_port=src_port, server_port=tunnel.port,
                    client_mac=client_mac, server_mac=server_mac,
                    payload=payload, include_ethernet=include_ethernet,
                    ip_ttl=tunnel.ttl, encap=encap,
                ),
                ts_sec=last_usec // 1_000_000,
                ts_usec=last_usec % 1_000_000,
                direction=direction,
                payload_len=len(payload),
                label=label,
            ))
    if impairments is not None:
        # An RNG of its own, so the outer impairments never shift a draw the
        # inner stream made.  A string seed is hashed deterministically.
        rng = Random(f"udp-tunnel:{seed}") if seed is not None else Random()
        packets = apply_datagram_impairments(
            packets, rng=rng, config=impairments,
            include_ethernet=include_ethernet, encap=encap,
        )
    return UDPStream(packets=packets)


def load_wrapper(
    path: str | os.PathLike, args: Mapping[str, str] | None = None,
) -> TunnelWrapper:
    """Import a tunnel module and return the wrapper its factory makes.

    The module defines ``make_wrapper(args: dict[str, str]) -> TunnelWrapper``,
    and is given *args* — ``--tunnel-arg KEY=VALUE`` on the command line.
    What the wrapper does with them, a key log to write for instance, is its
    own business.

    **A tunnel module is code, and loading it runs that code**, as with
    :func:`packeteer.protocols.load_module`: take the path from the user,
    never from data packeteer parsed.  The module is executed afresh on each
    call, so each wrapper starts with the module's state new.

    Args:
        path: Path to a ``.py`` file.
        args: The factory's arguments.  ``None`` is an empty mapping.

    Returns:
        The wrapper.

    Raises:
        ValueError: If *path* is not a file, fails while being imported,
            defines no ``make_wrapper``, raises from it, or returns something
            without a ``wrap`` method — naming the file each time.

    """
    shown = os.fspath(path)
    resolved = os.path.abspath(shown)
    if not os.path.isfile(resolved):
        raise ValueError(f"no tunnel module at {shown!r}")
    name = "packeteer._tunnel." + os.path.splitext(os.path.basename(resolved))[0]
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load a Python module from {shown!r}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        del sys.modules[name]
        raise ValueError(
            f"{shown} failed while being imported ({type(exc).__name__}: {exc})"
        ) from exc
    factory = getattr(module, WRAPPER_FACTORY, None)
    if not callable(factory):
        raise ValueError(
            f"{shown} defines no {WRAPPER_FACTORY}(args), the function that "
            f"makes its tunnel wrapper"
        )
    try:
        wrapper = factory(dict(args or {}))
    except Exception as exc:
        raise ValueError(
            f"{shown}: {WRAPPER_FACTORY} raised {type(exc).__name__}: {exc}"
        ) from exc
    if not callable(getattr(wrapper, "wrap", None)):
        raise ValueError(
            f"{shown}: {WRAPPER_FACTORY} returned a {type(wrapper).__name__}, "
            f"which has no wrap(inner, direction, timestamp) method"
        )
    return wrapper
