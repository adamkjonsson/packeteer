"""Generate and merge several independent sessions into one capture.

A single call to :func:`generate_tcp_stream` (or the UDP/SCTP variants) produces
one conversation between one client/server IP pair.  :func:`generate_session_mix`
produces *several* such conversations — each with its own distinct IP pair,
start-time offset, and RNG seed — and interleaves them into a single
timestamp-sorted stream.

Client and server addresses are kept in clearly separated ranges: the client
IPs are ``client_ip + 0 .. client_ip + (sessions - 1)`` and the server IPs are
``server_ip + 0 .. server_ip + (sessions - 1)``.  If those two ranges would
overlap, a :class:`ValueError` is raised rather than silently emitting traffic
where one session's client address is another session's server address.

:func:`merge_streams` is the underlying primitive: it combines the packet lists
of any streams (built however you like) into one timestamp-sorted
:class:`CombinedStream`.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import random
import time
from collections.abc import Sequence
from dataclasses import dataclass

from .sctp_stream import SCTPStream, SCTPStreamConfig, SCTPStreamPacket, generate_sctp_stream
from .stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
)
from .tcp_stream import TCPStream, TCPStreamConfig, TCPStreamPacket, generate_tcp_stream
from .udp_stream import UDPStream, UDPStreamConfig, UDPStreamPacket, generate_udp_stream

Stream = TCPStream | UDPStream | SCTPStream
StreamConfig = TCPStreamConfig | UDPStreamConfig | SCTPStreamConfig
StreamPacket = TCPStreamPacket | UDPStreamPacket | SCTPStreamPacket

# The config type selects the protocol — the CLI's --protocol just picks which
# config to build, so a separate protocol argument would be redundant.
_GENERATOR_BY_CONFIG: dict[type[StreamConfig], object] = {
    TCPStreamConfig: generate_tcp_stream,
    UDPStreamConfig: generate_udp_stream,
    SCTPStreamConfig: generate_sctp_stream,
}


@dataclass
class CombinedStream:
    """Several streams merged into one timestamp-ordered packet list.

    Exposes the same ``packets`` / :meth:`to_pcap_tuples` interface as the
    single-session stream classes, so it is a drop-in for pcap writing and
    packet-spec serialisation.

    Attributes:
        packets: All sessions' packets, stably sorted by capture timestamp.

    """

    packets: list[StreamPacket]

    def to_pcap_tuples(self) -> list[tuple[bytes, int, int]]:
        """Return ``(raw, ts_sec, ts_usec)`` tuples ready for :func:`write_pcap`.

        Returns:
            One tuple per packet, in timestamp order.

        """
        return [(p.raw, p.ts_sec, p.ts_usec) for p in self.packets]


def merge_streams(streams: Sequence[Stream | CombinedStream]) -> CombinedStream:
    """Merge several streams into one timestamp-sorted :class:`CombinedStream`.

    The packets of every stream are concatenated and stably sorted by
    ``(ts_sec, ts_usec)``, so packets from different sessions interleave in
    capture order while each session keeps its internal ordering on ties.

    Args:
        streams: Streams to merge.  They should all be the same protocol so the
            resulting packet list is homogeneous.

    Returns:
        A :class:`CombinedStream` over all the packets.

    """
    packets: list[StreamPacket] = []
    for stream in streams:
        packets.extend(stream.packets)
    packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))
    return CombinedStream(packets=packets)


def _ip_plus(ip: str, offset: int) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return *ip* advanced by *offset* addresses, raising on overflow."""
    return ipaddress.ip_address(ip) + offset


def _assign_endpoints(
    client_ip: str, server_ip: str, sessions: int,
) -> tuple[list[str], list[str]]:
    """Return per-session client and server IPs, keeping the ranges disjoint.

    Raises:
        ValueError: If *client_ip* and *server_ip* are different families, or if
            the two address ranges would overlap across *sessions* sessions.

    """
    base_client = ipaddress.ip_address(client_ip)
    base_server = ipaddress.ip_address(server_ip)
    if base_client.version != base_server.version:
        raise ValueError(
            f"client IP {client_ip!r} and server IP {server_ip!r} must be the "
            "same address family"
        )
    clients = [base_client + i for i in range(sessions)]
    servers = [base_server + i for i in range(sessions)]
    if set(clients) & set(servers):
        raise ValueError(
            f"client and server IP ranges overlap across {sessions} sessions: "
            f"clients {clients[0]}..{clients[-1]} and servers "
            f"{servers[0]}..{servers[-1]} intersect.  Choose client and server "
            "base addresses at least "
            f"{sessions} apart, or put them in different subnets."
        )
    return [str(ip) for ip in clients], [str(ip) for ip in servers]


def generate_session_mix(
    *,
    sessions: int,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    num_data_packets: int = 10,
    min_payload: int = 40,
    max_payload: int = 1460,
    payload_distribution: str = "uniform",
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    inter_packet_gap: float = 0.001,
    mtu: int | None = None,
    encap: EncapSpec = None,
    session_stagger: float = 1.0,
    config: StreamConfig | None = None,
) -> CombinedStream:
    """Generate *sessions* independent conversations and interleave them.

    Each session is a complete single-protocol stream with its own endpoints
    and timing.  The protocol is selected by the type of *config*: a
    ``TCPStreamConfig`` produces TCP sessions, ``UDPStreamConfig`` UDP, and
    ``SCTPStreamConfig`` SCTP (the default is TCP).

    - **Endpoints** — session ``i`` uses ``client_ip + i`` / ``server_ip + i``;
      the client and server IP ranges must not overlap (see
      :func:`_assign_endpoints`).  MAC addresses are shared across sessions,
      modelling traffic that crosses a common L2 next-hop.
    - **Timing** — session ``i`` starts at ``base_time + offset_i``, where
      ``offset_i`` is drawn from ``[0, session_stagger]`` (session 0 starts at
      ``base_time``).  Merging by timestamp interleaves the sessions.
    - **Reproducibility** — when *config* carries a ``seed``, session ``i`` uses
      ``seed + i`` and the start offsets are drawn from that seed, so the whole
      mix is deterministic.

    Args:
        sessions: Number of sessions to generate (at least 1).
        client_ip: Base client IP; session ``i`` uses this address plus ``i``.
        server_ip: Base server IP; session ``i`` uses this address plus ``i``.
        client_port: Client source port, shared by every session.
        server_port: Server destination port, shared by every session.
        client_mac: Client MAC, shared by every session.
        server_mac: Server MAC, shared by every session.
        num_data_packets: Data packets per session (see the stream generators).
        min_payload: Minimum payload size in bytes.
        max_payload: Maximum payload size in bytes.
        payload_distribution: ``"uniform"``, ``"bimodal"``, or ``"fixed"``.
        include_ethernet: Whether to include an Ethernet header.
        ip_ttl: IP TTL / hop limit.
        inter_packet_gap: Base inter-packet gap in seconds.
        mtu: Optional MTU; larger packets are fragmented.
        encap: Optional encapsulation layer(s) applied to every session.
        session_stagger: Width in seconds of the window over which session
            start times are spread.
        config: Protocol config (``TCPStreamConfig`` etc.); its type selects the
            protocol, and its ``base_time`` and ``seed`` seed the per-session
            timing and RNG.  Defaults to ``TCPStreamConfig()``.

    Returns:
        A :class:`CombinedStream` containing every session's packets, merged in
        timestamp order.

    Raises:
        ValueError: If *config* is an unsupported type, *sessions* is below 1,
            or the client and server IP ranges overlap.

    """
    if sessions < 1:
        raise ValueError(f"sessions must be at least 1, got {sessions}")
    if config is None:
        config = TCPStreamConfig()
    generator = _GENERATOR_BY_CONFIG.get(type(config))
    if generator is None:
        raise ValueError(
            f"unsupported config type {type(config).__name__}; expected one of "
            "TCPStreamConfig, UDPStreamConfig, SCTPStreamConfig"
        )

    base_time = config.base_time if config.base_time is not None else time.time()
    base_seed = config.seed

    client_ips, server_ips = _assign_endpoints(client_ip, server_ip, sessions)

    rng = random.Random(base_seed)
    offsets = [0.0]
    offsets += [rng.uniform(0.0, session_stagger) for _ in range(sessions - 1)]

    streams: list[Stream] = []
    for i in range(sessions):
        session_config = dataclasses.replace(
            config,
            base_time=base_time + offsets[i],
            seed=(base_seed + i) if base_seed is not None else None,
        )
        streams.append(generator(  # type: ignore[operator]
            client_ip=client_ips[i],
            server_ip=server_ips[i],
            client_port=client_port,
            server_port=server_port,
            client_mac=client_mac,
            server_mac=server_mac,
            num_data_packets=num_data_packets,
            min_payload=min_payload,
            max_payload=max_payload,
            payload_distribution=payload_distribution,
            include_ethernet=include_ethernet,
            ip_ttl=ip_ttl,
            inter_packet_gap=inter_packet_gap,
            mtu=mtu,
            encap=encap,
            config=session_config,
        ))
    return merge_streams(streams)
