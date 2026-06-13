"""Generate traffic for a fictive, deliberately simple binary VPN protocol.

The protocol has two UDP channels:

* a **key-exchange channel** (its own UDP port) that performs a three-message
  handshake — INIT (client random) → RESPONSE (server random) → CONFIRM — at
  the start of every key *epoch*;
* a **data channel** (a separate UDP port) carrying packets encrypted with a
  block cipher in counter (CTR) mode; each packet therefore carries a counter.

A run consists of *epochs* key negotiations, each followed by *packets_per_epoch*
data packets (so a rekey happens every *packets_per_epoch* packets).  Data flows
in both directions with an independent per-direction counter that resets to zero
at each rekey.  All "ciphertext" and random values are random bytes — nothing is
actually encrypted.

Wire format (big-endian).  Common 8-byte header::

    magic(4) | version(1) | msg_type(1) | key_epoch(2)

* key-exchange message: header followed by a random value;
* data message: header followed by counter(8) and the random ciphertext.
"""
from __future__ import annotations

import random
import struct
import time
from dataclasses import dataclass

from ..session_mix import CombinedStream, _assign_endpoints, merge_streams
from ..stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
)
from .base import AppMessage, render_udp_session

_MSG_KEY_INIT = 1
_MSG_KEY_RESPONSE = 2
_MSG_KEY_CONFIRM = 3
_MSG_DATA = 4

_HEADER = struct.Struct(">4sBBH")   # magic, version, msg_type, key_epoch
_COUNTER = struct.Struct(">Q")      # 64-bit data counter


@dataclass
class VPNConfig:
    """Wire-format knobs for :func:`generate_vpn_stream`.

    Attributes:
        data_port: UDP port of the data channel.
        key_port: UDP port of the key-exchange channel.
        magic: Four-byte protocol magic placed at the start of every message.
        version: Protocol version byte.
        random_value_size: Length in bytes of the random value carried in each
            key-exchange message.

    """

    data_port: int = 51820
    key_port: int = 51821
    magic: bytes = b"VPNX"
    version: int = 1
    random_value_size: int = 32


def _header(msg_type: int, epoch: int, config: VPNConfig) -> bytes:
    """Pack the common 8-byte VPN header."""
    return _HEADER.pack(config.magic, config.version, msg_type, epoch)


def _key_message(rng: random.Random, msg_type: int, epoch: int, config: VPNConfig) -> bytes:
    """Build a key-exchange message: header + a random value."""
    return _header(msg_type, epoch, config) + rng.randbytes(config.random_value_size)


def _data_message(
    rng: random.Random, epoch: int, counter: int, size: int, config: VPNConfig,
) -> bytes:
    """Build a data message: header + counter + random ciphertext."""
    return _header(_MSG_DATA, epoch, config) + _COUNTER.pack(counter) + rng.randbytes(size)


def _handshake_messages(rng: random.Random, epoch: int, config: VPNConfig) -> list[AppMessage]:
    """Build the three key-exchange messages for one epoch."""
    return [
        AppMessage("c2s", _key_message(rng, _MSG_KEY_INIT, epoch, config),
                   f"KEY-INIT[epoch={epoch}]"),
        AppMessage("s2c", _key_message(rng, _MSG_KEY_RESPONSE, epoch, config),
                   f"KEY-RESPONSE[epoch={epoch}]"),
        AppMessage("c2s", _key_message(rng, _MSG_KEY_CONFIRM, epoch, config),
                   f"KEY-CONFIRM[epoch={epoch}]"),
    ]


def _data_messages(
    rng: random.Random, epoch: int, count: int,
    min_payload: int, max_payload: int, config: VPNConfig,
) -> list[AppMessage]:
    """Build *count* bidirectional data messages with per-direction counters."""
    messages: list[AppMessage] = []
    counters = {"c2s": 0, "s2c": 0}
    for _ in range(count):
        direction = "c2s" if rng.random() < 0.5 else "s2c"
        counter = counters[direction]
        counters[direction] += 1
        size = rng.randint(min_payload, max_payload)
        messages.append(AppMessage(
            direction,
            _data_message(rng, epoch, counter, size, config),
            f"DATA {direction} ctr={counter} epoch={epoch}",
        ))
    return messages


def generate_vpn_stream(
    *,
    client_ip: str,
    server_ip: str,
    epochs: int = 4,
    packets_per_epoch: int = 10,
    client_port: int = 54321,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    sessions: int = 1,
    session_stagger: float = 1.0,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    inter_packet_gap: float = 0.001,
    min_payload: int = 40,
    max_payload: int = 1460,
    encap: EncapSpec = None,
    seed: int | None = None,
    base_time: float | None = None,
    config: VPNConfig | None = None,
) -> CombinedStream:
    """Generate fictive VPN traffic and return it as a merged stream.

    Each session runs *epochs* key negotiations on the key-exchange port; after
    each handshake, *packets_per_epoch* data packets flow on the data port (so a
    rekey occurs every *packets_per_epoch* packets).  Data is bidirectional with
    an independent per-direction CTR counter that resets at each rekey.  With
    *sessions* > 1 the whole workload is repeated for each distinct client/server
    IP pair (session ``i`` uses ``client_ip + i`` / ``server_ip + i``; the two
    ranges must not overlap).

    Args:
        client_ip: Base client IP address.
        server_ip: Base server IP address.
        epochs: Number of key negotiations (epochs) per session.
        packets_per_epoch: Data packets after each handshake (the rekey interval).
        client_port: Client source port (shared by both channels).
        client_mac: Client MAC address.
        server_mac: Server MAC address.
        sessions: Number of distinct client/server IP pairs.
        session_stagger: Window in seconds over which session start times spread.
        include_ethernet: Whether to include Ethernet headers.
        ip_ttl: IP TTL / hop limit.
        inter_packet_gap: Seconds between consecutive packets.
        min_payload: Minimum ciphertext size in bytes.
        max_payload: Maximum ciphertext size in bytes.
        encap: Optional encapsulation layer(s) applied to every packet.
        seed: RNG seed; the same seed reproduces the whole capture.
        base_time: Unix start time; defaults to the current time.
        config: Wire-format knobs (:class:`VPNConfig`).

    Returns:
        A :class:`~packeteer.generate.session_mix.CombinedStream` of both
        channels across all epochs and sessions, merged in timestamp order.

    Raises:
        ValueError: If *epochs* or *packets_per_epoch* is below 1, *min_payload*
            exceeds *max_payload*, or the client/server IP ranges overlap.

    """
    if epochs < 1:
        raise ValueError(f"epochs must be at least 1, got {epochs}")
    if packets_per_epoch < 1:
        raise ValueError(
            f"packets_per_epoch must be at least 1, got {packets_per_epoch}"
        )
    if min_payload > max_payload:
        raise ValueError(
            f"min_payload ({min_payload}) must not exceed max_payload ({max_payload})"
        )
    if config is None:
        config = VPNConfig()

    client_ips, server_ips = _assign_endpoints(client_ip, server_ip, sessions)
    rng = random.Random(seed)
    start = base_time if base_time is not None else time.time()
    gap = inter_packet_gap

    streams = []
    for session_idx in range(sessions):
        cursor = start if session_idx == 0 else start + rng.uniform(0.0, session_stagger)
        for epoch in range(epochs):
            common = {
                "client_ip": client_ips[session_idx],
                "server_ip": server_ips[session_idx],
                "client_port": client_port,
                "client_mac": client_mac,
                "server_mac": server_mac,
                "include_ethernet": include_ethernet,
                "ip_ttl": ip_ttl,
                "inter_packet_gap": gap,
                "encap": encap,
            }
            handshake = _handshake_messages(rng, epoch, config)
            streams.append(render_udp_session(
                handshake, server_port=config.key_port, base_time=cursor, **common,
            ))
            cursor += len(handshake) * gap

            data = _data_messages(
                rng, epoch, packets_per_epoch, min_payload, max_payload, config,
            )
            streams.append(render_udp_session(
                data, server_port=config.data_port, base_time=cursor, **common,
            ))
            cursor += len(data) * gap
    return merge_streams(streams)
