"""SCTP stream generation (RFC 9260).

This module generates a complete, realistic SCTP association as a sequence
of byte-accurate packets: four-way handshake, data transfer, and graceful
shutdown.  Verification tags, TSNs, and all SCTP/IP checksums are computed
correctly.

**Packet sequence** (``2 * num_data_packets + 7`` packets):

.. list-table::
   :header-rows: 1

   * - Phase
     - Direction
     - Chunk type
     - Label
   * - Handshake
     - c2s
     - INIT
     - ``"INIT"``
   * - Handshake
     - s2c
     - INIT ACK
     - ``"INIT-ACK"``
   * - Handshake
     - c2s
     - COOKIE ECHO
     - ``"COOKIE-ECHO"``
   * - Handshake
     - s2c
     - COOKIE ACK
     - ``"COOKIE-ACK"``
   * - Data (×N)
     - c2s
     - DATA
     - ``"DATA[0]"`` … ``"DATA[N-1]"``
   * - Data (×N)
     - s2c
     - SACK
     - ``"SACK[0]"`` … ``"SACK[N-1]"``
   * - Shutdown
     - c2s
     - SHUTDOWN
     - ``"SHUTDOWN"``
   * - Shutdown
     - s2c
     - SHUTDOWN ACK
     - ``"SHUTDOWN-ACK"``
   * - Shutdown
     - c2s
     - SHUTDOWN COMPLETE
     - ``"SHUTDOWN-COMPLETE"``

Typical usage::

    from packeteer.generate.sctp_stream import generate_sctp_stream
    from packeteer.pcap import write_pcap

    stream = generate_sctp_stream(
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        server_port=9999,
        num_data_packets=10,
    )
    write_pcap(stream.to_pcap_tuples(), path="sctp_flow.pcap")
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from random import Random

from ._stream_common import (
    _alloc_usec,
    _fragment_ip_raw,
    _payload_sizes,
    _pkt_usec,
    _repeat_payload,
)
from .builder import PacketBuilder
from .sctp import (
    SCTP_DATA_FLAG_BEGINNING,
    SCTP_DATA_FLAG_ENDING,
    SCTPCookieAckChunk,
    SCTPCookieEchoChunk,
    SCTPDataChunk,
    SCTPInitAckChunk,
    SCTPInitChunk,
    SCTPSackChunk,
    SCTPShutdownAckChunk,
    SCTPShutdownChunk,
    SCTPShutdownCompleteChunk,
)
from .stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
    _apply_encap,
    _encap_ip_start,
)

_WRAP = 2 ** 32


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class SCTPStreamPacket:
    """One packet in a generated SCTP stream.

    Attributes:
        raw: Fully-assembled packet bytes, ready for pcap output.
        ts_sec: Packet timestamp — whole seconds part.
        ts_usec: Packet timestamp — microseconds part.
        direction: ``"c2s"`` (client→server) or ``"s2c"`` (server→client).
        tsn: TSN of the DATA chunk, or ``0`` for control packets.
        payload_len: User payload length in bytes (``0`` for control packets).
        label: Human-readable label (e.g. ``"DATA[0]"``, ``"INIT"``).

    """

    raw:         bytes
    ts_sec:      int
    ts_usec:     int
    direction:   str
    tsn:         int
    payload_len: int
    label:       str


@dataclass
class SCTPStream:
    """A complete generated SCTP stream.

    Attributes:
        packets: Ordered list of all packets in the stream.

    """

    packets: list[SCTPStreamPacket]

    def to_pcap_tuples(self) -> list[tuple[bytes, int, int]]:
        """Return packets as ``(raw, ts_sec, ts_usec)`` tuples for pcap output."""
        return [(p.raw, p.ts_sec, p.ts_usec) for p in self.packets]

    def client_packets(self) -> list[SCTPStreamPacket]:
        """Return only client→server packets."""
        return [p for p in self.packets if p.direction == "c2s"]

    def server_packets(self) -> list[SCTPStreamPacket]:
        """Return only server→client packets."""
        return [p for p in self.packets if p.direction == "s2c"]


@dataclass
class SCTPStreamConfig:
    """Optional SCTP-stream parameters.

    Pass an instance as the *config* argument to :func:`generate_sctp_stream`
    to customise timing and payload details without widening the function
    signature.

    Attributes:
        payload_sizes: Explicit list of payload sizes, one per DATA chunk.
            When provided, overrides *min_payload*, *max_payload*, and
            *payload_distribution*.  Must have exactly *num_data_packets*
            entries.
        base_time: Start timestamp in seconds.  Defaults to
            ``time.time()`` when ``None``.
        gap_jitter: Maximum additional random delay per inter-packet gap in
            seconds.  Packets are re-sorted by timestamp after jitter is
            applied.  Defaults to ``0.0`` (no jitter).
        seed: Integer seed for the random number generator.  When set, two
            calls with identical arguments produce byte-identical output.
            Defaults to ``None`` (non-deterministic).

    """

    payload_sizes: list[int] | None = None
    base_time: float | None = None
    gap_jitter: float = 0.0
    seed: int | None = None


# ── Internal helpers ──────────────────────────────────────────────────────────


def _build_sctp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    src_mac: str,
    dst_mac: str,
    vtag: int,
    chunks: list,
    include_ethernet: bool,
    ip_ttl: int,
    encap: EncapSpec = None,
) -> bytes:
    b = PacketBuilder()
    if include_ethernet:
        b = b.ethernet(src_mac=src_mac, dst_mac=dst_mac)
    b = _apply_encap(b, encap, src_mac, dst_mac)
    return (b
        .ip(src=src_ip, dst=dst_ip, ttl=ip_ttl)
        .sctp(src_port=src_port, dst_port=dst_port,
              verification_tag=vtag, chunks=chunks)
        .build()
    )


def _fragment_sctp_pkt(
    pkt: SCTPStreamPacket,
    mtu: int,
    include_ethernet: bool,
    used_ts: set[int],
    encap: EncapSpec = None,
) -> list[SCTPStreamPacket]:
    """Split *pkt* into IP fragments if its IP-layer size exceeds *mtu*."""
    ip_start = _encap_ip_start(encap, include_ethernet)
    frag_raws = _fragment_ip_raw(pkt.raw, ip_start, mtu, encap)
    if frag_raws is None:
        return [pkt]

    orig_usec = _pkt_usec(pkt)
    used_ts.discard(orig_usec)
    result: list[SCTPStreamPacket] = []
    for i, frag_raw in enumerate(frag_raws):
        ts = _alloc_usec(orig_usec + i, used_ts)
        result.append(SCTPStreamPacket(
            raw=frag_raw,
            ts_sec=ts // 1_000_000,
            ts_usec=ts % 1_000_000,
            direction=pkt.direction,
            tsn=pkt.tsn,
            payload_len=pkt.payload_len,
            label=f"FRAG[{pkt.label}][{i}]",
        ))
    return result


def _next_ts(
    cursor: int, gap: float, jitter: float, used: set[int], rng: Random,
) -> tuple[int, int, int]:
    """Advance *cursor* by one inter-packet gap and allocate a unique µs timestamp.

    Returns ``(ts_alloc, ts_sec, ts_usec)``.
    """
    gap_usec = int((gap + rng.uniform(0, jitter)) * 1_000_000)
    cursor += gap_usec
    ts = _alloc_usec(cursor, used)
    return ts, ts // 1_000_000, ts % 1_000_000


# ── Public generator ──────────────────────────────────────────────────────────

def generate_sctp_stream(
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    num_data_packets: int = 10,
    min_payload: int = 20,
    max_payload: int = 512,
    payload_distribution: str = "uniform",
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    inter_packet_gap: float = 0.001,
    mtu: int | None = None,
    encap: EncapSpec = None,
    config: SCTPStreamConfig | None = None,
) -> SCTPStream:
    """Generate a complete SCTP association with data transfer and shutdown.

    The generated stream contains ``2 * num_data_packets + 7`` packets:
    a four-way handshake (INIT / INIT ACK / COOKIE ECHO / COOKIE ACK),
    *num_data_packets* DATA chunks from client to server each followed by a
    server SACK, and a three-packet graceful shutdown
    (SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE).

    Verification tags are chosen at random (matching RFC 9260 §5.1) and
    used consistently throughout the stream.  The CRC-32c checksum on each
    packet is computed automatically.

    Args:
        client_ip: Client IP address (IPv4 or IPv6).
        server_ip: Server IP address (same family as *client_ip*).
        client_port: Client SCTP source port.  Defaults to ``54321``.
        server_port: Server SCTP destination port.  Defaults to ``80``.
        client_mac: Client MAC address.  Ignored when *include_ethernet* is
            ``False``.
        server_mac: Server MAC address.  Ignored when *include_ethernet* is
            ``False``.
        num_data_packets: Number of client DATA chunks to generate.
        min_payload: Minimum DATA chunk payload in bytes.
        max_payload: Maximum DATA chunk payload in bytes.
        payload_distribution: ``"uniform"`` (default), ``"bimodal"``, or
            ``"fixed"`` (all chunks carry *max_payload* bytes).
        include_ethernet: When ``True`` (default) each packet includes an
            Ethernet II header.
        ip_ttl: IP TTL / IPv6 Hop Limit.  Defaults to ``64``.
        inter_packet_gap: Gap between consecutive packets in seconds.
            Defaults to ``0.001`` (1 ms).
        mtu: When set, fragment packets whose IP-layer size exceeds
            this value, simulating a middlebox with a lower MTU.
        encap: One or more encapsulation layers to wrap every packet in.
            Accepts a single descriptor, a list of descriptors (applied
            outermost first), or ``None`` (default, no encapsulation).
            See :mod:`packeteer.generate.stream_encap` for available types
            (VLANEncap, QinQEncap, MPLSEncap, PPPoEEncap, GREEncap,
            EtherIPEncap, IPIPEncap) and combination rules.
        config: Optional :class:`SCTPStreamConfig` supplying timing details,
            explicit payload sizes, and RNG seed.  All fields default to their
            *SCTPStreamConfig* defaults when ``None``.

    Returns:
        A :class:`SCTPStream` whose :attr:`~SCTPStream.packets` list contains
        all assembled packets in timestamp order.

    Example::

        stream = generate_sctp_stream(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            server_port=9999,
            num_data_packets=10,
            payload_distribution="bimodal",
        )
        write_pcap(stream.to_pcap_tuples(), path="sctp_stream.pcap")

    """
    config = config or SCTPStreamConfig()
    payload_sizes = config.payload_sizes
    base_time = config.base_time if config.base_time is not None else time.time()
    gap_jitter = config.gap_jitter
    rng = Random(config.seed)

    # ── Verification tags and initial TSNs (RFC 9260 §5.1) ───────────────────
    # client_vtag: Initiate Tag chosen by the client in INIT
    # server_vtag: Initiate Tag chosen by the server in INIT ACK
    # After association, client→server packets carry server_vtag as their
    # verification tag and vice versa.
    client_vtag  = rng.randint(1, 0xFFFFFFFF)
    server_vtag  = rng.randint(1, 0xFFFFFFFF)
    client_tsn   = rng.randint(0, 0xFFFFFFFF)
    server_tsn   = rng.randint(0, 0xFFFFFFFF)

    # State cookie echoed from INIT ACK → COOKIE ECHO (opaque bytes)
    cookie = bytes(rng.getrandbits(8) for _ in range(16))

    # ── Payload sizes and continuous payload ──────────────────────────────────
    sizes = _payload_sizes(
        num_data_packets, min_payload, max_payload,
        payload_distribution, payload_sizes, rng,
    )
    payload_data = _repeat_payload(sum(sizes))
    payload_offset = 0

    # ── Timestamp state ───────────────────────────────────────────────────────
    used_ts:  set[int] = set()
    cursor = int(base_time * 1_000_000)

    packets: list[SCTPStreamPacket] = []

    def emit(direction: str, raw: bytes, tsn: int, plen: int, label: str) -> None:
        nonlocal cursor
        cursor, ts_sec, ts_usec = _next_ts(cursor, inter_packet_gap, gap_jitter, used_ts, rng)
        packets.append(SCTPStreamPacket(
            raw=raw, ts_sec=ts_sec, ts_usec=ts_usec,
            direction=direction, tsn=tsn, payload_len=plen, label=label,
        ))

    def c2s(vtag: int, chunks: list, tsn: int = 0, plen: int = 0, label: str = "") -> None:
        raw = _build_sctp(
            src_ip=client_ip, dst_ip=server_ip,
            src_port=client_port, dst_port=server_port,
            src_mac=client_mac, dst_mac=server_mac,
            vtag=vtag, chunks=chunks,
            include_ethernet=include_ethernet, ip_ttl=ip_ttl,
            encap=encap,
        )
        emit("c2s", raw, tsn, plen, label)

    def s2c(vtag: int, chunks: list, tsn: int = 0, plen: int = 0, label: str = "") -> None:
        raw = _build_sctp(
            src_ip=server_ip, dst_ip=client_ip,
            src_port=server_port, dst_port=client_port,
            src_mac=server_mac, dst_mac=client_mac,
            vtag=vtag, chunks=chunks,
            include_ethernet=include_ethernet, ip_ttl=ip_ttl,
            encap=encap,
        )
        emit("s2c", raw, tsn, plen, label)

    # ── Handshake ─────────────────────────────────────────────────────────────

    # INIT: client → server, vtag=0 (RFC 9260 §3.3.2)
    c2s(vtag=0, chunks=[SCTPInitChunk(
        initiate_tag=client_vtag,
        a_rwnd=131072,
        outbound_streams=1,
        inbound_streams=1,
        initial_tsn=client_tsn,
    )], label="INIT")

    # INIT ACK: server → client, vtag=client_vtag
    # State Cookie parameter (RFC 9260 §3.3.3): Type=7, Length=4+len(cookie)
    # params must carry a fully-formed TLV, not raw bytes.
    cookie_param = struct.pack("!HH", 7, 4 + len(cookie)) + cookie
    if len(cookie_param) % 4:
        cookie_param += b"\x00" * (4 - len(cookie_param) % 4)
    s2c(vtag=client_vtag, chunks=[SCTPInitAckChunk(
        initiate_tag=server_vtag,
        a_rwnd=131072,
        outbound_streams=1,
        inbound_streams=1,
        initial_tsn=server_tsn,
        params=cookie_param,
    )], label="INIT-ACK")

    # COOKIE ECHO: client → server, vtag=server_vtag
    c2s(vtag=server_vtag, chunks=[SCTPCookieEchoChunk(cookie=cookie)],
        label="COOKIE-ECHO")

    # COOKIE ACK: server → client, vtag=client_vtag
    s2c(vtag=client_vtag, chunks=[SCTPCookieAckChunk()], label="COOKIE-ACK")

    # ── Data transfer ─────────────────────────────────────────────────────────
    cur_tsn = client_tsn
    for i in range(num_data_packets):
        chunk_data = payload_data[payload_offset:payload_offset + sizes[i]]
        payload_offset += sizes[i]

        # DATA: client → server
        c2s(vtag=server_vtag, chunks=[SCTPDataChunk(
            tsn=cur_tsn,
            stream_id=0,
            stream_seq=i & 0xFFFF,
            ppid=0,
            data=chunk_data,
            flags=SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING,
        )], tsn=cur_tsn, plen=len(chunk_data), label=f"DATA[{i}]")

        # SACK: server → client, acknowledges cur_tsn
        s2c(vtag=client_vtag, chunks=[SCTPSackChunk(
            cum_tsn_ack=cur_tsn,
            a_rwnd=131072,
        )], label=f"SACK[{i}]")

        cur_tsn = (cur_tsn + 1) % _WRAP

    # ── Shutdown (RFC 9260 §9.2) ──────────────────────────────────────────────

    # SHUTDOWN: client → server (cum_tsn_ack = 0, no server DATA received)
    c2s(vtag=server_vtag, chunks=[SCTPShutdownChunk(cum_tsn_ack=0)],
        label="SHUTDOWN")

    # SHUTDOWN ACK: server → client
    s2c(vtag=client_vtag, chunks=[SCTPShutdownAckChunk()],
        label="SHUTDOWN-ACK")

    # SHUTDOWN COMPLETE: client → server
    c2s(vtag=server_vtag, chunks=[SCTPShutdownCompleteChunk()],
        label="SHUTDOWN-COMPLETE")

    # ── Re-sort if jitter was applied ─────────────────────────────────────────
    if gap_jitter > 0:
        packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))

    # ── Middlebox fragmentation ───────────────────────────────────────────────
    if mtu is not None:
        used_ts = {_pkt_usec(p) for p in packets}
        fragmented: list[SCTPStreamPacket] = []
        for pkt in packets:
            fragmented.extend(_fragment_sctp_pkt(pkt, mtu, include_ethernet, used_ts, encap))
        packets = fragmented
        packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))

    return SCTPStream(packets=packets)
