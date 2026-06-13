r"""Session builders for creating realistic multi-packet flows.

:class:`TCPSession`, :class:`UDPSession`, and :class:`SCTPSession` let you
specify application-layer payloads via ``.send()`` / ``.recv()`` calls and
have all protocol machinery — handshakes, ACKs, sequence numbers, teardowns —
handled automatically.  ``.build()`` returns the same stream type as the
corresponding low-level generator, so all downstream code (``to_pcap_tuples``,
``write_pcap``, encapsulation) works unchanged.

Standalone helpers :func:`tcp_handshake`, :func:`tcp_teardown`, and
:func:`sctp_handshake` return pre-built packet lists for use with manual
:class:`~packeteer.generate.PacketBuilder`-based workflows.

Typical usage::

    from packeteer.generate import TCPSession, UDPSession, SCTPSession
    from packeteer.pcap import write_pcap

    # Bidirectional HTTP-style exchange
    stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=80)
        .send(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
        .recv(b"HTTP/1.1 200 OK\\r\\n\\r\\nHello")
        .build()
    )
    write_pcap(stream.to_pcap_tuples(), path="http.pcap")

    # Unidirectional log shipping over UDP
    stream = (UDPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=514)
        .send_many(5, lambda i: f"<134>event {i}\\n".encode())
        .build()
    )

    # DNS query/response over UDP
    stream = (UDPSession(client_ip="10.0.0.1", server_ip="8.8.8.8", server_port=53)
        .send(dns_query_bytes)
        .recv(dns_response_bytes)
        .build()
    )

"""
from __future__ import annotations

import random
import struct
import time
from collections.abc import Callable
from random import Random

from ._stream_common import _alloc_usec
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
from .sctp_stream import SCTPStream, SCTPStreamPacket, _build_sctp, _next_ts
from .stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
)
from .tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN
from .tcp_stream import (
    TCPStream,
    TCPStreamPacket,
    _advance_seq,
    _build_packet,
    _TCPEndpoint,
)
from .udp_stream import UDPStream, UDPStreamPacket, _build_udp_packet

_WRAP = 2 ** 32


# ── TCP ───────────────────────────────────────────────────────────────────────

class TCPSession:
    r"""Build a complete TCP stream by specifying application payloads.

    Call ``.send()`` and ``.recv()`` to describe the exchange, then call
    ``.build()`` to produce a :class:`~packeteer.generate.TCPStream` with
    the three-way handshake, data segments (MSS-segmented with PSH on the
    last segment of each exchange), ACKs, and four-way teardown all wired
    up automatically.

    Unidirectional streams — where only one side sends data — are expressed
    naturally: call only ``.send()`` (or only ``.recv()``) and the other
    side will emit pure ACKs.

    Example::

        stream = (TCPSession(
                client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=80)
            .send(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
            .recv(b"HTTP/1.1 200 OK\\r\\n\\r\\n" + b"x" * 4000)
            .build()
        )

    """

    def __init__(
        self,
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
        client_isn: int | None = None,
        server_isn: int | None = None,
        base_time: float | None = None,
        encap: EncapSpec = None,
    ) -> None:
        """Initialise a TCP session builder.

        Args:
            client_ip: Client IP address (IPv4 or IPv6).
            server_ip: Server IP address (same family as *client_ip*).
            client_port: Client source port.  Defaults to ``54321``.
            server_port: Server destination port.  Defaults to ``80``.
            client_mac: Client MAC address.
            server_mac: Server MAC address.
            mss: Maximum segment size used to split large payloads.
                Defaults to ``1460`` (typical Ethernet MSS for IPv4).
            include_ethernet: Include Ethernet II headers.  Defaults to
                ``True``.
            ip_ttl: IP TTL / hop limit.  Defaults to ``64``.
            inter_packet_gap: Seconds between consecutive packets.
                Defaults to ``0.001`` (1 ms).
            client_isn: Client initial sequence number.  Randomly chosen
                when ``None`` (default).
            server_isn: Server initial sequence number.  Randomly chosen
                when ``None`` (default).
            base_time: Unix timestamp for the first packet.  Defaults to
                the current time.
            encap: Encapsulation layer(s) to wrap every packet in.

        """
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.mss = mss
        self.include_ethernet = include_ethernet
        self.ip_ttl = ip_ttl
        self.inter_packet_gap = inter_packet_gap
        self.client_isn = client_isn
        self.server_isn = server_isn
        self.base_time = base_time
        self.encap = encap
        self._exchanges: list[tuple[str, bytes, str | None]] = []

    def send(self, data: bytes, label: str | None = None) -> TCPSession:
        """Queue *data* as a client→server payload.

        Args:
            data: Application bytes to send from client to server.
            label: Optional human-readable label for the resulting data
                segment(s) (e.g. ``"GET /api/v1/orders/42"``).  When omitted, a
                generic ``"DATA[i]"`` label is used.

        Returns:
            ``self``, for chaining.

        """
        self._exchanges.append(("c2s", data, label))
        return self

    def recv(self, data: bytes, label: str | None = None) -> TCPSession:
        """Queue *data* as a server→client payload.

        Args:
            data: Application bytes to send from server to client.
            label: Optional human-readable label for the resulting data
                segment(s) (e.g. ``"200 OK"``).  When omitted, a generic
                ``"DATA[i]"`` label is used.

        Returns:
            ``self``, for chaining.

        """
        self._exchanges.append(("s2c", data, label))
        return self

    def send_many(self, n: int, payload_fn: Callable[[int], bytes]) -> TCPSession:
        """Queue *n* client→server payloads produced by *payload_fn*.

        Args:
            n: Number of exchanges to queue.
            payload_fn: Callable ``(index) -> bytes`` called for each
                exchange, where *index* counts from ``0`` within this call.

        Returns:
            ``self``, for chaining.

        """
        for i in range(n):
            self._exchanges.append(("c2s", payload_fn(i), None))
        return self

    def recv_many(self, n: int, payload_fn: Callable[[int], bytes]) -> TCPSession:
        """Queue *n* server→client payloads produced by *payload_fn*.

        Args:
            n: Number of exchanges to queue.
            payload_fn: Callable ``(index) -> bytes`` called for each
                exchange, where *index* counts from ``0`` within this call.

        Returns:
            ``self``, for chaining.

        """
        for i in range(n):
            self._exchanges.append(("s2c", payload_fn(i), None))
        return self

    def build(self) -> TCPStream:
        """Assemble and return the complete :class:`~packeteer.generate.TCPStream`.

        The returned stream contains the three-way handshake, all data
        segments with correct sequence numbers and ACKs, and the four-way
        teardown.  Large payloads are split into MSS-sized segments; PSH
        is set on the last segment of each exchange.

        Returns:
            A :class:`~packeteer.generate.TCPStream` ready for pcap output.

        """
        base_usec = int((self.base_time if self.base_time is not None
                         else time.time()) * 1_000_000)
        gap_usec = int(self.inter_packet_gap * 1_000_000)

        client = _TCPEndpoint(
            ip=self.client_ip, port=self.client_port, mac=self.client_mac,
            seq=random.randint(0, _WRAP - 1) if self.client_isn is None
                else self.client_isn,
            ack=0, window=65535,
        )
        server = _TCPEndpoint(
            ip=self.server_ip, port=self.server_port, mac=self.server_mac,
            seq=random.randint(0, _WRAP - 1) if self.server_isn is None
                else self.server_isn,
            ack=0, window=65535,
        )

        packets: list[TCPStreamPacket] = []
        index = 0

        def emit(
            src: _TCPEndpoint,
            dst: _TCPEndpoint,
            flags: int,
            payload: bytes,
            direction: str,
            label: str,
        ) -> None:
            nonlocal index
            seq_before = src.seq
            ack_before = src.ack
            raw = _build_packet(src, dst, flags, payload,
                                self.include_ethernet, self.ip_ttl, None, self.encap)
            _advance_seq(src, flags, len(payload))
            dst.ack = src.seq
            ts_sec, ts_usec = divmod(base_usec + index * gap_usec, 1_000_000)
            packets.append(TCPStreamPacket(
                raw=raw, ts_sec=ts_sec, ts_usec=ts_usec,
                direction=direction, flags=flags,
                seq=seq_before,
                ack=ack_before if (flags & TCP_ACK) else 0,
                payload_len=len(payload), label=label,
            ))
            index += 1

        # Three-way handshake
        emit(client, server, TCP_SYN,           b"", "c2s", "SYN")
        emit(server, client, TCP_SYN | TCP_ACK, b"", "s2c", "SYN-ACK")
        emit(client, server, TCP_ACK,           b"", "c2s", "ACK")

        # Data exchanges
        seg_idx = 0
        for direction, payload, label in self._exchanges:
            if direction == "c2s":
                sender, receiver, send_dir, ack_dir = client, server, "c2s", "s2c"
            else:
                sender, receiver, send_dir, ack_dir = server, client, "s2c", "c2s"

            segments = ([b""] if not payload
                        else [payload[i:i + self.mss]
                              for i in range(0, len(payload), self.mss)])

            for seg_num, chunk in enumerate(segments):
                is_last = seg_num == len(segments) - 1
                flags = TCP_ACK | TCP_PSH if is_last else TCP_ACK
                if label is None:
                    seg_label = f"DATA[{seg_idx}]"
                elif len(segments) == 1:
                    seg_label = label
                else:
                    seg_label = f"{label} [{seg_num + 1}/{len(segments)}]"
                emit(sender, receiver, flags, chunk, send_dir, seg_label)
                emit(receiver, sender, TCP_ACK, b"", ack_dir, f"ACK[{seg_idx}]")
                seg_idx += 1

        # Four-way teardown
        emit(client, server, TCP_FIN | TCP_ACK, b"", "c2s", "FIN-ACK")
        emit(server, client, TCP_ACK,           b"", "s2c", "ACK")
        emit(server, client, TCP_FIN | TCP_ACK, b"", "s2c", "FIN-ACK")
        emit(client, server, TCP_ACK,           b"", "c2s", "ACK")

        return TCPStream(packets=packets)


# ── UDP ───────────────────────────────────────────────────────────────────────

class UDPSession:
    r"""Build a UDP stream by specifying application payloads.

    Call ``.send()`` and ``.recv()`` to describe the exchange, then call
    ``.build()`` to produce a :class:`~packeteer.generate.UDPStream`.
    Unlike TCP, UDP has no connection state — datagrams are emitted in the
    order they are queued.

    Example::

        # DNS query/response
        stream = (UDPSession(
                client_ip="10.0.0.1", server_ip="8.8.8.8", server_port=53)
            .send(dns_query_bytes)
            .recv(dns_response_bytes)
            .build()
        )

        # Unidirectional syslog
        stream = (UDPSession(
                client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=514)
            .send_many(100, lambda i: f"<134>event {i}\\n".encode())
            .build()
        )

    """

    def __init__(
        self,
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
    ) -> None:
        """Initialise a UDP session builder.

        Args:
            client_ip: Client IP address (IPv4 or IPv6).
            server_ip: Server IP address (same family as *client_ip*).
            client_port: Client source port.  Defaults to ``54321``.
            server_port: Server destination port.  Defaults to ``80``.
            client_mac: Client MAC address.
            server_mac: Server MAC address.
            include_ethernet: Include Ethernet II headers.  Defaults to
                ``True``.
            ip_ttl: IP TTL / hop limit.  Defaults to ``64``.
            inter_packet_gap: Seconds between consecutive datagrams.
                Defaults to ``0.001`` (1 ms).
            base_time: Unix timestamp for the first datagram.  Defaults to
                the current time.
            encap: Encapsulation layer(s) to wrap every packet in.

        """
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.include_ethernet = include_ethernet
        self.ip_ttl = ip_ttl
        self.inter_packet_gap = inter_packet_gap
        self.base_time = base_time
        self.encap = encap
        self._exchanges: list[tuple[str, bytes, str | None]] = []

    def send(self, data: bytes, label: str | None = None) -> UDPSession:
        """Queue *data* as a client→server datagram.

        Args:
            data: Payload bytes to send from client to server.
            label: Optional human-readable label for the datagram; a generic
                ``"DATA[i]"`` label is used when omitted.

        Returns:
            ``self``, for chaining.

        """
        self._exchanges.append(("c2s", data, label))
        return self

    def recv(self, data: bytes, label: str | None = None) -> UDPSession:
        """Queue *data* as a server→client datagram.

        Args:
            data: Payload bytes to send from server to client.
            label: Optional human-readable label for the datagram; a generic
                ``"DATA[i]"`` label is used when omitted.

        Returns:
            ``self``, for chaining.

        """
        self._exchanges.append(("s2c", data, label))
        return self

    def send_many(self, n: int, payload_fn: Callable[[int], bytes]) -> UDPSession:
        """Queue *n* client→server datagrams produced by *payload_fn*.

        Args:
            n: Number of datagrams to queue.
            payload_fn: Callable ``(index) -> bytes``.

        Returns:
            ``self``, for chaining.

        """
        for i in range(n):
            self._exchanges.append(("c2s", payload_fn(i), None))
        return self

    def recv_many(self, n: int, payload_fn: Callable[[int], bytes]) -> UDPSession:
        """Queue *n* server→client datagrams produced by *payload_fn*.

        Args:
            n: Number of datagrams to queue.
            payload_fn: Callable ``(index) -> bytes``.

        Returns:
            ``self``, for chaining.

        """
        for i in range(n):
            self._exchanges.append(("s2c", payload_fn(i), None))
        return self

    def build(self) -> UDPStream:
        """Assemble and return the complete :class:`~packeteer.generate.UDPStream`.

        Returns:
            A :class:`~packeteer.generate.UDPStream` ready for pcap output.

        """
        usec_cursor = int((self.base_time if self.base_time is not None
                           else time.time()) * 1_000_000)
        gap_usec = int(self.inter_packet_gap * 1_000_000)
        used_ts: set[int] = set()
        packets: list[UDPStreamPacket] = []

        for i, (direction, payload, label) in enumerate(self._exchanges):
            usec_cursor += gap_usec
            ts = _alloc_usec(usec_cursor, used_ts)

            if direction == "c2s":
                src_ip, dst_ip = self.client_ip, self.server_ip
                src_port, dst_port = self.client_port, self.server_port
                src_mac, dst_mac = self.client_mac, self.server_mac
            else:
                src_ip, dst_ip = self.server_ip, self.client_ip
                src_port, dst_port = self.server_port, self.client_port
                src_mac, dst_mac = self.server_mac, self.client_mac

            raw = _build_udp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                src_mac=src_mac, dst_mac=dst_mac,
                payload=payload,
                include_ethernet=self.include_ethernet,
                ip_ttl=self.ip_ttl,
                encap=self.encap,
            )
            packets.append(UDPStreamPacket(
                raw=raw,
                ts_sec=ts // 1_000_000,
                ts_usec=ts % 1_000_000,
                direction=direction,
                payload_len=len(payload),
                label=label if label is not None else f"DATA[{i}]",
            ))

        return UDPStream(packets=packets)


# ── SCTP ──────────────────────────────────────────────────────────────────────

class SCTPSession:
    """Build a complete SCTP association by specifying application payloads.

    Call ``.send()`` and ``.recv()`` to describe the data exchange, then
    call ``.build()`` to produce a :class:`~packeteer.generate.SCTPStream`
    with the four-way handshake, DATA chunks (with SACKs), and graceful
    shutdown all handled automatically.

    Example::

        # Bidirectional exchange
        stream = (SCTPSession(
                client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=36412)
            .send(s1ap_setup_request)
            .recv(s1ap_setup_response)
            .build()
        )

        # Unidirectional upload
        stream = (SCTPSession(
                client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=9000)
            .send_many(10, lambda i: f"record {i}".encode())
            .build()
        )

    """

    def __init__(
        self,
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
    ) -> None:
        """Initialise an SCTP session builder.

        Args:
            client_ip: Client IP address (IPv4 or IPv6).
            server_ip: Server IP address (same family as *client_ip*).
            client_port: Client SCTP source port.  Defaults to ``54321``.
            server_port: Server SCTP destination port.  Defaults to ``80``.
            client_mac: Client MAC address.
            server_mac: Server MAC address.
            include_ethernet: Include Ethernet II headers.  Defaults to
                ``True``.
            ip_ttl: IP TTL / hop limit.  Defaults to ``64``.
            inter_packet_gap: Seconds between consecutive packets.
                Defaults to ``0.001`` (1 ms).
            base_time: Unix timestamp for the first packet.  Defaults to
                the current time.
            encap: Encapsulation layer(s) to wrap every packet in.

        """
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.include_ethernet = include_ethernet
        self.ip_ttl = ip_ttl
        self.inter_packet_gap = inter_packet_gap
        self.base_time = base_time
        self.encap = encap
        self._exchanges: list[tuple[str, bytes]] = []

    def send(self, data: bytes) -> SCTPSession:
        """Queue *data* as a client→server DATA chunk.

        Args:
            data: Payload bytes to send from client to server.

        Returns:
            ``self``, for chaining.

        """
        self._exchanges.append(("c2s", data))
        return self

    def recv(self, data: bytes) -> SCTPSession:
        """Queue *data* as a server→client DATA chunk.

        Args:
            data: Payload bytes to send from server to client.

        Returns:
            ``self``, for chaining.

        """
        self._exchanges.append(("s2c", data))
        return self

    def send_many(self, n: int, payload_fn: Callable[[int], bytes]) -> SCTPSession:
        """Queue *n* client→server DATA chunks produced by *payload_fn*.

        Args:
            n: Number of exchanges to queue.
            payload_fn: Callable ``(index) -> bytes``.

        Returns:
            ``self``, for chaining.

        """
        for i in range(n):
            self._exchanges.append(("c2s", payload_fn(i)))
        return self

    def recv_many(self, n: int, payload_fn: Callable[[int], bytes]) -> SCTPSession:
        """Queue *n* server→client DATA chunks produced by *payload_fn*.

        Args:
            n: Number of exchanges to queue.
            payload_fn: Callable ``(index) -> bytes``.

        Returns:
            ``self``, for chaining.

        """
        for i in range(n):
            self._exchanges.append(("s2c", payload_fn(i)))
        return self

    def build(self) -> SCTPStream:
        """Assemble and return the complete :class:`~packeteer.generate.SCTPStream`.

        The returned stream contains the four-way SCTP handshake, all DATA
        chunks with correct TSNs and SACKs, and the graceful shutdown
        sequence.  Verification tags and TSNs are chosen at random per
        RFC 9260.

        Returns:
            A :class:`~packeteer.generate.SCTPStream` ready for pcap output.

        """
        client_vtag = random.randint(1, 0xFFFFFFFF)
        server_vtag = random.randint(1, 0xFFFFFFFF)
        client_tsn  = random.randint(0, 0xFFFFFFFF)
        server_tsn  = random.randint(0, 0xFFFFFFFF)
        cookie = bytes(random.getrandbits(8) for _ in range(16))

        used_ts: set[int] = set()
        cursor = int((self.base_time if self.base_time is not None
                      else time.time()) * 1_000_000)
        packets: list[SCTPStreamPacket] = []
        _rng = Random()

        def emit(direction: str, raw: bytes,
                 tsn: int, plen: int, label: str) -> None:
            nonlocal cursor
            cursor, ts_sec, ts_usec = _next_ts(
                cursor, self.inter_packet_gap, 0.0, used_ts, _rng)
            packets.append(SCTPStreamPacket(
                raw=raw, ts_sec=ts_sec, ts_usec=ts_usec,
                direction=direction, tsn=tsn, payload_len=plen, label=label,
            ))

        def c2s(vtag: int, chunks: list,
                tsn: int = 0, plen: int = 0, label: str = "") -> None:
            raw = _build_sctp(
                src_ip=self.client_ip, dst_ip=self.server_ip,
                src_port=self.client_port, dst_port=self.server_port,
                src_mac=self.client_mac, dst_mac=self.server_mac,
                vtag=vtag, chunks=chunks,
                include_ethernet=self.include_ethernet,
                ip_ttl=self.ip_ttl, encap=self.encap,
            )
            emit("c2s", raw, tsn, plen, label)

        def s2c(vtag: int, chunks: list,
                tsn: int = 0, plen: int = 0, label: str = "") -> None:
            raw = _build_sctp(
                src_ip=self.server_ip, dst_ip=self.client_ip,
                src_port=self.server_port, dst_port=self.client_port,
                src_mac=self.server_mac, dst_mac=self.client_mac,
                vtag=vtag, chunks=chunks,
                include_ethernet=self.include_ethernet,
                ip_ttl=self.ip_ttl, encap=self.encap,
            )
            emit("s2c", raw, tsn, plen, label)

        # Four-way handshake
        c2s(vtag=0, chunks=[SCTPInitChunk(
            initiate_tag=client_vtag, a_rwnd=131072,
            outbound_streams=1, inbound_streams=1, initial_tsn=client_tsn,
        )], label="INIT")

        cookie_param = struct.pack("!HH", 7, 4 + len(cookie)) + cookie
        if len(cookie_param) % 4:
            cookie_param += b"\x00" * (4 - len(cookie_param) % 4)
        s2c(vtag=client_vtag, chunks=[SCTPInitAckChunk(
            initiate_tag=server_vtag, a_rwnd=131072,
            outbound_streams=1, inbound_streams=1, initial_tsn=server_tsn,
            params=cookie_param,
        )], label="INIT-ACK")

        c2s(vtag=server_vtag,
            chunks=[SCTPCookieEchoChunk(cookie=cookie)], label="COOKIE-ECHO")
        s2c(vtag=client_vtag,
            chunks=[SCTPCookieAckChunk()], label="COOKIE-ACK")

        # Data exchanges
        cur_client_tsn = client_tsn
        cur_server_tsn = server_tsn
        for exc_idx, (direction, payload) in enumerate(self._exchanges):
            seq = exc_idx & 0xFFFF
            if direction == "c2s":
                c2s(vtag=server_vtag, chunks=[SCTPDataChunk(
                    tsn=cur_client_tsn, stream_id=0, stream_seq=seq, ppid=0,
                    data=payload,
                    flags=SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING,
                )], tsn=cur_client_tsn, plen=len(payload),
                    label=f"DATA[{exc_idx}]")
                s2c(vtag=client_vtag, chunks=[SCTPSackChunk(
                    cum_tsn_ack=cur_client_tsn, a_rwnd=131072,
                )], label=f"SACK[{exc_idx}]")
                cur_client_tsn = (cur_client_tsn + 1) % _WRAP
            else:
                s2c(vtag=client_vtag, chunks=[SCTPDataChunk(
                    tsn=cur_server_tsn, stream_id=0, stream_seq=seq, ppid=0,
                    data=payload,
                    flags=SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING,
                )], tsn=cur_server_tsn, plen=len(payload),
                    label=f"DATA[{exc_idx}]")
                c2s(vtag=server_vtag, chunks=[SCTPSackChunk(
                    cum_tsn_ack=cur_server_tsn, a_rwnd=131072,
                )], label=f"SACK[{exc_idx}]")
                cur_server_tsn = (cur_server_tsn + 1) % _WRAP

        # Graceful shutdown
        c2s(vtag=server_vtag,
            chunks=[SCTPShutdownChunk(cum_tsn_ack=0)], label="SHUTDOWN")
        s2c(vtag=client_vtag,
            chunks=[SCTPShutdownAckChunk()], label="SHUTDOWN-ACK")
        c2s(vtag=server_vtag,
            chunks=[SCTPShutdownCompleteChunk()], label="SHUTDOWN-COMPLETE")

        return SCTPStream(packets=packets)


# ── Standalone handshake helpers ──────────────────────────────────────────────

def tcp_handshake(
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    client_isn: int | None = None,
    server_isn: int | None = None,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    encap: EncapSpec = None,
) -> list[bytes]:
    """Return the three raw packets of a TCP three-way handshake.

    Returns ``[SYN, SYN-ACK, ACK]`` as fully-assembled byte strings with
    correct checksums.  Useful for manual packet-sequence construction; for
    full flows with correct seq/ack tracking, use :class:`TCPSession`
    instead.

    Args:
        client_ip: Client IP address (IPv4 or IPv6).
        server_ip: Server IP address.
        client_port: Client source port.  Defaults to ``54321``.
        server_port: Server destination port.  Defaults to ``80``.
        client_mac: Client MAC address.
        server_mac: Server MAC address.
        client_isn: Client initial sequence number.  Randomly chosen when
            ``None`` (default).
        server_isn: Server initial sequence number.  Randomly chosen when
            ``None`` (default).
        include_ethernet: Include Ethernet II headers.  Defaults to ``True``.
        ip_ttl: IP TTL / hop limit.  Defaults to ``64``.
        encap: Encapsulation layer(s) to wrap every packet in.

    Returns:
        ``[SYN, SYN-ACK, ACK]`` — three :class:`bytes` objects.

    """
    client = _TCPEndpoint(
        ip=client_ip, port=client_port, mac=client_mac,
        seq=random.randint(0, _WRAP - 1) if client_isn is None else client_isn,
        ack=0, window=65535,
    )
    server = _TCPEndpoint(
        ip=server_ip, port=server_port, mac=server_mac,
        seq=random.randint(0, _WRAP - 1) if server_isn is None else server_isn,
        ack=0, window=65535,
    )
    result: list[bytes] = []
    for src, dst, flags in [
        (client, server, TCP_SYN),
        (server, client, TCP_SYN | TCP_ACK),
        (client, server, TCP_ACK),
    ]:
        raw = _build_packet(src, dst, flags, b"",
                            include_ethernet, ip_ttl, None, encap)
        _advance_seq(src, flags, 0)
        dst.ack = src.seq
        result.append(raw)
    return result


def tcp_teardown(
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    client_seq: int = 0,
    client_ack: int = 0,
    server_seq: int = 0,
    server_ack: int = 0,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    encap: EncapSpec = None,
) -> list[bytes]:
    """Return the four raw packets of a TCP four-way teardown.

    Returns ``[FIN-ACK (c2s), ACK (s2c), FIN-ACK (s2c), ACK (c2s)]``.

    *client_seq*, *client_ack*, *server_seq*, and *server_ack* should
    reflect the TCP state at the moment the connection is closed.  When
    building a full session manually, read these from the last data packet.
    For :class:`TCPSession`-based flows the teardown is included in
    ``.build()`` automatically and this function is not needed.

    Args:
        client_ip: Client IP address (IPv4 or IPv6).
        server_ip: Server IP address.
        client_port: Client source port.  Defaults to ``54321``.
        server_port: Server destination port.  Defaults to ``80``.
        client_mac: Client MAC address.
        server_mac: Server MAC address.
        client_seq: Client TCP sequence number at teardown time.
        client_ack: Client TCP acknowledgement number at teardown time.
        server_seq: Server TCP sequence number at teardown time.
        server_ack: Server TCP acknowledgement number at teardown time.
        include_ethernet: Include Ethernet II headers.  Defaults to ``True``.
        ip_ttl: IP TTL / hop limit.  Defaults to ``64``.
        encap: Encapsulation layer(s) to wrap every packet in.

    Returns:
        ``[FIN-ACK, ACK, FIN-ACK, ACK]`` — four :class:`bytes` objects.

    """
    client = _TCPEndpoint(
        ip=client_ip, port=client_port, mac=client_mac,
        seq=client_seq, ack=client_ack, window=65535,
    )
    server = _TCPEndpoint(
        ip=server_ip, port=server_port, mac=server_mac,
        seq=server_seq, ack=server_ack, window=65535,
    )
    result: list[bytes] = []
    for src, dst, flags in [
        (client, server, TCP_FIN | TCP_ACK),
        (server, client, TCP_ACK),
        (server, client, TCP_FIN | TCP_ACK),
        (client, server, TCP_ACK),
    ]:
        raw = _build_packet(src, dst, flags, b"",
                            include_ethernet, ip_ttl, None, encap)
        _advance_seq(src, flags, 0)
        dst.ack = src.seq
        result.append(raw)
    return result


def sctp_handshake(
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    encap: EncapSpec = None,
) -> list[bytes]:
    """Return the four raw packets of an SCTP four-way handshake.

    Returns ``[INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK]`` as
    fully-assembled byte strings with correct CRC-32c checksums.
    Verification tags and the state cookie are chosen at random per
    RFC 9260.

    Args:
        client_ip: Client IP address (IPv4 or IPv6).
        server_ip: Server IP address.
        client_port: Client SCTP source port.  Defaults to ``54321``.
        server_port: Server SCTP destination port.  Defaults to ``80``.
        client_mac: Client MAC address.
        server_mac: Server MAC address.
        include_ethernet: Include Ethernet II headers.  Defaults to ``True``.
        ip_ttl: IP TTL / hop limit.  Defaults to ``64``.
        encap: Encapsulation layer(s) to wrap every packet in.

    Returns:
        ``[INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK]`` — four
        :class:`bytes` objects.

    """
    client_vtag = random.randint(1, 0xFFFFFFFF)
    server_vtag = random.randint(1, 0xFFFFFFFF)
    client_tsn  = random.randint(0, 0xFFFFFFFF)
    server_tsn  = random.randint(0, 0xFFFFFFFF)
    cookie = bytes(random.getrandbits(8) for _ in range(16))

    kw: dict[str, object] = {
        "include_ethernet": include_ethernet, "ip_ttl": ip_ttl, "encap": encap,
    }

    init = _build_sctp(
        src_ip=client_ip, dst_ip=server_ip,
        src_port=client_port, dst_port=server_port,
        src_mac=client_mac, dst_mac=server_mac,
        vtag=0, chunks=[SCTPInitChunk(
            initiate_tag=client_vtag, a_rwnd=131072,
            outbound_streams=1, inbound_streams=1, initial_tsn=client_tsn,
        )], **kw,  # type: ignore[arg-type]
    )

    cookie_param = struct.pack("!HH", 7, 4 + len(cookie)) + cookie
    if len(cookie_param) % 4:
        cookie_param += b"\x00" * (4 - len(cookie_param) % 4)
    init_ack = _build_sctp(
        src_ip=server_ip, dst_ip=client_ip,
        src_port=server_port, dst_port=client_port,
        src_mac=server_mac, dst_mac=client_mac,
        vtag=client_vtag, chunks=[SCTPInitAckChunk(
            initiate_tag=server_vtag, a_rwnd=131072,
            outbound_streams=1, inbound_streams=1, initial_tsn=server_tsn,
            params=cookie_param,
        )], **kw,  # type: ignore[arg-type]
    )

    cookie_echo = _build_sctp(
        src_ip=client_ip, dst_ip=server_ip,
        src_port=client_port, dst_port=server_port,
        src_mac=client_mac, dst_mac=server_mac,
        vtag=server_vtag, chunks=[SCTPCookieEchoChunk(cookie=cookie)],
        **kw,  # type: ignore[arg-type]
    )

    cookie_ack = _build_sctp(
        src_ip=server_ip, dst_ip=client_ip,
        src_port=server_port, dst_port=client_port,
        src_mac=server_mac, dst_mac=client_mac,
        vtag=client_vtag, chunks=[SCTPCookieAckChunk()],
        **kw,  # type: ignore[arg-type]
    )

    return [init, init_ack, cookie_echo, cookie_ack]
