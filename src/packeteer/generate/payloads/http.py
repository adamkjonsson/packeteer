"""Randomly generate HTTP/1.1 REST client traffic.

:func:`generate_http_stream` simulates a client exercising a REST API: it
fabricates random but plausible request/response exchanges (varied methods,
resource paths, query strings, headers, and JSON bodies) and renders them onto
one or more TCP connections, returning a merged
:class:`~packeteer.generate.session_mix.CombinedStream`.

The generated traffic is cleartext HTTP/1.1 and round-trips through packeteer's
own HTTP parser.  Two knobs shape the connection layout: *requests* (total
transactions) and *requests_per_connection* (``1`` = a new connection per
request; larger = keep-alive connections carrying several transactions).

Responses are framed with ``Content-Length`` by default.  Set
:attr:`HTTPRestConfig.chunked_rate` to frame a proportion of them with
``Transfer-Encoding: chunked`` instead — HTTP/1.1's other framing mechanism,
and the one a decoder is more likely to get wrong, since the body's extent is
discovered by walking size lines rather than read from a header.
"""
from __future__ import annotations

import json
import math
import random
import time
from collections.abc import Callable
from dataclasses import dataclass

from ..http import HTTPRequest, HTTPResponse, encode_http_message
from ..impairments import FlowEndpoints, ImpairmentConfig, apply_impairments
from ..session_mix import CombinedStream, _assign_endpoints, merge_streams
from ..stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
)
from ..tcp_stream import TCPStream, TCPStreamPacket
from .base import AppMessage, render_tcp_session

_WRAP = 2 ** 32

# Methods, weighted toward reads, that the simulated client issues.
_METHODS: tuple[str, ...] = (
    "GET", "GET", "GET", "GET", "POST", "POST", "PUT", "PATCH", "DELETE",
)
_RESOURCES: tuple[str, ...] = (
    "users", "orders", "products", "items", "sessions", "accounts",
    "invoices", "payments", "carts", "reviews", "tickets", "messages",
)
_HOSTS: tuple[str, ...] = (
    "api.example.com", "api.acme.test", "rest.internal", "svc.example.net",
)
_USER_AGENTS: tuple[str, ...] = (
    "curl/8.5.0",
    "python-requests/2.31.0",
    "PostmanRuntime/7.36.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "okhttp/4.12.0",
)
_SERVERS: tuple[str, ...] = ("nginx", "Apache", "gunicorn/21.2.0", "Kestrel", "Werkzeug/3.0.1")
_NOUNS: tuple[str, ...] = (
    "alpha", "bravo", "delta", "orion", "nova", "atlas", "vega", "lyra", "echo", "zephyr",
)
_ERROR_STATUSES: tuple[tuple[int, str], ...] = (
    (400, "Bad Request"), (401, "Unauthorized"), (403, "Forbidden"),
    (404, "Not Found"), (409, "Conflict"), (422, "Unprocessable Entity"),
    (500, "Internal Server Error"), (503, "Service Unavailable"),
)

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

#: Trailer fields sent after a chunked body when trailers are enabled.  Each
#: entry is (name, value factory); these are all fields RFC 7230 4.4 permits
#: to be deferred, since they are only knowable once the body has been sent.
_TRAILERS: tuple[tuple[str, Callable[[random.Random], str]], ...] = (
    ("Server-Timing", lambda rng: f"db;dur={rng.randint(1, 400)}"),
    ("X-Content-Digest", lambda rng: f"sha256={_token(rng, 32)}"),
    ("Expires", lambda rng: "Mon, 01 Jan 2024 13:00:00 GMT"),
)


@dataclass
class HTTPRestConfig:
    """Content and impairment knobs for :func:`generate_http_stream`.

    Carried as one object rather than as further arguments, the way
    :class:`~packeteer.generate.tcp_stream.TCPStreamConfig` is on the
    low-level path.

    Attributes:
        methods: Pool of HTTP methods drawn from (with repeats acting as
            weights) for each request.
        resources: REST resource names used to build paths.
        hosts: Candidate ``Host`` header values.
        base_path: Path prefix prepended to every resource (e.g. ``"/api/v1"``).
        error_rate: Probability (0.0–1.0) that a response is a 4xx/5xx error
            rather than a success correlated to the request method.
        chunked_rate: Probability (0.0–1.0) that a response *with a body* is
            framed with ``Transfer-Encoding: chunked`` instead of
            ``Content-Length``.  Defaults to ``0.0`` (every response counted).
        chunk_size: ``(min, max)`` bytes per chunk, before the last.  Sizes are
            drawn uniformly from this range, so the default of ``(8, 32)``
            splits the generated JSON bodies into several chunks — a
            single-chunk body does not distinguish a decoder that walks the
            size lines from one that reads to the end.  Raise it for larger
            bodies.
        trailer_rate: Probability (0.0–1.0) that a chunked body is followed by
            a trailer section, announced by a ``Trailer`` header.  Legal per
            RFC 7230 4.4 and widely forgotten by decoders.  Defaults to
            ``0.0``.  Has no effect unless *chunked_rate* is non-zero.
        impairments: Wire impairments
            (:class:`~packeteer.generate.impairments.ImpairmentConfig`) applied
            to each connection independently, so a lost segment or a RST
            affects one connection rather than reaching across the capture.
            ``None`` (the default) leaves the traffic clean and draws no
            randomness, so a capture generated without impairments still
            reproduces from its seed exactly as it did before impairments were
            available.

    """

    methods: tuple[str, ...] = _METHODS
    resources: tuple[str, ...] = _RESOURCES
    hosts: tuple[str, ...] = _HOSTS
    base_path: str = "/api/v1"
    error_rate: float = 0.1
    chunked_rate: float = 0.0
    chunk_size: tuple[int, int] = (8, 32)
    trailer_rate: float = 0.0
    impairments: ImpairmentConfig | None = None


def _token(rng: random.Random, length: int = 16) -> str:
    """Return a random lowercase-hex token."""
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def _random_json(rng: random.Random) -> bytes:
    """Return a small plausible JSON object as bytes."""
    obj = {
        "id": rng.randint(1, 99_999),
        "name": f"{rng.choice(_NOUNS)}-{rng.randint(1, 999)}",
        "amount": round(rng.uniform(1.0, 1000.0), 2),
        "active": rng.choice([True, False]),
    }
    return json.dumps(obj).encode("utf-8")


def _request_path(rng: random.Random, config: HTTPRestConfig, method: str) -> str:
    """Build a REST path (collection for POST, item otherwise) with optional query."""
    resource = rng.choice(config.resources)
    if method == "POST" or (method == "GET" and rng.random() < 0.4):
        path = f"{config.base_path}/{resource}"          # collection
    else:
        path = f"{config.base_path}/{resource}/{rng.randint(1, 99_999)}"   # item
    if method == "GET" and rng.random() < 0.5:
        params = []
        if rng.random() < 0.7:
            params.append(f"page={rng.randint(1, 50)}")
        if rng.random() < 0.7:
            params.append(f"limit={rng.choice([10, 20, 50, 100])}")
        if rng.random() < 0.3:
            params.append(f"sort={rng.choice(['asc', 'desc'])}")
        if params:
            path += "?" + "&".join(params)
    return path


def _request_headers(
    rng: random.Random, host: str, has_body: bool, keepalive: bool,
) -> dict[str, str]:
    """Build a plausible request header set."""
    headers = {
        "Host": host,
        "User-Agent": rng.choice(_USER_AGENTS),
        "Accept": "application/json",
    }
    if has_body:
        headers["Content-Type"] = "application/json"
    if rng.random() < 0.5:
        headers["Authorization"] = f"Bearer {_token(rng, 24)}"
    headers["Connection"] = "keep-alive" if keepalive else "close"
    return headers


def _response_headers(rng: random.Random, has_body: bool, keepalive: bool) -> dict[str, str]:
    """Build a plausible response header set."""
    headers = {
        "Server": rng.choice(_SERVERS),
        "Date": "Mon, 01 Jan 2024 12:00:00 GMT",
    }
    if has_body:
        headers["Content-Type"] = "application/json"
    headers["Connection"] = "keep-alive" if keepalive else "close"
    return headers


def _pick_status(rng: random.Random, method: str, error_rate: float) -> tuple[int, str]:
    """Return a (status_code, reason) correlated to *method*, or an error."""
    if rng.random() < error_rate:
        return rng.choice(_ERROR_STATUSES)
    if method == "POST":
        return (201, "Created")
    if method == "DELETE":
        return (204, "No Content")
    if method in ("PUT", "PATCH"):
        return rng.choice([(200, "OK"), (204, "No Content")])
    return (200, "OK")


def _chunk_body(
    body: bytes,
    rng: random.Random,
    chunk_size: tuple[int, int],
    trailers: dict[str, str],
) -> bytes:
    """Frame *body* as an HTTP/1.1 chunked message body (RFC 7230 4.1).

    Each chunk is a hex size line, the chunk data, and CRLF; the body ends
    with a zero-size chunk, an optional trailer section, and a final CRLF.
    Chunk sizes are drawn from *chunk_size*, so a body longer than the maximum
    is split across several chunks.

    Args:
        body: The payload bytes to frame.
        rng: Seeded random generator, used for the chunk sizes.
        chunk_size: ``(min, max)`` bytes per chunk, before the last.
        trailers: Trailer fields to emit after the terminating chunk.  Empty
            for no trailer section.

    Returns:
        The chunk-framed body, ready to be used as
        :attr:`~packeteer.generate.http.HTTPResponse.body` alongside a
        ``Transfer-Encoding: chunked`` header.

    """
    low, high = chunk_size
    out = bytearray()
    pos = 0
    while pos < len(body):
        size = min(rng.randint(low, high), len(body) - pos)
        out += f"{size:x}\r\n".encode("latin-1")
        out += body[pos:pos + size]
        out += b"\r\n"
        pos += size
    out += b"0\r\n"
    for name, value in trailers.items():
        out += f"{name}: {value}\r\n".encode("latin-1")
    out += b"\r\n"
    return bytes(out)


def _pick_trailers(rng: random.Random) -> dict[str, str]:
    """Return one or two trailer fields drawn from :data:`_TRAILERS`."""
    chosen = rng.sample(_TRAILERS, rng.randint(1, 2))
    return {name: make(rng) for name, make in chosen}


def generate_http_conversation(
    rng: random.Random, *, transactions: int, keepalive: bool, config: HTTPRestConfig,
) -> list[AppMessage]:
    """Generate one connection's worth of request/response exchanges.

    Args:
        rng: Seeded random generator (drives all content choices).
        transactions: Number of request/response pairs in this connection.
        keepalive: Whether the connection persists between transactions.  When
            ``True``, every request but the last advertises ``keep-alive``; the
            last advertises ``close``.
        config: Content knobs.

    Returns:
        An ordered list of :class:`~packeteer.generate.payloads.base.AppMessage`
        alternating client requests and server responses.

    """
    messages: list[AppMessage] = []
    host = rng.choice(config.hosts)
    for txn in range(transactions):
        persist = keepalive and txn < transactions - 1
        method = rng.choice(config.methods)
        path = _request_path(rng, config, method)
        has_body = method in _BODY_METHODS
        req = HTTPRequest(
            method=method, path=path,
            headers=_request_headers(rng, host, has_body, persist),
            body=_random_json(rng) if has_body else b"",
        )
        messages.append(AppMessage("c2s", encode_http_message(req), f"{method} {path}"))

        status, reason = _pick_status(rng, method, config.error_rate)
        resp_has_body = 200 <= status < 300 and status != 204
        # Header set before body, matching the evaluation order of the keyword
        # arguments this replaced, so a given seed still draws in the same order.
        headers = _response_headers(rng, resp_has_body, persist)
        body = _random_json(rng) if resp_has_body else b""

        # Chunk the body for a share of the responses that have one.  The draws
        # are guarded so that a zero rate consumes no randomness, keeping output
        # for a given seed identical to a run with the framing knobs untouched.
        if body and config.chunked_rate and rng.random() < config.chunked_rate:
            trailers: dict[str, str] = {}
            if config.trailer_rate and rng.random() < config.trailer_rate:
                trailers = _pick_trailers(rng)
                headers["Trailer"] = ", ".join(trailers)
            headers["Transfer-Encoding"] = "chunked"
            body = _chunk_body(body, rng, config.chunk_size, trailers)

        resp = HTTPResponse(
            status_code=status, reason=reason, headers=headers, body=body,
        )
        messages.append(AppMessage("s2c", encode_http_message(resp), f"{status} {reason}"))
    return messages


def _impair(
    stream: TCPStream,
    impairments: ImpairmentConfig,
    rng: random.Random,
    *,
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
    client_mac: str,
    server_mac: str,
    include_ethernet: bool,
    ip_ttl: int,
    inter_packet_gap: float,
    encap: EncapSpec,
) -> TCPStream:
    """Apply the post-pass impairments to one rendered connection.

    Loss is not among them — it is applied as the connection is emitted, by
    :func:`~packeteer.generate.payloads.base.render_tcp_session`, so that a
    lost segment also suppresses its acknowledgement.
    """
    packets = apply_impairments(
        stream.packets,
        rng=rng,
        config=impairments,
        flow=FlowEndpoints(
            client_ip=client_ip, client_port=client_port, client_mac=client_mac,
            server_ip=server_ip, server_port=server_port, server_mac=server_mac,
            include_ethernet=include_ethernet, ip_ttl=ip_ttl, encap=encap,
        ),
        make=TCPStreamPacket,
        gap_usec=int(inter_packet_gap * 1_000_000),
    )
    packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))
    return TCPStream(packets=packets)


def generate_http_stream(
    *,
    client_ip: str,
    server_ip: str,
    requests: int = 10,
    requests_per_connection: int | None = None,
    server_port: int = 80,
    client_port: int = 54321,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    sessions: int = 1,
    session_stagger: float = 1.0,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    inter_packet_gap: float = 0.001,
    mss: int = 1460,
    encap: EncapSpec = None,
    seed: int | None = None,
    base_time: float | None = None,
    config: HTTPRestConfig | None = None,
) -> CombinedStream:
    """Simulate a REST client and return the traffic as a merged stream.

    Responses are framed with ``Content-Length`` unless
    :attr:`HTTPRestConfig.chunked_rate` asks for chunked framing on a share of
    them.

    *requests* request/response transactions are spread across connections of
    *requests_per_connection* each (``None`` = all in one keep-alive
    connection; ``1`` = a fresh connection per request).  Connections within a
    session use successive client ports and staggered start times; with
    *sessions* > 1, the whole workload is repeated for each distinct client/
    server IP pair (session ``i`` uses ``client_ip + i`` / ``server_ip + i``,
    and the two ranges must not overlap).

    Args:
        client_ip: Base client IP address.
        server_ip: Base server IP address.
        requests: Total number of request/response transactions per session.
        requests_per_connection: Transactions per TCP connection, or ``None``
            for a single keep-alive connection carrying them all.
        server_port: Server (destination) port.
        client_port: First client port; connection ``c`` uses ``client_port + c``.
        client_mac: Client MAC address (shared across connections).
        server_mac: Server MAC address (shared across connections).
        sessions: Number of distinct client/server IP pairs.
        session_stagger: Window in seconds over which connection start times
            are spread.
        include_ethernet: Whether to include Ethernet headers.
        ip_ttl: IP TTL / hop limit.
        inter_packet_gap: Seconds between consecutive packets within a stream.
        mss: Maximum segment size for splitting large bodies.
        encap: Optional encapsulation layer(s) applied to every packet.
        seed: RNG seed; the same seed reproduces the whole capture.
        base_time: Unix start time; defaults to the current time.
        config: Content and impairment knobs (:class:`HTTPRestConfig`).

    Returns:
        A :class:`~packeteer.generate.session_mix.CombinedStream` of all
        connections, merged in timestamp order.

    Raises:
        ValueError: If *requests* or *requests_per_connection* is below 1, the
            client/server IP ranges overlap, a connection's client port exceeds
            65535, or ``config.chunk_size`` is not a range with
            ``1 <= min <= max``.

    """
    if requests < 1:
        raise ValueError(f"requests must be at least 1, got {requests}")
    per_conn = requests if requests_per_connection is None else requests_per_connection
    if per_conn < 1:
        raise ValueError(
            f"requests_per_connection must be at least 1, got {per_conn}"
        )
    if config is None:
        config = HTTPRestConfig()
    low, high = config.chunk_size
    if low < 1 or high < low:
        # A zero-size chunk would emit "0\r\n" mid-body, which is the
        # terminator: the message would end early and silently.
        raise ValueError(
            f"chunk_size must be a (min, max) range with 1 <= min <= max, "
            f"got {config.chunk_size!r}"
        )

    connections = math.ceil(requests / per_conn)
    if client_port + connections - 1 > 65535:
        raise ValueError(
            f"{connections} connections from client port {client_port} exceed "
            "port 65535; lower --requests, raise --requests-per-connection, or "
            "lower --client-port"
        )
    client_ips, server_ips = _assign_endpoints(client_ip, server_ip, sessions)

    rng = random.Random(seed)
    start = base_time if base_time is not None else time.time()

    streams = []
    first = True
    for session_idx in range(sessions):
        remaining = requests
        for conn in range(connections):
            n_txn = min(per_conn, remaining)
            remaining -= n_txn
            conversation = generate_http_conversation(
                rng, transactions=n_txn, keepalive=n_txn > 1, config=config,
            )
            offset = 0.0 if first else rng.uniform(0.0, session_stagger)
            first = False
            stream = render_tcp_session(
                conversation,
                client_ip=client_ips[session_idx],
                server_ip=server_ips[session_idx],
                client_port=client_port + conn,
                server_port=server_port,
                client_mac=client_mac,
                server_mac=server_mac,
                mss=mss,
                include_ethernet=include_ethernet,
                ip_ttl=ip_ttl,
                inter_packet_gap=inter_packet_gap,
                base_time=start + offset,
                encap=encap,
                client_isn=rng.randint(0, _WRAP - 1),
                server_isn=rng.randint(0, _WRAP - 1),
                # Loss is applied here rather than as a pass over the finished
                # connection: a lost segment must also suppress the
                # acknowledgement it would have triggered, which only the emit
                # loop can do.
                packet_loss_probability=(
                    config.impairments.packet_loss_probability
                    if config.impairments is not None else 0.0
                ),
                loss_rng=rng,
            )
            if config.impairments is not None:
                stream = _impair(
                    stream, config.impairments, rng,
                    client_ip=client_ips[session_idx],
                    server_ip=server_ips[session_idx],
                    client_port=client_port + conn, server_port=server_port,
                    client_mac=client_mac, server_mac=server_mac,
                    include_ethernet=include_ethernet, ip_ttl=ip_ttl,
                    inter_packet_gap=inter_packet_gap, encap=encap,
                )
            streams.append(stream)
    return merge_streams(streams)
