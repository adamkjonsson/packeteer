"""Generate adversarial packet variants for decoder robustness testing.

Two complementary public functions are provided:

* :func:`fuzz` — works on packet spec dicts (the JSON format produced by
  ``packeteer parse``).  Returns a list of :class:`FuzzVariant` objects,
  each containing a single mutated spec ready for replay with
  ``packeteer build``.

* :func:`fuzz_bytes` — works on raw serialised packet bytes.  Returns a
  list of ``(label, corrupted_bytes)`` pairs suitable for writing directly
  to a pcap file.

Both functions accept a :class:`FuzzOptions` instance that selects which
mutation types to apply.  You can pass the same options object to both
functions; each one silently applies only the mutations relevant to its
domain.

Spec-level mutations (used by :func:`fuzz`)
--------------------------------------------

==================  ===========================================================
Name                What it does
==================  ===========================================================
``boundary``        Sets numeric header fields (TTL, TOS, ports, window,
                    seq/ack, fragment offset, ICMP id/seq, SCTP verification
                    tag) to their minimum, near-minimum, near-maximum, and
                    maximum representable values.
``reserved-bits``   Sets reserved or undefined flag bits: the IPv4 "evil bit"
                    (RFC 3514), the DF+MF combination (RFC-invalid), and the
                    TCP reserved nibble.
``tcp-flags``       Emits all classically pathological TCP flag combinations:
                    SYN+FIN, SYN+RST, null scan (no flags), XMAS (all flags),
                    and several others.
``truncate``        Removes the payload or cuts it to 1 byte, 25%, or 50% of
                    its original length.
``extend``          Appends extra zero or random bytes after the existing
                    payload.
==================  ===========================================================

Byte-level mutations (used by :func:`fuzz_bytes`)
--------------------------------------------------

===================  ==========================================================
Name                 What it does
===================  ==========================================================
``bit-flip``         Flips a single random bit per variant.  The number of
                     variants is controlled by :attr:`FuzzOptions.count`.
``wrong-checksum``   Corrupts IP, TCP, and UDP checksum fields to ``0x0000``,
                     ``0xffff``, and the bitwise inverse of the original value.
``wrong-length``     Sets IP total-length and UDP length fields to zero,
                     below-minimum, off-by-one, and maximum values.
===================  ==========================================================

Example::

    import json
    from packeteer.fuzz import fuzz, fuzz_bytes, FuzzOptions

    with open("capture.json") as f:
        config = json.load(f)

    # Spec-level variants (serialise to pcap with packeteer build)
    variants = fuzz(config, FuzzOptions(mutations=["boundary", "tcp-flags"], seed=42))
    for v in variants:
        print(v.label, v.source_idx)

    # Byte-level variants (write raw bytes directly)
    raw_pkt = b"..."  # serialised Ethernet+IPv4+TCP packet
    for label, corrupted in fuzz_bytes(raw_pkt):
        print(label, len(corrupted))

"""
from __future__ import annotations

import copy
import random as _random_module
import struct
from dataclasses import dataclass, field
from typing import Any, Callable

from .generate.tcp import (
    TCP_ACK,
    TCP_CWR,
    TCP_ECE,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_URG,
)

__all__ = [
    "fuzz",
    "fuzz_bytes",
    "FuzzOptions",
    "FuzzVariant",
    "MUTATION_NAMES",
    "BYTE_MUTATION_NAMES",
    "ALL_MUTATION_NAMES",
]

# ── Internal callable type ────────────────────────────────────────────────────

_MutFn = Callable[
    [dict[str, Any], _random_module.Random],
    list[tuple[str, dict[str, Any]]],
]


# ── Public types ──────────────────────────────────────────────────────────────


@dataclass
class FuzzOptions:
    """Control which mutation types are applied and how many variants are produced.

    The same :class:`FuzzOptions` instance can be passed to both :func:`fuzz`
    and :func:`fuzz_bytes`; each function silently applies only the mutations
    relevant to its domain (spec-level or byte-level respectively).

    Attributes:
        mutations: Names of mutations to apply.  May contain any combination
            of spec-level names (:data:`MUTATION_NAMES`) and byte-level names
            (:data:`BYTE_MUTATION_NAMES`).  Defaults to all mutations in
            :data:`ALL_MUTATION_NAMES`.
        count: Number of ``bit-flip`` variants produced per source packet.
            Deterministic mutations always produce a fixed set.
        seed: RNG seed for reproducibility.  ``None`` means non-deterministic.

    Example::

        # Apply only boundary and bit-flip mutations, reproducibly
        opts = FuzzOptions(mutations=["boundary", "bit-flip"], seed=42)

        spec_variants = fuzz(config, opts)    # applies "boundary"
        byte_variants = fuzz_bytes(raw, opts) # applies "bit-flip"

    """

    # default_factory references ALL_MUTATION_NAMES which is defined later in
    # this module; the lambda is evaluated at instantiation time, not here.
    mutations: list[str] = field(
        default_factory=lambda: list(ALL_MUTATION_NAMES)
    )
    count: int = 10
    seed: int | None = None


@dataclass
class FuzzVariant:
    """One mutated packet produced by :func:`fuzz`.

    Attributes:
        source_idx: Zero-based index of the source packet in the input config.
        mutation: Mutation type name (e.g. ``"boundary"``).
        label: Human-readable description of what changed
            (e.g. ``"boundary: network.ttl=0"``).
        spec: Mutated single-packet spec dict — same structure as one element
            of ``config["packets"]``.

    """

    source_idx: int
    mutation: str
    label: str
    spec: dict[str, Any]


# ── Boundary value tables ─────────────────────────────────────────────────────

_NETWORK_BOUNDARY: list[tuple[str, list[int]]] = [
    ("ttl",             [0, 1, 254, 255]),
    ("tos",             [0, 255]),
    ("identification",  [0, 65535]),
    ("fragment_offset", [0, 8191]),
]

_PORT_BOUNDARY: list[int] = [0, 1, 65534, 65535]

_TCP_BOUNDARY: list[tuple[str, list[int]]] = [
    ("window",     [0, 1, 65534, 65535]),
    ("seq",        [0, 1, 0xFFFFFFFE, 0xFFFFFFFF]),
    ("ack",        [0, 1, 0xFFFFFFFE, 0xFFFFFFFF]),
    ("urgent_ptr", [0, 65535]),
]

_ICMP_BOUNDARY: list[tuple[str, list[int]]] = [
    ("type",       [0, 255]),
    ("code",       [0, 255]),
    ("identifier", [0, 65535]),
    ("sequence",   [0, 65535]),
]

_SCTP_BOUNDARY: list[tuple[str, list[int]]] = [
    ("verification_tag", [0, 0xFFFFFFFF]),
]

# ── TCP flag combos ───────────────────────────────────────────────────────────

_TCP_FLAG_COMBOS: list[tuple[str, int]] = [
    ("SYN+FIN",         TCP_SYN | TCP_FIN),
    ("SYN+RST",         TCP_SYN | TCP_RST),
    ("FIN+RST",         TCP_FIN | TCP_RST),
    ("SYN+FIN+PSH",     TCP_SYN | TCP_FIN | TCP_PSH),
    ("null (no flags)", 0x00),
    ("FIN only",        TCP_FIN),
    ("all flags",       0xFF),
    ("PSH+URG no ACK",  TCP_PSH | TCP_URG),
    ("RST+ACK+URG",     TCP_RST | TCP_ACK | TCP_URG),
    ("ECE+CWR",         TCP_ECE | TCP_CWR),
]

# ── Zero-append sizes for the extend mutation ─────────────────────────────────

_EXTEND_ZERO_SIZES: list[int] = [1, 4, 8, 64, 512]


# ── Spec-level helpers ────────────────────────────────────────────────────────


def _pkt_proto(pkt: dict[str, Any]) -> str:
    """Return the transport protocol string from *pkt*, lower-cased."""
    return (pkt.get("network", {}).get("protocol") or "").lower()


def _get_hex_payload(pkt: dict[str, Any]) -> str | None:
    """Return the hex payload data string if *pkt* carries a hex payload."""
    pl = pkt.get("payload", {})
    if pl.get("encoding", "hex") == "hex" and isinstance(pl.get("data"), str):
        return pl["data"]
    return None


def _set_hex_payload(pkt: dict[str, Any], data: str) -> None:
    """Set the payload data hex string on *pkt* in-place."""
    pkt.setdefault("payload", {})["data"] = data
    pkt["payload"].pop("encoding", None)


# ── Spec-level mutation functions ─────────────────────────────────────────────


def _boundary(
    pkt: dict[str, Any],
    rng: _random_module.Random,
) -> list[tuple[str, dict[str, Any]]]:
    """Produce variants with numeric header fields set to boundary values."""
    results: list[tuple[str, dict[str, Any]]] = []
    net = pkt.get("network", {})
    transport = pkt.get("transport", {})
    proto = _pkt_proto(pkt)

    for fname, values in _NETWORK_BOUNDARY:
        if fname not in net:
            continue
        for val in values:
            v = copy.deepcopy(pkt)
            v["network"][fname] = val
            results.append((f"boundary: network.{fname}={val}", v))

    if proto in ("tcp", "udp", "sctp") and transport:
        for fname in ("src_port", "dst_port"):
            if fname not in transport:
                continue
            for val in _PORT_BOUNDARY:
                v = copy.deepcopy(pkt)
                v["transport"][fname] = val
                results.append((f"boundary: transport.{fname}={val}", v))

    if proto == "tcp" and transport:
        for fname, values in _TCP_BOUNDARY:
            if fname not in transport:
                continue
            for val in values:
                v = copy.deepcopy(pkt)
                v["transport"][fname] = val
                results.append((f"boundary: transport.{fname}={val}", v))

    if proto in ("icmp", "icmpv6") and transport:
        for fname, values in _ICMP_BOUNDARY:
            if fname not in transport:
                continue
            for val in values:
                v = copy.deepcopy(pkt)
                v["transport"][fname] = val
                results.append((f"boundary: transport.{fname}={val}", v))

    if proto == "sctp" and transport:
        for fname, values in _SCTP_BOUNDARY:
            if fname not in transport:
                continue
            for val in values:
                v = copy.deepcopy(pkt)
                v["transport"][fname] = val
                results.append((f"boundary: transport.{fname}={val}", v))

    return results


def _reserved_bits(
    pkt: dict[str, Any],
    rng: _random_module.Random,
) -> list[tuple[str, dict[str, Any]]]:
    """Produce variants with reserved or undefined flag bits set."""
    results: list[tuple[str, dict[str, Any]]] = []
    net = pkt.get("network", {})
    proto = _pkt_proto(pkt)

    if "flags" in net:
        current: int = net["flags"]
        v = copy.deepcopy(pkt)
        v["network"]["flags"] = current | 0b100
        results.append(("reserved-bits: IPv4 reserved flag (evil bit) set", v))

        # DF + MF simultaneously — RFC-invalid combination
        v = copy.deepcopy(pkt)
        v["network"]["flags"] = 0b011
        results.append(("reserved-bits: IPv4 DF+MF simultaneously (RFC-invalid)", v))

    if proto == "tcp":
        for val in (1, 7):
            v = copy.deepcopy(pkt)
            v.setdefault("transport", {})["reserved"] = val
            results.append((f"reserved-bits: TCP reserved field={val}", v))

    return results


def _tcp_flags(
    pkt: dict[str, Any],
    rng: _random_module.Random,
) -> list[tuple[str, dict[str, Any]]]:
    """Produce variants with pathological TCP flag combinations."""
    if _pkt_proto(pkt) != "tcp" or not pkt.get("transport"):
        return []
    results: list[tuple[str, dict[str, Any]]] = []
    for desc, flag_val in _TCP_FLAG_COMBOS:
        v = copy.deepcopy(pkt)
        v["transport"]["flags"] = flag_val
        results.append((f"tcp-flags: {desc} (0x{flag_val:02x})", v))
    return results


def _truncate(
    pkt: dict[str, Any],
    rng: _random_module.Random,
) -> list[tuple[str, dict[str, Any]]]:
    """Produce variants with the payload shortened or removed."""
    hex_data = _get_hex_payload(pkt)
    if hex_data is None:
        return []
    byte_len = len(hex_data) // 2
    if byte_len == 0:
        return []

    results: list[tuple[str, dict[str, Any]]] = []

    v = copy.deepcopy(pkt)
    v.pop("payload", None)
    results.append(("truncate: payload removed entirely", v))

    if byte_len > 1:
        v = copy.deepcopy(pkt)
        _set_hex_payload(v, hex_data[:2])
        results.append(("truncate: payload truncated to 1 byte", v))

    keep_25 = max(1, byte_len // 4)
    if keep_25 < byte_len and keep_25 > 1:
        v = copy.deepcopy(pkt)
        _set_hex_payload(v, hex_data[: keep_25 * 2])
        results.append((f"truncate: payload truncated to {keep_25} bytes (25%)", v))

    keep_50 = max(1, byte_len // 2)
    if keep_50 < byte_len and keep_50 > 1 and keep_50 != keep_25:
        v = copy.deepcopy(pkt)
        _set_hex_payload(v, hex_data[: keep_50 * 2])
        results.append((f"truncate: payload truncated to {keep_50} bytes (50%)", v))

    return results


def _extend(
    pkt: dict[str, Any],
    rng: _random_module.Random,
) -> list[tuple[str, dict[str, Any]]]:
    """Produce variants with extra bytes appended after the existing payload."""
    hex_data = _get_hex_payload(pkt)
    base_hex = hex_data if hex_data is not None else ""

    results: list[tuple[str, dict[str, Any]]] = []

    for n in _EXTEND_ZERO_SIZES:
        v = copy.deepcopy(pkt)
        _set_hex_payload(v, base_hex + "00" * n)
        results.append((f"extend: +{n} zero bytes appended", v))

    rand_bytes = bytes(rng.randint(0, 255) for _ in range(16))
    v = copy.deepcopy(pkt)
    _set_hex_payload(v, base_hex + rand_bytes.hex())
    results.append(("extend: +16 random bytes appended", v))

    return results


# ── Spec-level mutation registry ──────────────────────────────────────────────

_MUTATIONS: dict[str, _MutFn] = {
    "boundary":      _boundary,
    "reserved-bits": _reserved_bits,
    "tcp-flags":     _tcp_flags,
    "truncate":      _truncate,
    "extend":        _extend,
}

MUTATION_NAMES: tuple[str, ...] = tuple(_MUTATIONS)
"""Names of all spec-level mutation types, in registration order."""


# ── Byte-level mutation helpers ───────────────────────────────────────────────


def _ip_header_offset(raw: bytes) -> int:
    """Return the byte offset of the IPv4 header in *raw*, or -1 if not found.

    Handles standard Ethernet frames and 802.1Q / 802.1ad VLAN tags.
    Returns -1 for non-Ethernet frames or non-IPv4 EtherTypes.
    """
    if len(raw) < 14:
        return -1
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8):   # 802.1Q, 802.1ad
        if len(raw) < offset + 4:
            return -1
        ethertype = struct.unpack_from("!H", raw, offset + 2)[0]
        offset += 4
    return offset if ethertype == 0x0800 else -1


def _raw_bit_flip(
    raw: bytes,
    rng: _random_module.Random,
    count: int,
) -> list[tuple[str, bytes]]:
    """Return *count* single-bit-flip variants of *raw*."""
    if not raw:
        return []
    results: list[tuple[str, bytes]] = []
    for i in range(count):
        ba = bytearray(raw)
        bit_idx = rng.randrange(len(ba) * 8)
        ba[bit_idx // 8] ^= 1 << (bit_idx % 8)
        results.append(
            (f"bit-flip #{i + 1}: byte {bit_idx // 8} bit {bit_idx % 8}", bytes(ba))
        )
    return results


def _raw_wrong_checksum(raw: bytes) -> list[tuple[str, bytes]]:
    """Return variants of *raw* with IP, TCP, and UDP checksums corrupted."""
    ip_off = _ip_header_offset(raw)
    if ip_off < 0 or len(raw) < ip_off + 20:
        return []

    ihl = (raw[ip_off] & 0x0F) * 4
    proto = raw[ip_off + 9]
    results: list[tuple[str, bytes]] = []

    existing_ip = struct.unpack_from("!H", raw, ip_off + 10)[0]
    for label, cksum in [
        ("0x0000",                                  0),
        ("0xffff",                                  0xFFFF),
        (f"inverted (0x{existing_ip ^ 0xFFFF:04x})", existing_ip ^ 0xFFFF),
    ]:
        ba = bytearray(raw)
        struct.pack_into("!H", ba, ip_off + 10, cksum)
        results.append((f"wrong-checksum: IP checksum={label}", bytes(ba)))

    t_off = ip_off + ihl
    if proto == 6 and len(raw) >= t_off + 18:      # TCP checksum at offset +16
        for label, cksum in [("0x0000", 0), ("0xffff", 0xFFFF)]:
            ba = bytearray(raw)
            struct.pack_into("!H", ba, t_off + 16, cksum)
            results.append((f"wrong-checksum: TCP checksum={label}", bytes(ba)))
    elif proto == 17 and len(raw) >= t_off + 8:    # UDP checksum at offset +6
        for label, cksum in [("0x0000", 0), ("0xffff", 0xFFFF)]:
            ba = bytearray(raw)
            struct.pack_into("!H", ba, t_off + 6, cksum)
            results.append((f"wrong-checksum: UDP checksum={label}", bytes(ba)))

    return results


def _raw_wrong_length(raw: bytes) -> list[tuple[str, bytes]]:
    """Return variants of *raw* with IP total-length and UDP length corrupted."""
    ip_off = _ip_header_offset(raw)
    if ip_off < 0 or len(raw) < ip_off + 20:
        return []

    ihl = (raw[ip_off] & 0x0F) * 4
    proto = raw[ip_off + 9]
    actual_ip_total = struct.unpack_from("!H", raw, ip_off + 2)[0]
    results: list[tuple[str, bytes]] = []

    for label, val in [
        ("0",        0),
        ("ihl_only", ihl),
        ("actual-1", max(0, actual_ip_total - 1)),
        ("actual+1", (actual_ip_total + 1) & 0xFFFF),
        ("0xffff",   0xFFFF),
    ]:
        ba = bytearray(raw)
        struct.pack_into("!H", ba, ip_off + 2, val)
        results.append((f"wrong-length: IP total_length={label}", bytes(ba)))

    t_off = ip_off + ihl
    if proto == 17 and len(raw) >= t_off + 8:
        actual_udp = struct.unpack_from("!H", raw, t_off + 4)[0]
        for label, val in [
            ("0",        0),
            ("7",        7),                              # below minimum header of 8
            ("actual-1", max(0, actual_udp - 1)),
            ("actual+1", (actual_udp + 1) & 0xFFFF),
            ("0xffff",   0xFFFF),
        ]:
            ba = bytearray(raw)
            struct.pack_into("!H", ba, t_off + 4, val)
            results.append((f"wrong-length: UDP length={label}", bytes(ba)))

    return results


# ── Byte-level mutation registry ──────────────────────────────────────────────

BYTE_MUTATION_NAMES: tuple[str, ...] = ("bit-flip", "wrong-checksum", "wrong-length")
"""Names of all byte-level mutation types."""

ALL_MUTATION_NAMES: tuple[str, ...] = MUTATION_NAMES + BYTE_MUTATION_NAMES
"""All mutation type names: spec-level first, then byte-level."""


# ── Public API ────────────────────────────────────────────────────────────────


def fuzz(
    config: dict[str, Any],
    options: FuzzOptions | None = None,
) -> list[FuzzVariant]:
    """Return mutated variants of every packet in *config*.

    Each source packet in ``config["packets"]`` is processed by every
    spec-level mutation type listed in *options.mutations*.  Byte-level
    mutation names (``bit-flip``, ``wrong-checksum``, ``wrong-length``) are
    silently ignored — pass the same options object to :func:`fuzz_bytes` to
    apply those.

    The original config is never modified.

    Args:
        config: Packet config dict in the format produced by ``packeteer parse``
            — must have a top-level ``"packets"`` list.
        options: Controls which mutations are applied and the RNG seed.
            Defaults to :class:`FuzzOptions` with all mutations enabled.

    Returns:
        Ordered list of :class:`FuzzVariant` objects.  Within each source
        packet, variants are grouped by mutation type in the order given in
        ``options.mutations``.

    Raises:
        ValueError: If *config* has no ``"packets"`` key, or if
            ``options.mutations`` contains a name not in
            :data:`ALL_MUTATION_NAMES`.

    Example::

        variants = fuzz(config)
        variants = fuzz(config, FuzzOptions(mutations=["boundary", "tcp-flags"], seed=42))

    """
    if "packets" not in config:
        raise ValueError("config must contain a 'packets' key")

    if options is None:
        options = FuzzOptions()

    unknown = [m for m in options.mutations if m not in set(ALL_MUTATION_NAMES)]
    if unknown:
        raise ValueError(
            f"unknown mutation type(s): {', '.join(repr(m) for m in unknown)}"
        )

    rng = _random_module.Random(options.seed)
    results: list[FuzzVariant] = []

    for idx, src_pkt in enumerate(config["packets"]):
        for mut_name in options.mutations:
            if mut_name not in _MUTATIONS:
                continue   # byte-level name, not applicable here
            for label, variant_pkt in _MUTATIONS[mut_name](src_pkt, rng):
                results.append(
                    FuzzVariant(
                        source_idx=idx,
                        mutation=mut_name,
                        label=label,
                        spec=variant_pkt,
                    )
                )

    return results


def fuzz_bytes(
    raw: bytes,
    options: FuzzOptions | None = None,
) -> list[tuple[str, bytes]]:
    """Return byte-level mutations of the raw serialised packet *raw*.

    Spec-level mutation names (``boundary``, ``tcp-flags``, etc.) in
    *options.mutations* are silently ignored — pass the same options object
    to :func:`fuzz` to apply those.

    Only Ethernet-framed IPv4 packets are supported for ``wrong-checksum``
    and ``wrong-length``; those mutations return an empty list for other
    frame types.  ``bit-flip`` works on any non-empty byte string.

    Args:
        raw: Serialised packet bytes (e.g. from a pcap file or
            ``PacketBuilder.build()``).
        options: Controls which byte-level mutations are applied, the
            ``bit-flip`` count, and the RNG seed.  Defaults to
            :class:`FuzzOptions` with all mutations enabled.

    Returns:
        List of ``(label, corrupted_bytes)`` pairs, one per corruption
        applied.  The list may be empty if *raw* is too short or uses a
        frame type not supported by the requested mutations.

    Raises:
        ValueError: If ``options.mutations`` contains a name not in
            :data:`ALL_MUTATION_NAMES`.

    Example::

        for label, corrupted in fuzz_bytes(raw_pkt, FuzzOptions(seed=0)):
            write_to_pcap(corrupted)

    """
    if options is None:
        options = FuzzOptions()

    unknown = [m for m in options.mutations if m not in set(ALL_MUTATION_NAMES)]
    if unknown:
        raise ValueError(
            f"unknown mutation type(s): {', '.join(repr(m) for m in unknown)}"
        )

    byte_muts = {m for m in options.mutations if m in set(BYTE_MUTATION_NAMES)}
    rng = _random_module.Random(options.seed)
    results: list[tuple[str, bytes]] = []

    if "bit-flip" in byte_muts:
        results.extend(_raw_bit_flip(raw, rng, options.count))
    if "wrong-checksum" in byte_muts:
        results.extend(_raw_wrong_checksum(raw))
    if "wrong-length" in byte_muts:
        results.extend(_raw_wrong_length(raw))

    return results
