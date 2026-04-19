r"""Packet filter for the packeteer parse pipeline.

A :class:`PacketFilter` holds one or more criteria; a packet must satisfy
**all** of them to be kept (AND logic).  Each criterion value may be prefixed
with ``!`` to negate it:

- ``proto="!tcp"`` — keep packets whose IP protocol is *not* TCP.
- ``port=["!80", "!443"]`` — keep packets whose source **and** destination
  port are neither 80 nor 443.

For list criteria (``port``, ``src_port``, ``dst_port``, ``src``, ``dst``,
``host``) all values must be either all positive or all negative; mixing is
an error.

The filter operates on packet spec dicts — the same format produced by
``packeteer parse``.  For tunnelled packets (GRE, EtherIP, IP-in-IP) only
the *outer* layer is checked.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_neg(val: str) -> bool:
    return val.startswith("!")


def _strip(val: str) -> str:
    return val[1:] if val.startswith("!") else val


def _validate_list(values: list[str], name: str) -> None:
    """Raise ValueError if *values* mixes negated and non-negated entries."""
    if len(values) < 2:
        return
    negs = [_is_neg(v) for v in values]
    if any(negs) and not all(negs):
        raise ValueError(
            f"{name!r}: cannot mix positive and negated values; "
            "use either 'a,b' or '!a,!b'"
        )


def _validate_ports(values: list[str], name: str) -> None:
    _validate_list(values, name)
    for v in values:
        raw = _strip(v)
        try:
            n = int(raw)
        except ValueError:
            raise ValueError(f"{name!r}: {raw!r} is not a valid port number") from None
        if not 0 <= n <= 65535:
            raise ValueError(f"{name!r}: port {n} is out of range 0–65535")


def _validate_addrs(values: list[str], name: str) -> None:
    _validate_list(values, name)
    for v in values:
        raw = _strip(v)
        try:
            ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(
                f"{name!r}: {raw!r} is not a valid IP address or CIDR prefix"
            ) from None


def _addr_in_pattern(addr: str, pattern: str) -> bool:
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


def _match_port_list(port: int | None, values: list[str]) -> bool:
    """Return True when *port* satisfies the port-list constraint."""
    if not values:
        return True
    if port is None:
        return False
    negated = _is_neg(values[0])
    int_vals = {int(_strip(v)) for v in values}
    return (port not in int_vals) if negated else (port in int_vals)


def _match_addr_list(addr: str | None, values: list[str]) -> bool:
    """Return True when *addr* satisfies the address-list constraint."""
    if not values:
        return True
    if addr is None:
        return False
    negated = _is_neg(values[0])
    patterns = [_strip(v) for v in values]
    matched = any(_addr_in_pattern(addr, p) for p in patterns)
    return (not matched) if negated else matched


# ── public API ────────────────────────────────────────────────────────────────

@dataclass
class PacketFilter:
    r"""Criteria for selecting packets from a parsed pcap.

    A packet must satisfy **all** set criteria to be kept.  Unset criteria
    (``None`` or empty list) match every packet.

    Prefix any value with ``!`` to negate it.  For list criteria all values
    must be consistently positive or consistently negative.

    Args:
        proto: IP protocol name, optionally negated.
            Examples: ``"tcp"``, ``"!udp"``, ``"icmpv6"``.
        port: Source-or-destination port list, optionally negated.
            Examples: ``["80", "443"]``, ``["!80", "!443"]``.
        src_port: Source port list, optionally negated.
        dst_port: Destination port list, optionally negated.
        src: Source IP address or CIDR list, optionally negated.
            Both IPv4 and IPv6 are supported.
            Examples: ``["10.0.0.0/24"]``, ``["!192.168.1.1"]``,
            ``["2001:db8::/32"]``.
        dst: Destination IP address or CIDR list, optionally negated.
        host: Source-or-destination IP address or CIDR list, optionally
            negated.
        app: Application-layer name, optionally negated.
            Recognised values: ``"dns"``, ``"dhcp"``, ``"http"``.
            Examples: ``"http"``, ``"!dns"``.

    Example::

        from packeteer.filter import PacketFilter

        # Keep only HTTP traffic to/from 10.0.0.0/8
        f = PacketFilter(proto="tcp", port=["80", "8080"], host=["10.0.0.0/8"])
        kept = [pkt for pkt in packets if f.matches(pkt)]

    """

    proto:    str | None   = None
    port:     list[str]    = field(default_factory=list)
    src_port: list[str]    = field(default_factory=list)
    dst_port: list[str]    = field(default_factory=list)
    src:      list[str]    = field(default_factory=list)
    dst:      list[str]    = field(default_factory=list)
    host:     list[str]    = field(default_factory=list)
    app:      str | None   = None

    def __post_init__(self) -> None:
        _validate_ports(self.port,     "port")
        _validate_ports(self.src_port, "src_port")
        _validate_ports(self.dst_port, "dst_port")
        _validate_addrs(self.src,      "src")
        _validate_addrs(self.dst,      "dst")
        _validate_addrs(self.host,     "host")

    def is_empty(self) -> bool:
        """Return ``True`` when no criteria are set — every packet matches."""
        return (
            self.proto is None
            and not self.port
            and not self.src_port
            and not self.dst_port
            and not self.src
            and not self.dst
            and not self.host
            and self.app is None
        )

    def matches(self, pkt: dict[str, Any]) -> bool:
        """Return ``True`` if *pkt* satisfies all criteria.

        Args:
            pkt: A packet spec dict as produced by ``packeteer parse``
                (one element of the top-level ``"packets"`` array).

        Returns:
            ``True`` when the packet should be kept; ``False`` when it
            should be discarded.

        """
        net       = pkt.get("network", {})
        transport = pkt.get("transport", {})

        # proto: negated == match means "negated and matched" or "positive and not matched"
        if self.proto is not None:
            match = net.get("protocol", "").lower() == _strip(self.proto).lower()
            if _is_neg(self.proto) == match:
                return False

        # port (src or dst): keep if either port is in the set (positive) or
        # neither port is in the set (negated)
        if self.port:
            s        = transport.get("src_port")
            d        = transport.get("dst_port")
            negated  = _is_neg(self.port[0])
            int_vals = {int(_strip(v)) for v in self.port}
            either   = (s is not None and s in int_vals) or (d is not None and d in int_vals)
            if negated == either:
                return False

        if self.src_port and not _match_port_list(transport.get("src_port"), self.src_port):
            return False

        if self.dst_port and not _match_port_list(transport.get("dst_port"), self.dst_port):
            return False

        if self.src and not _match_addr_list(net.get("src"), self.src):
            return False

        if self.dst and not _match_addr_list(net.get("dst"), self.dst):
            return False

        # host: for positive, either src or dst must match; for negated, neither may
        if self.host:
            src_ok  = _match_addr_list(net.get("src"), self.host)
            dst_ok  = _match_addr_list(net.get("dst"), self.host)
            negated = _is_neg(self.host[0])
            ok      = (src_ok and dst_ok) if negated else (src_ok or dst_ok)
            if not ok:
                return False

        # app: negated == present means "negated and present" or "positive and absent"
        if self.app is not None:
            present = _strip(self.app).lower() in pkt
            if _is_neg(self.app) == present:
                return False

        return True
