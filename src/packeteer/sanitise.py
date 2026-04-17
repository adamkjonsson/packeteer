"""Sanitise a JSON packet config by replacing sensitive field values.

Reads a config dict in the format produced by ``packeteer parse`` and
returns a deep-copied, sanitised version where selected field values have been
replaced with synthetic but structurally valid equivalents.

Replacement strategy
--------------------
* **Consistency** — the same original value always maps to the same synthetic
  value within a single :func:`sanitise` call, across all packets and all
  nesting levels.  This preserves the communication structure (who talked to
  whom, which ports were used) while hiding the real identities.

* **Valid synthetic ranges** — replacements are drawn from IANA-reserved
  ranges so sanitised captures can never be mistaken for live traffic:

  ========  =====================================================
  Field     Synthetic range
  ========  =====================================================
  IPv4      RFC 5737 documentation blocks 192.0.2.0/24,
            198.51.100.0/24, 203.0.113.0/24 (762 addresses)
  IPv6      2001:db8::/32 (RFC 3849)
  MAC       Locally-administered unicast 02:00:00:xx:xx:xx
  Port      10000–59999 (consistent remapping)
  Payload   Zero-filled hex string, same byte length
  DNS name  label0.label1... — each unique label replaced
            consistently so shared parents are preserved
  ========  =====================================================

Example::

    import json
    from packeteer.sanitise import sanitise, SanitiseOptions

    with open("capture.json") as f:
        config = json.load(f)

    clean = sanitise(config)

    with open("clean.json", "w") as f:
        json.dump(clean, f, indent=2)
"""
from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass, field

__all__ = ["sanitise", "SanitiseOptions"]

# ── RFC 5737 IPv4 documentation blocks ───────────────────────────────────────

_IPV4_POOLS: list[tuple[int, int]] = [
    (0xC0000200, 0xC00002FE),  # 192.0.2.1   – 192.0.2.254
    (0xC6336400, 0xC63364FE),  # 198.51.100.1 – 198.51.100.254
    (0xCB007100, 0xCB0071FE),  # 203.0.113.1  – 203.0.113.254
]
_IPV4_POOL_SIZE = sum(hi - lo + 1 for lo, hi in _IPV4_POOLS)


def _ipv4_from_index(n: int) -> str:
    """Return the *n*-th address (0-based) from the RFC 5737 pool."""
    n = n % _IPV4_POOL_SIZE
    for lo, hi in _IPV4_POOLS:
        size = hi - lo + 1
        if n < size:
            return str(ipaddress.IPv4Address(lo + n))
        n -= size
    raise RuntimeError("unreachable")  # pragma: no cover


def _ipv6_from_index(n: int) -> str:
    """Return 2001:db8::<n+1>."""
    base = ipaddress.IPv6Address("2001:db8::")
    return str(ipaddress.IPv6Address(int(base) + n + 1))


def _mac_from_index(n: int) -> str:
    """Return a locally-administered unicast MAC for index *n*."""
    # Byte layout: 02:00:00:<b2>:<b1>:<b0>  (up to 16 777 215 addresses)
    b0 = n & 0xFF
    b1 = (n >> 8) & 0xFF
    b2 = (n >> 16) & 0xFF
    return f"02:00:00:{b2:02x}:{b1:02x}:{b0:02x}"


# ── SanitiseOptions ───────────────────────────────────────────────────────────

@dataclass
class SanitiseOptions:
    """Controls which field types are replaced during sanitisation.

    All fields default to their most common setting: IP addresses and MAC
    addresses are replaced; port numbers, payload data, and timestamps are
    left unchanged.

    Attributes:
        ips: Replace ``src`` and ``dst`` in every ``network`` section,
            including those inside nested tunnel specs (ipip, gre, etherip).
        macs: Replace ``src_mac`` and ``dst_mac`` in every ``ethernet``
            section, including those inside tunnel specs.
        ports: Replace ``src_port`` and ``dst_port`` in every ``transport``
            section.  The same original port always maps to the same synthetic
            port (10000–59999).
        payload: Zero out ``payload.data`` hex strings.  The byte length is
            preserved so the rebuilt packet has the same size.
        timestamps: Zero ``timestamp_s`` and ``timestamp_us`` / ``timestamp_ns``
            in every ``metadata`` section.
        dns_ids: Zero the 16-bit transaction ``id`` field in every ``dns``
            section.  DNS names and A/AAAA addresses in DNS RDATA are always
            sanitised when a ``dns`` section is present (controlled by *ips*
            for addresses).

    """

    ips:        bool = True
    macs:       bool = True
    ports:      bool = False
    payload:    bool = False
    timestamps: bool = False
    dns_ids:    bool = False


# ── Internal replacer state ───────────────────────────────────────────────────

@dataclass
class _Replacer:
    """Holds mapping tables and allocation counters for one sanitise call."""

    _ipv4_map:       dict[str, str] = field(default_factory=dict)
    _ipv6_map:       dict[str, str] = field(default_factory=dict)
    _mac_map:        dict[str, str] = field(default_factory=dict)
    _port_map:       dict[int, int] = field(default_factory=dict)
    _dns_label_map:  dict[str, str] = field(default_factory=dict)

    _ipv4_counter:      int = 0
    _ipv6_counter:      int = 0
    _mac_counter:       int = 0
    _port_counter:      int = 10000
    _dns_label_counter: int = 0

    def ip(self, addr: str) -> str:
        """Return the consistent synthetic replacement for *addr*."""
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            return addr  # not a valid IP — leave unchanged
        if isinstance(parsed, ipaddress.IPv4Address):
            if addr not in self._ipv4_map:
                self._ipv4_map[addr] = _ipv4_from_index(self._ipv4_counter)
                self._ipv4_counter += 1
            return self._ipv4_map[addr]
        if addr not in self._ipv6_map:
            self._ipv6_map[addr] = _ipv6_from_index(self._ipv6_counter)
            self._ipv6_counter += 1
        return self._ipv6_map[addr]

    def mac(self, addr: str) -> str:
        """Return the consistent synthetic replacement for *addr*."""
        key = addr.lower().replace("-", ":")
        if key not in self._mac_map:
            self._mac_map[key] = _mac_from_index(self._mac_counter)
            self._mac_counter += 1
        return self._mac_map[key]

    def port(self, p: int) -> int:
        """Return the consistent synthetic replacement for port *p*."""
        if p not in self._port_map:
            self._port_map[p] = self._port_counter
            self._port_counter += 1
            if self._port_counter > 59999:
                self._port_counter = 10000
        return self._port_map[p]

    def dns_label(self, label: str) -> str:
        """Return the consistent synthetic replacement for a single DNS label."""
        key = label.lower()
        if key not in self._dns_label_map:
            self._dns_label_map[key] = f"label{self._dns_label_counter}"
            self._dns_label_counter += 1
        return self._dns_label_map[key]


# ── DNS record-type constants (duplicated to avoid import) ────────────────────

_DNS_TYPE_A    = 1
_DNS_TYPE_NS   = 2
_DNS_TYPE_CNAME = 5
_DNS_TYPE_SOA  = 6
_DNS_TYPE_PTR  = 12
_DNS_TYPE_MX   = 15
_DNS_TYPE_AAAA = 28

# ── DNS sanitisation helpers ──────────────────────────────────────────────────

def _sanitise_dns_name(name: str, r: _Replacer) -> str:
    """Replace every label in *name* with a consistent synthetic label."""
    trailing_dot = name.endswith(".")
    bare = name.rstrip(".")
    if not bare:
        return name  # root label "."
    new_labels = [r.dns_label(lbl) for lbl in bare.split(".")]
    result = ".".join(new_labels)
    return result + "." if trailing_dot else result


def _sanitise_dns_rdata(rdata: dict, rtype: int, r: _Replacer, opts: SanitiseOptions) -> None:
    """Sanitise the rdata dict in-place given the numeric *rtype*."""
    if rtype in (_DNS_TYPE_A, _DNS_TYPE_AAAA) and opts.ips and "address" in rdata:
        rdata["address"] = r.ip(rdata["address"])
    elif rtype in (_DNS_TYPE_CNAME, _DNS_TYPE_NS, _DNS_TYPE_PTR) and "name" in rdata:
        rdata["name"] = _sanitise_dns_name(rdata["name"], r)
    elif rtype == _DNS_TYPE_MX and "exchange" in rdata:
        rdata["exchange"] = _sanitise_dns_name(rdata["exchange"], r)
    elif rtype == _DNS_TYPE_SOA:
        if "mname" in rdata:
            rdata["mname"] = _sanitise_dns_name(rdata["mname"], r)
        if "rname" in rdata:
            rdata["rname"] = _sanitise_dns_name(rdata["rname"], r)


def _sanitise_dns(dns: dict, r: _Replacer, opts: SanitiseOptions) -> None:
    """Sanitise a ``dns`` section dict in-place."""
    if opts.dns_ids:
        dns["id"] = 0
    for q in dns.get("questions", []):
        if "name" in q:
            q["name"] = _sanitise_dns_name(q["name"], r)
    for section in ("answers", "authority", "additional"):
        for rr in dns.get(section, []):
            if "name" in rr:
                rr["name"] = _sanitise_dns_name(rr["name"], r)
            rdata = rr.get("rdata")
            if isinstance(rdata, dict):
                _sanitise_dns_rdata(rdata, rr.get("rtype", 0), r, opts)


# ── Recursive packet walker ───────────────────────────────────────────────────

def _sanitise_network(net: dict, r: _Replacer) -> None:
    if "src" in net:
        net["src"] = r.ip(net["src"])
    if "dst" in net:
        net["dst"] = r.ip(net["dst"])


def _sanitise_ethernet(eth: dict, r: _Replacer, opts: SanitiseOptions) -> None:
    if opts.macs:
        if "src_mac" in eth:
            eth["src_mac"] = r.mac(eth["src_mac"])
        if "dst_mac" in eth:
            eth["dst_mac"] = r.mac(eth["dst_mac"])


def _sanitise_packet(pkt: dict, r: _Replacer, opts: SanitiseOptions) -> None:
    """In-place sanitisation of one packet dict (already deep-copied)."""
    if "ethernet" in pkt:
        _sanitise_ethernet(pkt["ethernet"], r, opts)

    if opts.ips and "network" in pkt:
        _sanitise_network(pkt["network"], r)

    if opts.ports and "transport" in pkt:
        t = pkt["transport"]
        if "src_port" in t:
            t["src_port"] = r.port(t["src_port"])
        if "dst_port" in t:
            t["dst_port"] = r.port(t["dst_port"])

    if opts.payload and "payload" in pkt:
        pl = pkt["payload"]
        if "data" in pl and isinstance(pl["data"], str):
            pl["data"] = "00" * (len(pl["data"]) // 2)

    if opts.payload and "transport" in pkt:
        t = pkt["transport"]
        if t.get("protocol") == "sctp":
            for chunk in t.get("chunks", []):
                # Zero all opaque binary hex fields present in any chunk type
                for key in ("data", "params", "cookie", "info", "causes", "value"):
                    if key in chunk and isinstance(chunk[key], str):
                        chunk[key] = "00" * (len(chunk[key]) // 2)

    if opts.timestamps and "packet_metadata" in pkt:
        meta = pkt["packet_metadata"]
        meta["timestamp_s"] = 0
        for key in ("timestamp_us", "timestamp_ns"):
            if key in meta:
                meta[key] = 0

    if "dns" in pkt:
        _sanitise_dns(pkt["dns"], r, opts)

    # ── Tunnel recursion ──────────────────────────────────────────────────────
    for tunnel_key in ("ipip", "gre", "etherip"):
        if tunnel_key not in pkt:
            continue
        inner = pkt[tunnel_key]
        if "ethernet" in inner:
            _sanitise_ethernet(inner["ethernet"], r, opts)
        _sanitise_packet(inner, r, opts)


# ── Public API ────────────────────────────────────────────────────────────────

def sanitise(
    config: dict,
    options: SanitiseOptions | None = None,
) -> dict:
    """Return a sanitised deep copy of *config*.

    *config* must be a dict in the format produced by ``packeteer parse``
    — a top-level ``"packets"`` list, with an optional ``"metadata"``
    block.

    The original dict is never modified.

    Args:
        config: Packet config dict as returned by
            :func:`packeteer.parse.to_config.to_packet_spec` or loaded from a
            packet spec file written by ``packeteer parse``.
        options: Controls which field types are replaced.  Defaults to
            :class:`SanitiseOptions` with ``ips=True``, ``macs=True``,
            ``ports=False``, ``payload=False``, ``timestamps=False``.

    Returns:
        A new dict with the same structure but sensitive field values replaced
        by synthetic equivalents drawn from IANA-reserved ranges.

    Raises:
        ValueError: If *config* has no ``"packets"`` key.

    Example::

        clean = sanitise(config)
        clean_ips_only = sanitise(config, SanitiseOptions(macs=False))
        clean_all = sanitise(config, SanitiseOptions(ports=True, payload=True, timestamps=True))

    """
    if "packets" not in config:
        raise ValueError("config must contain a 'packets' key")

    if options is None:
        options = SanitiseOptions()

    result = copy.deepcopy(config)
    r = _Replacer()

    for pkt in result["packets"]:
        _sanitise_packet(pkt, r, options)

    return result
