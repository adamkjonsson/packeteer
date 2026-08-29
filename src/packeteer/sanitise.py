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
  HTTP hdr  ``[redacted]`` for Host, Cookie, Set-Cookie,
            Authorization, Location, Referer, Origin
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
import re
import warnings
from dataclasses import dataclass, field
from typing import Any

from packeteer import protocols

__all__ = ["sanitise", "SanitiseOptions", "PersonalDataWarning"]


class PersonalDataWarning(UserWarning):
    """Emitted when a possible personal data item is found in a UTF-8 payload.

    The :attr:`kind`, :attr:`match`, :attr:`text`, and :attr:`packet_num`
    attributes give machine-readable access to the finding without parsing the
    message string.

    Also emitted when something could not be redacted rather than found —
    an ICMP message type this version has no rule for, whose payload may carry
    addresses that are still in the output.  The two share a class on purpose:
    code that catches this warning is asking *is this file safe to share*, and
    a separate class for the second case would be silently missed by everyone
    already asking that question.

    Attributes:
        kind: ``"email"``, ``"name"``, or ``"unredacted"`` for something that
            could not be checked.
        match: The matched text with up to 40 characters of surrounding
            context; for ``"unredacted"``, what could not be redacted.
        text: The matched text itself, without surrounding context (used for
            consolidation across packets).
        packet_num: The 1-based index of the packet in the spec or capture file.

    Example::

        import warnings
        from packeteer.sanitise import sanitise, SanitiseOptions, PersonalDataWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            sanitise(spec, SanitiseOptions(scan_pii=True))

        for w in caught:
            if issubclass(w.category, PersonalDataWarning):
                print(w.message.kind, w.message.text, "in packet", w.message.packet_num)

    """

    kind:       str
    match:      str
    text:       str
    packet_num: int

    def __init__(
        self, message: str, kind: str, match: str, text: str, packet_num: int,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.match = match
        self.text = text
        self.packet_num = packet_num


# ── PII detection patterns ────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# Tier 1: RFC 5322 display names immediately before <email@domain>.
# Group 1 = quoted name ("Alice Smith"), group 2 = 2-3 unquoted title-case words.
_RFC5322_NAME_RE = re.compile(
    r'(?:"([^"]{2,60})"'
    r'|([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2}))'
    r'(?=\s*<[a-zA-Z0-9._%+\-]+@)',
)

# Tier 2: structured field labels preceding 2-3 title-case words.
# full_name / full-name before bare "name" so the longer form is preferred.
_LABEL_NAME_RE = re.compile(
    r'(?<![a-zA-Z0-9_])'
    r'(?:full[_\-]?name|name|contact|recipient|sender|from|to)'
    r'\s*[=:]\s*'
    r'([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){1,2})',
    re.IGNORECASE,
)


def _excerpt(text: str, start: int, end: int, context: int = 40) -> str:
    """Return the match at ``[start:end]`` with up to *context* surrounding chars."""
    left_start = max(0, start - context)
    right_end  = min(len(text), end + context)
    prefix = "…" if left_start > 0 else ""
    suffix = "…" if right_end < len(text) else ""
    return f"{prefix}{text[left_start:right_end]}{suffix}"


def _scan_emails(text: str) -> list[tuple[str, int, int]]:
    """Return ``(email, start, end)`` for each email address found in *text*."""
    return [(m.group(), m.start(), m.end()) for m in _EMAIL_RE.finditer(text)]


def _scan_names(text: str) -> list[tuple[str, int, int]]:
    """Return ``(name, start, end)`` for potential personal names in *text*.

    Applies two tiers:

    * **Tier 1** — RFC 5322 display names directly before ``<email@domain>``.
    * **Tier 2** — 2–3 consecutive title-case words after a recognised field
      label (``name:``, ``from:``, ``recipient:``, etc.).

    """
    results: list[tuple[str, int, int]] = []
    for m in _RFC5322_NAME_RE.finditer(text):
        if m.group(1) is not None:
            results.append((m.group(1), m.start(1), m.end(1)))
        else:
            results.append((m.group(2), m.start(2), m.end(2)))
    for m in _LABEL_NAME_RE.finditer(text):
        results.append((m.group(1), m.start(1), m.end(1)))
    return results


def _scan_utf8_payload(pl: dict[str, Any], packet_num: int) -> None:
    """Emit :class:`PersonalDataWarning` for PII found in *pl* (a utf8 payload dict)."""
    text = pl.get("data")
    if not isinstance(text, str):
        return
    seen: set[tuple[str, str]] = set()
    for email, start, end in _scan_emails(text):
        key: tuple[str, str] = ("email", email.lower())
        if key in seen:
            continue
        seen.add(key)
        excerpt = _excerpt(text, start, end)
        warnings.warn(
            PersonalDataWarning(
                f"Possible email address in packet {packet_num} payload: {excerpt!r}",
                kind="email",
                match=excerpt,
                text=email,
                packet_num=packet_num,
            ),
            stacklevel=2,
        )
    for name, start, end in _scan_names(text):
        key = ("name", name.lower())
        if key in seen:
            continue
        seen.add(key)
        excerpt = _excerpt(text, start, end)
        warnings.warn(
            PersonalDataWarning(
                f"Possible name in packet {packet_num} payload: {excerpt!r}",
                kind="name",
                match=excerpt,
                text=name,
                packet_num=packet_num,
            ),
            stacklevel=2,
        )


#: Kinds that are a *finding* — something identifying was located in the data.
#: Anything else is a report that something could not be checked, and keeps the
#: wording whoever raised it chose.
_FINDING_KINDS: dict[str, str] = {"email": "email address", "name": "name"}


def _consolidate_pii_warnings(caught: list, path: str | None = None) -> None:
    """Re-emit non-PII warnings unchanged; consolidate the rest, one per finding.

    Consolidation is per ``(kind, text)``, so a capture with the same finding
    in ninety packets reports it once, naming them.  A ``kind`` that is not a
    finding — ``"unredacted"``, meaning something could not be checked —
    keeps its own message, because a description written for a specific
    situation says more than a template can.
    """
    # groups maps (kind, text) -> [first_excerpt, [packet_num, ...], message]
    groups: dict[tuple[str, str], list] = {}
    for w in caught:
        if issubclass(w.category, PersonalDataWarning):
            assert isinstance(w.message, PersonalDataWarning)
            key = (w.message.kind, w.message.text)
            if key not in groups:
                groups[key] = [w.message.match, [], str(w.message)]
            groups[key][1].append(w.message.packet_num)
        else:
            warnings.warn_explicit(
                w.message, w.category, w.filename, w.lineno, source=w.source,
            )
    file_hint = f" in {path!r}" if path is not None else ""
    for (kind, text), (first_excerpt, packet_nums, message) in sorted(groups.items()):
        unique_nums = sorted(set(packet_nums))
        n = len(unique_nums)
        pkt_str = ", ".join(str(p) for p in unique_nums)
        count_str = f"{n} packet{'s' if n != 1 else ''}"
        if kind in _FINDING_KINDS:
            summary = (f"Possible {_FINDING_KINDS[kind]} found in "
                       f"{count_str}{file_hint} (packet_num {pkt_str}): "
                       f"{first_excerpt!r}")
        else:
            summary = f"{message}  Affects {count_str}{file_hint} " \
                      f"(packet_num {pkt_str})."
        warnings.warn(
            PersonalDataWarning(
                summary,
                kind=kind,
                match=first_excerpt,
                text=text,
                packet_num=unique_nums[0],
            ),
            stacklevel=3,
        )

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
            including those inside nested tunnel specs (ipip, gre, etherip,
            pseudowire).
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
        dhcp_xids: Zero the 32-bit transaction ``xid`` field in every
            ``dhcp`` section.  DHCP IP fields (``ciaddr``, ``yiaddr``,
            ``siaddr``, ``giaddr``) and IP addresses in DHCP options are
            always sanitised when a ``dhcp`` section is present (controlled by
            *ips* for addresses; *macs* for ``chaddr``).
        http_headers: Replace the values of sensitive HTTP headers in every
            ``http`` section with ``"[redacted]"``.  Affected headers:
            ``Host``, ``Cookie``, ``Set-Cookie``, ``Authorization``,
            ``Location``, ``Referer``, ``Origin``.  Non-sensitive structural
            headers (``Content-Type``, ``Content-Length``, etc.) are left
            unchanged.
        scan_pii: Scan UTF-8 encoded payloads for potential personal data and
            emit a :class:`PersonalDataWarning` for each finding.  Only
            payloads with ``"encoding": "utf8"`` are scanned; hex payloads
            are not.  Detected items: email addresses (regex) and personal
            names (RFC 5322 display names and field-label patterns such as
            ``name: Alice Smith``).  The packet spec is not modified.

    """

    ips:          bool = True
    macs:         bool = True
    ports:        bool = False
    payload:      bool = False
    timestamps:   bool = False
    dns_ids:      bool = False
    dhcp_xids:    bool = False
    http_headers: bool = False
    scan_pii:     bool = True


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


# ── DHCP option code constants (duplicated to avoid import) ──────────────────

_DHCP_OPT_SUBNET_MASK  = 1
_DHCP_OPT_ROUTER       = 3
_DHCP_OPT_DNS_SERVER   = 6
_DHCP_OPT_HOSTNAME     = 12
_DHCP_OPT_DOMAIN_NAME  = 15
_DHCP_OPT_REQUESTED_IP = 50
_DHCP_OPT_SERVER_ID    = 54

# ── DHCP sanitisation helper ──────────────────────────────────────────────────

def _sanitise_dhcp(dhcp: dict, r: _Replacer, opts: SanitiseOptions) -> None:
    """Sanitise a ``dhcp`` section dict in-place."""
    if opts.dhcp_xids:
        dhcp["xid"] = 0
    if opts.ips:
        for field_name in ("ciaddr", "yiaddr", "siaddr", "giaddr"):
            if field_name in dhcp and dhcp[field_name] != "0.0.0.0":
                dhcp[field_name] = r.ip(dhcp[field_name])
    if opts.macs and "chaddr" in dhcp:
        raw = dhcp["chaddr"]
        if isinstance(raw, str) and len(raw) >= 12 and raw != "00" * 16:
            mac_str = ":".join(raw[i:i+2] for i in range(0, 12, 2))
            new_mac = r.mac(mac_str).replace(":", "")
            dhcp["chaddr"] = new_mac + raw[12:]
    for opt in dhcp.get("options", []):
        code = opt.get("code", 0)
        if opts.ips:
            if code in (_DHCP_OPT_SUBNET_MASK, _DHCP_OPT_REQUESTED_IP, _DHCP_OPT_SERVER_ID):
                if "address" in opt:
                    opt["address"] = r.ip(opt["address"])
            elif code == _DHCP_OPT_ROUTER:
                opt["routers"] = [r.ip(a) for a in opt.get("routers", [])]
            elif code == _DHCP_OPT_DNS_SERVER:
                opt["servers"] = [r.ip(a) for a in opt.get("servers", [])]


# ── HTTP sensitive header names (case-insensitive check uses .lower()) ────────

_HTTP_SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "host", "cookie", "set-cookie", "authorization",
    "location", "referer", "origin",
})

_HTTP_REDACTED = "[redacted]"


def _sanitise_http(http: dict, opts: SanitiseOptions) -> None:
    """Sanitise an ``http`` section dict in-place."""
    if not opts.http_headers:
        return
    headers = http.get("headers")
    if not isinstance(headers, dict):
        return
    for key in list(headers):
        if key.lower() in _HTTP_SENSITIVE_HEADERS:
            headers[key] = _HTTP_REDACTED


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


def _sanitise_sll(sll: dict, r: _Replacer, opts: SanitiseOptions) -> None:
    """Rewrite the link-layer address in a Linux cooked (``sll``/``sll2``) section."""
    if opts.macs and ":" in sll.get("address", ""):
        sll["address"] = r.mac(sll["address"])


def _sanitise_arp(arp: dict, r: _Replacer, opts: SanitiseOptions) -> None:
    """Sanitise the MAC and IP addresses inside an ``arp`` section in-place.

    Uses the same replacement tables as the Ethernet/IP layers, so an address
    maps to the same synthetic value wherever it appears in the capture.
    """
    if opts.macs:
        for key in ("sender_mac", "target_mac"):
            if key in arp:
                arp[key] = r.mac(arp[key])
    if opts.ips:
        for key in ("sender_ip", "target_ip"):
            if key in arp:
                arp[key] = r.ip(arp[key])


# ── ICMP and ICMPv6 ───────────────────────────────────────────────────────────
#
# An ICMP payload is opaque bytes to the rest of packeteer, but several message
# types carry addresses inside it — a Neighbour Discovery target, a link-layer
# address option, a router's own prefix, or the whole packet that provoked an
# error.  Left alone they defeat the sanitisation around them: an IPv6
# link-local address is EUI-64 derived from the MAC, so a leaked link-layer
# option reconstructs the address that was replaced.
#
# The bytes are rewritten in place rather than parsed into a model, which is
# how `_sanitise_dns` works too: `sanitise` needs to understand enough
# structure to redact, and nothing more.  The ICMP checksum is not carried in a
# packet spec, so a rebuild recomputes it and the edited payload stays valid.

_ICMPV6_NEIGHBOUR_SOLICITATION = 135
_ICMPV6_NEIGHBOUR_ADVERTISEMENT = 136
_ICMPV6_ROUTER_SOLICITATION = 133
_ICMPV6_ROUTER_ADVERTISEMENT = 134
_ICMPV6_REDIRECT = 137
_ICMPV6_ECHO = frozenset({128, 129})
#: Types whose payload is the packet that provoked them.
_ICMPV6_QUOTING = frozenset({1, 2, 3, 4})
_ICMPV4_ECHO = frozenset({0, 8})
_ICMPV4_QUOTING = frozenset({3, 4, 5, 11, 12})
_ICMPV4_REDIRECT = 5

_ND_OPT_SOURCE_LINK_ADDR = 1
_ND_OPT_TARGET_LINK_ADDR = 2
_ND_OPT_PREFIX_INFORMATION = 3

_IPV6_ADDR_LEN = 16
_IPV4_ADDR_LEN = 4
_ND_OPT_UNIT = 8


def _payload_bytes(pl: dict) -> bytes | None:
    """Return a payload section's bytes, whichever way it was encoded."""
    data = pl.get("data")
    if not isinstance(data, str):
        return None
    if pl.get("encoding") == "utf8":
        return data.encode("utf-8")
    try:
        return bytes.fromhex(data)
    except ValueError:
        return None


def _set_payload_bytes(pl: dict, data: bytes) -> None:
    """Write *data* back to a payload section, as hex."""
    pl["data"] = data.hex()
    pl.pop("encoding", None)


def _replace_ipv6(buf: bytearray, offset: int, r: _Replacer) -> None:
    """Rewrite the IPv6 address at *offset* through *r*."""
    if offset + _IPV6_ADDR_LEN > len(buf):
        return
    original = ipaddress.IPv6Address(bytes(buf[offset:offset + _IPV6_ADDR_LEN]))
    buf[offset:offset + _IPV6_ADDR_LEN] = ipaddress.IPv6Address(
        r.ip(str(original)),
    ).packed


def _replace_ipv4(buf: bytearray, offset: int, r: _Replacer) -> None:
    """Rewrite the IPv4 address at *offset* through *r*."""
    if offset + _IPV4_ADDR_LEN > len(buf):
        return
    original = ipaddress.IPv4Address(bytes(buf[offset:offset + _IPV4_ADDR_LEN]))
    buf[offset:offset + _IPV4_ADDR_LEN] = ipaddress.IPv4Address(
        r.ip(str(original)),
    ).packed


def _replace_mac(buf: bytearray, offset: int, r: _Replacer) -> None:
    """Rewrite the six-byte MAC at *offset* through *r*.

    Through the same replacer as the Ethernet header, so a link-layer option
    and the frame that carries it end up with the same synthetic address and
    the capture still reads as coherent traffic.
    """
    if offset + 6 > len(buf):
        return
    original = ":".join(f"{b:02x}" for b in buf[offset:offset + 6])
    buf[offset:offset + 6] = bytes.fromhex(r.mac(original).replace(":", ""))


def _sanitise_nd_options(buf: bytearray, start: int, r: _Replacer,
                         opts: SanitiseOptions) -> None:
    """Rewrite addresses in the Neighbour Discovery options from *start*."""
    offset = start
    while offset + 2 <= len(buf):
        opt_type = buf[offset]
        length = buf[offset + 1] * _ND_OPT_UNIT
        if length == 0 or offset + length > len(buf):
            return
        if opts.macs and opt_type in (_ND_OPT_SOURCE_LINK_ADDR,
                                      _ND_OPT_TARGET_LINK_ADDR):
            _replace_mac(buf, offset + 2, r)
        elif opts.ips and opt_type == _ND_OPT_PREFIX_INFORMATION:
            # The advertised prefix is the network's own, and identifies it.
            _replace_ipv6(buf, offset + 16, r)
        offset += length


def _sanitise_quoted_packet(buf: bytearray, start: int, r: _Replacer,
                            opts: SanitiseOptions) -> None:
    """Rewrite the addresses of the packet an ICMP error quotes.

    The quoted bytes are a packet, header and all, so they carry the addresses
    of the exchange that provoked the error — the same ones sanitised in the
    frame around them.
    """
    if start >= len(buf):
        return
    version = buf[start] >> 4
    if version == 6 and start + 40 <= len(buf):
        if opts.ips:
            _replace_ipv6(buf, start + 8, r)
            _replace_ipv6(buf, start + 24, r)
        _sanitise_quoted_ports(buf, start + 40, buf[start + 6], r, opts)
    elif version == 4 and start + 20 <= len(buf):
        header_len = (buf[start] & 0x0F) * 4
        if opts.ips:
            _replace_ipv4(buf, start + 12, r)
            _replace_ipv4(buf, start + 16, r)
        _sanitise_quoted_ports(buf, start + header_len, buf[start + 9], r, opts)


def _sanitise_quoted_ports(buf: bytearray, start: int, protocol: int,
                           r: _Replacer, opts: SanitiseOptions) -> None:
    """Rewrite the ports of a quoted TCP or UDP header, if asked for."""
    if not opts.ports or protocol not in (6, 17) or start + 4 > len(buf):
        return
    for offset in (start, start + 2):
        port = int.from_bytes(buf[offset:offset + 2], "big")
        buf[offset:offset + 2] = r.port(port).to_bytes(2, "big")


def _sanitise_icmpv6_payload(buf: bytearray, icmp_type: int, r: _Replacer,
                             opts: SanitiseOptions, packet_num: int) -> None:
    """Rewrite whatever addresses an ICMPv6 message of *icmp_type* carries."""
    if icmp_type in (_ICMPV6_NEIGHBOUR_SOLICITATION,
                     _ICMPV6_NEIGHBOUR_ADVERTISEMENT):
        if opts.ips:
            _replace_ipv6(buf, 0, r)
        _sanitise_nd_options(buf, _IPV6_ADDR_LEN, r, opts)
    elif icmp_type == _ICMPV6_REDIRECT:
        if opts.ips:
            _replace_ipv6(buf, 0, r)
            _replace_ipv6(buf, _IPV6_ADDR_LEN, r)
        _sanitise_nd_options(buf, 2 * _IPV6_ADDR_LEN, r, opts)
    elif icmp_type == _ICMPV6_ROUTER_SOLICITATION:
        _sanitise_nd_options(buf, 0, r, opts)
    elif icmp_type == _ICMPV6_ROUTER_ADVERTISEMENT:
        # Reachable time and retransmit timer come first, then the options.
        _sanitise_nd_options(buf, 8, r, opts)
    elif icmp_type in _ICMPV6_QUOTING:
        _sanitise_quoted_packet(buf, 0, r, opts)
    elif icmp_type not in _ICMPV6_ECHO:
        _warn_unknown_icmp("ICMPv6", icmp_type, packet_num)


def _sanitise_icmpv4_payload(pkt: dict, buf: bytearray, icmp_type: int,
                             r: _Replacer, opts: SanitiseOptions,
                             packet_num: int) -> None:
    """Rewrite whatever addresses an ICMPv4 message of *icmp_type* carries."""
    if icmp_type in _ICMPV4_QUOTING:
        if icmp_type == _ICMPV4_REDIRECT and opts.ips:
            _sanitise_icmpv4_gateway(pkt, r)
        _sanitise_quoted_packet(buf, 0, r, opts)
    elif icmp_type not in _ICMPV4_ECHO:
        _warn_unknown_icmp("ICMP", icmp_type, packet_num)


def _sanitise_icmpv4_gateway(pkt: dict, r: _Replacer) -> None:
    """Rewrite a Redirect's gateway address.

    It sits in the four header bytes a packet spec records as *identifier* and
    *sequence*, because those are what an Echo puts there.
    """
    transport = pkt.get("transport", {})
    high = transport.get("identifier")
    low = transport.get("sequence")
    if not isinstance(high, int) or not isinstance(low, int):
        return
    gateway = ipaddress.IPv4Address((high << 16) | low)
    packed = int(ipaddress.IPv4Address(r.ip(str(gateway))))
    transport["identifier"] = packed >> 16
    transport["sequence"] = packed & 0xFFFF


def _warn_unknown_icmp(family: str, icmp_type: int, packet_num: int) -> None:
    """Say that a message type could not be checked for addresses.

    Silence is what let this go unnoticed: a type nobody wrote a rule for may
    carry an address, and passing it through quietly is indistinguishable from
    having redacted it.
    """
    what = f"{family} type {icmp_type}"
    warnings.warn(
        PersonalDataWarning(
            f"{what} is not one this version knows how to redact; if it "
            f"carries addresses they are still in the output.  Use "
            f"SanitiseOptions(payload=True) to zero it.",
            kind="unredacted",
            match=what,
            text=what,
            packet_num=packet_num,
        ),
        stacklevel=2,
    )


def _sanitise_icmp(pkt: dict, r: _Replacer, opts: SanitiseOptions,
                   packet_num: int) -> None:
    """Redact the addresses inside an ICMP or ICMPv6 payload."""
    protocol = pkt.get("network", {}).get("protocol")
    if protocol not in ("icmp", "icmpv6"):
        return
    transport = pkt.get("transport", {})
    icmp_type = transport.get("type")
    if not isinstance(icmp_type, int):
        return
    payload = pkt.get("payload")
    data = _payload_bytes(payload) if isinstance(payload, dict) else None
    if data is None:
        # A Redirect keeps its gateway in the header, so it is worth doing even
        # with no payload at all.
        if protocol == "icmp" and icmp_type == _ICMPV4_REDIRECT and opts.ips:
            _sanitise_icmpv4_gateway(pkt, r)
        return

    buf = bytearray(data)
    if protocol == "icmpv6":
        _sanitise_icmpv6_payload(buf, icmp_type, r, opts, packet_num)
    else:
        _sanitise_icmpv4_payload(pkt, buf, icmp_type, r, opts, packet_num)
    _set_payload_bytes(payload, bytes(buf))


def _sanitise_payloads(pkt: dict, opts: SanitiseOptions) -> None:
    """Zero the payload data and opaque SCTP chunk fields of *pkt* in-place.

    A no-op unless ``opts.payload`` is set.
    """
    if not opts.payload:
        return
    pl = pkt.get("payload")
    if isinstance(pl, dict) and isinstance(pl.get("data"), str):
        if pl.get("encoding") == "utf8":
            pl["data"] = "00" * len(pl["data"].encode("utf-8"))
            del pl["encoding"]
        else:
            pl["data"] = "00" * (len(pl["data"]) // 2)
    t = pkt.get("transport")
    if isinstance(t, dict) and t.get("protocol") == "sctp":
        for chunk in t.get("chunks", []):
            # Zero all opaque binary hex fields present in any chunk type.
            for key in ("data", "params", "cookie", "info", "causes", "value"):
                if key in chunk and isinstance(chunk[key], str):
                    chunk[key] = "00" * (len(chunk[key]) // 2)


def _sanitise_app_layers(pkt: dict, r: _Replacer, opts: SanitiseOptions) -> None:
    """Redact each registered protocol's section of *pkt* in-place.

    A protocol registered without a
    :attr:`~packeteer.protocols.AppProtocol.sanitise` callable is skipped, and
    its section passes through untouched — which is why the registry treats
    that as a deliberate choice rather than a default worth having.
    """
    for proto in protocols.registered():
        if proto.sanitise is not None and proto.name in pkt:
            proto.sanitise(pkt[proto.name], r, opts)


#: Keys that mean at least part of a packet was understood.  A packet with a
#: payload and none of these is a frame the parser could not decode — an
#: unsupported link type — so nothing in it has been redacted.
_STRUCTURAL_KEYS: frozenset[str] = frozenset({
    "ethernet", "sll", "sll2", "loopback", "arp", "network", "transport",
    "mpls", "pppoe", "ipip", "gre", "etherip", "pseudowire", "ah", "esp",
    "vxlan", "geneve", "gtpu",
})


def _warn_undecoded(pkt: dict, packet_num: int) -> None:
    """Say when a packet was never decoded, so nothing in it was redacted.

    An unsupported link type turns a whole frame into an opaque payload.  That
    is indistinguishable, in a spec, from a packet that genuinely carried only
    bytes — and the difference is the difference between a sanitised file and
    one that merely looks sanitised.
    """
    if "payload" not in pkt or any(key in pkt for key in _STRUCTURAL_KEYS):
        return
    warnings.warn(
        PersonalDataWarning(
            "A packet was not decoded — most likely an unsupported link type — "
            "so the whole frame is one opaque payload and nothing in it has "
            "been redacted.  Use SanitiseOptions(payload=True) to zero it.",
            kind="unredacted",
            match="undecoded frame",
            text="undecoded frame",
            packet_num=packet_num,
        ),
        stacklevel=2,
    )


def _maybe_scan_pii(pkt: dict, packet_num: int) -> None:
    """Scan *pkt*'s UTF-8 payload for PII if present."""
    pl = pkt.get("payload")
    if isinstance(pl, dict) and pl.get("encoding") == "utf8":
        _scan_utf8_payload(pl, packet_num)


def _sanitise_packet(
    pkt: dict, r: _Replacer, opts: SanitiseOptions, packet_num: int = 0,
) -> None:
    """In-place sanitisation of one packet dict (already deep-copied)."""
    if opts.scan_pii:
        _maybe_scan_pii(pkt, packet_num)

    if "ethernet" in pkt:
        _sanitise_ethernet(pkt["ethernet"], r, opts)

    for sll_key in ("sll", "sll2"):
        if sll_key in pkt:
            _sanitise_sll(pkt[sll_key], r, opts)

    if "arp" in pkt:
        _sanitise_arp(pkt["arp"], r, opts)

    if opts.ips and "network" in pkt:
        _sanitise_network(pkt["network"], r)

    if opts.ports and "transport" in pkt:
        t = pkt["transport"]
        if "src_port" in t:
            t["src_port"] = r.port(t["src_port"])
        if "dst_port" in t:
            t["dst_port"] = r.port(t["dst_port"])

    _warn_undecoded(pkt, packet_num)

    # Before _sanitise_payloads, which may zero the bytes this reads.
    _sanitise_icmp(pkt, r, opts, packet_num)

    _sanitise_payloads(pkt, opts)

    if opts.timestamps and "packet_metadata" in pkt:
        meta = pkt["packet_metadata"]
        meta["timestamp_s"] = 0
        for key in ("timestamp_us", "timestamp_ns"):
            if key in meta:
                meta[key] = 0

    _sanitise_app_layers(pkt, r, opts)

    # ── Tunnel recursion ──────────────────────────────────────────────────────
    # AH protects cleartext content (transport mode) or an inner IP packet
    # (tunnel mode), so its nested addresses/ports are sanitised too.  ESP's
    # payload is opaque ciphertext and carries no addresses.
    for tunnel_key in ("ipip", "gre", "etherip", "pseudowire", "ah"):
        if tunnel_key not in pkt:
            continue
        _sanitise_packet(pkt[tunnel_key], r, opts, packet_num)


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

    # Imported here rather than at module level, and this is load-bearing.
    # packeteer.app pulls in packeteer.generate, which this module otherwise
    # does not need — it is stdlib-only and works on spec dicts.  But importing
    # it is also what registers DNS, DHCP and HTTP, so without this call a
    # caller who imported only packeteer.sanitise would find an empty registry
    # and silently redact no application sections at all.  See the isolation
    # test in src/tests/test_sanitise_registry.py.
    from packeteer.app import register_builtins

    register_builtins()

    result = copy.deepcopy(config)
    r = _Replacer()

    if options.scan_pii:
        with warnings.catch_warnings(record=True) as _caught:
            warnings.filterwarnings("always", category=PersonalDataWarning)
            for i, pkt in enumerate(result["packets"], 1):
                _sanitise_packet(pkt, r, options, i)
        _consolidate_pii_warnings(_caught)
    else:
        for pkt in result["packets"]:
            _sanitise_packet(pkt, r, options)

    return result
