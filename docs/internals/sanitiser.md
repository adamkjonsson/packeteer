# Sanitiser internals

`packeteer/sanitise.py` implements `sanitise()`, which replaces sensitive field values
in a packet spec dict with synthetic but structurally valid equivalents.

## Design goals

- **Consistency** — the same original value always maps to the same synthetic
  value within a single `sanitise()` call.  A conversation between two hosts
  remains a conversation between the same two synthetic hosts in every packet.
- **IANA-safe ranges** — replacements come from ranges reserved for
  documentation, testing, or local administration, so a sanitised capture can
  never be mistaken for live traffic:

  | Field | Synthetic range / strategy |
  |---|---|
  | IPv4 | RFC 5737 documentation blocks: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (762 usable addresses) |
  | IPv6 | `2001:db8::/32` (RFC 3849): allocated as `2001:db8::<n+1>` |
  | MAC | Locally-administered unicast: `02:00:00:<b2>:<b1>:<b0>` |
  | Port | 10 000–59 999 (sequential allocation) |
  | Payload | Zero-filled hex string of the same byte length; `"encoding"` key removed (zeroed bytes are not printable text) |
  | DNS names | Each label replaced with `label0`, `label1`, … (consistent within a call); A/AAAA RDATA addresses replaced via the IP replacer |
  | DNS id | 16-bit transaction id zeroed (opt-in: `dns_ids=True`) |
  | DHCP XIDs | 32-bit `xid` field zeroed (opt-in: `dhcp_xids=True`); IP fields and IP-valued options replaced via the IP replacer; `chaddr` replaced via the MAC replacer |
  | HTTP headers | Sensitive header values replaced with `"[redacted]"` (opt-in: `http_headers=True`); affected headers: `Host`, `Cookie`, `Set-Cookie`, `Authorization`, `Location`, `Referer`, `Origin` |

## `_Replacer` — per-call state

A `_Replacer` instance is created fresh for each `sanitise()` call.  It holds:

- Five mapping dicts: `_ipv4_map`, `_ipv6_map`, `_mac_map`, `_port_map`,
  `_dns_label_map` — mapping original values to synthetic ones.
- Five counters tracking the next allocation index.

When a value is first seen, a new synthetic value is allocated from the
appropriate range and stored in the map.  Subsequent occurrences of the same
original value return the cached synthetic value.

```python
def ip(self, addr: str) -> str:
    if addr not in self._ipv4_map:
        self._ipv4_map[addr] = _ipv4_from_index(self._ipv4_counter)
        self._ipv4_counter += 1
    return self._ipv4_map[addr]
```

The IPv4 pool wraps modulo 762 if more than 762 distinct addresses appear.  The
IPv6 and MAC pools are effectively unlimited for practical input sizes.

## Recursive packet walking

`_sanitise_packet(pkt, r, opts, packet_num)` walks one packet dict in place
(the dict is already a deep copy at this point):

1. If `opts.scan_pii`, call `_maybe_scan_pii(pkt, packet_num)` to scan any
   UTF-8 payload for personal data (see below).
2. Replace MAC addresses in the `"ethernet"` section.
3. Replace the sender/target MAC and IP addresses in the `"arp"` section
   (via `_sanitise_arp`), using the same replacement tables as Ethernet/IP so an
   address maps consistently wherever it appears.
4. Replace IP addresses in the `"network"` section.
5. Optionally replace ports in `"transport"`.
6. Optionally zero out `"payload.data"` and opaque SCTP chunk fields, via
   `_sanitise_payloads` (byte length preserved; for UTF-8 payloads the byte
   count is derived from the string, and the `"encoding"` key is removed from
   the result).
7. Optionally zero `"packet_metadata"` timestamps.
8. For each tunnel key (`"ipip"`, `"gre"`, `"etherip"`): call
   `_sanitise_ethernet` on the inner `"ethernet"` section (if present), then
   recurse into `_sanitise_packet(inner, r, opts, packet_num)`.

The tunnel recursion handles arbitrarily nested tunnels without any special
limit.

## PII scanning

PII scanning is enabled by default (`scan_pii=True`).  `sanitise()` wraps its
packet loop in a `warnings.catch_warnings(record=True)` context, collects all
`PersonalDataWarning` instances emitted during the loop, and then re-emits one
consolidated warning per unique `(kind, text)` pair.

### Detection pipeline

`_maybe_scan_pii(pkt, packet_num)` checks whether the packet has a `"payload"`
section with `"encoding": "utf8"`, and if so calls `_scan_utf8_payload`.  Hex
payloads are never inspected.

`_scan_utf8_payload` runs two scanners against the decoded string:

- **`_scan_emails(text)`** — applies `_EMAIL_RE`, a regex for RFC 5321
  local-part + domain patterns.  Returns a list of `(text, start, end)` tuples.
- **`_scan_names(text)`** — runs two compiled regexes in order:
  - *Tier 1* (`_RFC5322_NAME_RE`): quoted or unquoted display names immediately
    followed by `<addr@domain>` (RFC 5322 mailbox syntax).
  - *Tier 2* (`_LABEL_NAME_RE`): two-or-more title-case words after a
    recognised field label (`name:`, `from:`, `recipient:`, `sender:`, `to:`,
    `contact:`, `full_name:`).

Each match is wrapped in a `_excerpt(text, start, end)` call that returns up to
40 characters of surrounding context with `…` ellipses when the window is
truncated.  A `PersonalDataWarning` is then emitted via `warnings.warn` with
`stacklevel=2`.

### Consolidation

After the packet loop, `_consolidate_pii_warnings(caught)` groups the collected
warnings by `(kind, text)`.  For each group it keeps the excerpt from the first
occurrence and the full list of packet numbers, then re-emits a single
consolidated `PersonalDataWarning`:

```
[PII] email 'alice@example.com' found in 2 packets (1, 3).
  Context: 'Contact: alice@example.com — Sales'
```

The consolidated warning's `packet_num` attribute holds the number of the first
packet where the finding appeared.

## `SanitiseOptions`

```python
@dataclass
class SanitiseOptions:
    ips:          bool = True    # replace src/dst in every "network" section
    macs:         bool = True    # replace src_mac/dst_mac in every "ethernet" section
    ports:        bool = False   # replace src_port/dst_port
    payload:      bool = False   # zero payload.data and SCTP chunk data fields
    timestamps:   bool = False   # zero packet_metadata timestamps
    dns_ids:      bool = False   # zero 16-bit DNS transaction id
    dhcp_xids:    bool = False   # zero 32-bit DHCP transaction xid
    http_headers: bool = False   # redact sensitive HTTP header values
    scan_pii:     bool = True    # scan UTF-8 payloads for emails and names
```

The defaults (IP/MAC replacement + PII scanning) cover the most common sharing
scenarios.  Ports and payload data are opt-in because replacing them changes
the observable application behaviour of the capture.  The `dns_ids`,
`dhcp_xids`, and `http_headers` flags are opt-in because the fields they
affect are not sensitive in all contexts.  PII scanning is opt-out
(`scan_pii=False`) because undisclosed personal data in a shared capture is
almost always unintentional.

## SCTP payload handling

When `opts.payload` is `True`, the sanitiser also zeros all opaque binary hex
fields inside SCTP chunks: `data`, `params`, `cookie`, `info`, `causes`, and
`value`.  This is handled by iterating `transport["chunks"]` inside
`_sanitise_packet`.
