# Sanitiser internals

`replacer.py` implements `sanitise()`, which replaces sensitive field values
in a packet spec dict with synthetic but structurally valid equivalents.

## Design goals

- **Consistency** — the same original value always maps to the same synthetic
  value within a single `sanitise()` call.  A conversation between two hosts
  remains a conversation between the same two synthetic hosts in every packet.
- **IANA-safe ranges** — replacements come from ranges reserved for
  documentation, testing, or local administration, so a sanitised capture can
  never be mistaken for live traffic:

  | Field | Synthetic range |
  |---|---|
  | IPv4 | RFC 5737 documentation blocks: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (762 usable addresses) |
  | IPv6 | `2001:db8::/32` (RFC 3849): allocated as `2001:db8::<n+1>` |
  | MAC | Locally-administered unicast: `02:00:00:<b2>:<b1>:<b0>` |
  | Port | 10 000–59 999 (sequential allocation) |
  | Payload | Zero-filled hex string of the same byte length |

## `_Replacer` — per-call state

A `_Replacer` instance is created fresh for each `sanitise()` call.  It holds:

- Four mapping dicts: `_ipv4_map`, `_ipv6_map`, `_mac_map`, `_port_map`
  — mapping original values to synthetic ones.
- Four counters tracking the next allocation index.

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

`_sanitise_packet(pkt, r, opts)` walks one packet dict in place (the dict is
already a deep copy at this point):

1. Replace MAC addresses in the `"ethernet"` section.
2. Replace IP addresses in the `"network"` section.
3. Optionally replace ports in `"transport"`.
4. Optionally zero out `"payload.data"` (hex string, length preserved).
5. Optionally zero `"packet_metadata"` timestamps.
6. For each tunnel key (`"ipip"`, `"gre"`, `"etherip"`): call
   `_sanitise_ethernet` on the inner `"ethernet"` section (if present), then
   recurse into `_sanitise_packet(inner, r, opts)`.

The tunnel recursion handles arbitrarily nested tunnels without any special
limit.

## `SanitiseOptions`

```python
@dataclass
class SanitiseOptions:
    ips:        bool = True    # replace src/dst in every "network" section
    macs:       bool = True    # replace src_mac/dst_mac in every "ethernet" section
    ports:      bool = False   # replace src_port/dst_port
    payload:    bool = False   # zero payload.data and SCTP chunk data fields
    timestamps: bool = False   # zero packet_metadata timestamps
```

The defaults (IP and MAC replacement only) are enough for most sharing
scenarios.  Ports and payload data are opt-in because replacing them changes
the observable application behaviour of the capture.

## SCTP payload handling

When `opts.payload` is `True`, the sanitiser also zeros all opaque binary hex
fields inside SCTP chunks: `data`, `params`, `cookie`, `info`, `causes`, and
`value`.  This is handled by iterating `transport["chunks"]` inside
`_sanitise_packet`.
