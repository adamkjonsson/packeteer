# Python API

```python
from packeteer.sanitise import sanitise, SanitiseOptions

with open("capture.json") as f:
    config = json.load(f)

# Default: replace IPs, MACs, and DNS names
clean = sanitise(config)

# Replace everything
clean = sanitise(config, SanitiseOptions(
    ports=True,
    payload=True,
    timestamps=True,
    dns_ids=True,
    dhcp_xids=True,
))

# Replace only IPs, keep MACs
clean = sanitise(config, SanitiseOptions(macs=False))
```

```{eval-rst}
.. autoclass:: packeteer.sanitise.SanitiseOptions
   :members:
```

```{eval-rst}
.. autofunction:: packeteer.sanitise.sanitise
```

## DNS sanitisation

Whenever a packet spec contains a `dns` section, names and addresses inside
it are sanitised automatically — no extra option is needed.

**Domain names** are replaced at label level so that shared structure is
preserved.  Each unique DNS label (case-insensitive) maps consistently to
`label0`, `label1`, …  For example:

**Before:**
```json
{
  "dns": {
    "id": 4660,
    "questions": [{ "name": "mail.example.com.", "qtype": 1, "qclass": 1 }],
    "answers": [
      { "name": "mail.example.com.", "rtype": 1, "rclass": 1, "ttl": 300,
        "rdata": { "address": "93.184.216.34" } },
      { "name": "www.example.com.", "rtype": 5, "rclass": 1, "ttl": 300,
        "rdata": { "name": "host.example.com." } }
    ],
    "authority": [], "additional": []
  }
}
```

**After** (`sanitise` with defaults, `dns_ids=False`):
```json
{
  "dns": {
    "id": 4660,
    "questions": [{ "name": "label0.label1.label2.", "qtype": 1, "qclass": 1 }],
    "answers": [
      { "name": "label0.label1.label2.", "rtype": 1, "rclass": 1, "ttl": 300,
        "rdata": { "address": "192.0.2.1" } },
      { "name": "label3.label1.label2.", "rtype": 5, "rclass": 1, "ttl": 300,
        "rdata": { "name": "label4.label1.label2." } }
    ],
    "authority": [], "additional": []
  }
}
```

`example` → `label1` and `com` → `label2` are shared across all three names
because the same label always maps to the same synthetic value.  The A-record
address is replaced using the same IPv4 pool used for `network.src`/`dst`, so
an address that appears in both a DNS response and an IP header will receive
the same synthetic replacement.

**Transaction IDs** are kept by default.  Set `dns_ids=True` to zero them:

```python
clean = sanitise(config, SanitiseOptions(dns_ids=True))
```

**To keep A/AAAA RDATA addresses unchanged**, disable IP replacement:

```python
clean = sanitise(config, SanitiseOptions(ips=False))
```

## DHCP sanitisation

Whenever a packet spec contains a `dhcp` section, IP addresses and the client
hardware address inside it are sanitised automatically using the same mapping
tables as all other IP and MAC fields — no extra option is needed.

The following replacements are applied:

- **Fixed IP fields** — `ciaddr`, `yiaddr`, `siaddr`, and `giaddr` are
  replaced (skipped when the value is `"0.0.0.0"`).
- **Client hardware address** (`chaddr`) — the first six bytes (the MAC
  portion) are replaced using the MAC mapping table, then re-encoded as the
  full 16-byte hex string.  Controlled by `macs=True/False`.
- **Option IPs** — IP addresses in common options are replaced:
  - Code 1 (`DHCPOptSubnetMask`) — `address` field
  - Code 3 (`DHCPOptRouter`) — all addresses in `routers` list
  - Code 6 (`DHCPOptDNSServer`) — all addresses in `servers` list
  - Code 50 (`DHCPOptRequestedIP`) — `address` field
  - Code 54 (`DHCPOptServerID`) — `address` field

**Transaction IDs** (`xid`) are kept by default.  Set `dhcp_xids=True` to
zero them:

```python
clean = sanitise(config, SanitiseOptions(dhcp_xids=True))
```

**To keep DHCP IP fields unchanged**, disable IP replacement:

```python
clean = sanitise(config, SanitiseOptions(ips=False))
```

## Tunnel handling

Nested tunnel specs (`ipip`, `gre`, `etherip`) are walked recursively.  The
same mapping table is shared across all nesting levels, so an IP address that
appears as both an outer tunnel endpoint and an inner address will always
receive the same synthetic replacement.

Example — GRE tunnel before and after sanitising:

**Before:**
```json
{
  "network": { "src": "203.0.113.5", "dst": "203.0.113.10", "protocol": "gre" },
  "gre": {
    "network": { "src": "10.0.1.1", "dst": "10.0.1.2", "protocol": "tcp" },
    "transport": { "src_port": 55123, "dst_port": 443 }
  }
}
```

**After** (`sanitise` with defaults):
```json
{
  "network": { "src": "192.0.2.1", "dst": "192.0.2.2", "protocol": "gre" },
  "gre": {
    "network": { "src": "192.0.2.3", "dst": "192.0.2.4", "protocol": "tcp" },
    "transport": { "src_port": 55123, "dst_port": 443 }
  }
}
```

Ports are unchanged because `ports=True` was not given.
