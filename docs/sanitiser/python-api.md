# Python API

```python
from packeteer.sanitiser import sanitise, SanitiseOptions

with open("capture.json") as f:
    config = json.load(f)

# Default: replace IPs and MACs
clean = sanitise(config)

# Replace everything
clean = sanitise(config, SanitiseOptions(
    ports=True,
    payload=True,
    timestamps=True,
))

# Replace only IPs, keep MACs
clean = sanitise(config, SanitiseOptions(macs=False))
```

```{eval-rst}
.. autoclass:: packeteer.sanitiser.SanitiseOptions
   :members:
```

```{eval-rst}
.. autofunction:: packeteer.sanitiser.sanitise
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

Ports are unchanged because `--ports` was not given.
