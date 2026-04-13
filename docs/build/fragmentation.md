# IP Fragmentation

Both IPv4 (RFC 791) and IPv6 (RFC 8200 §4.5) fragmentation are supported
at two levels: a high-level {meth}`packeteer.generator.builder.PacketBuilder.fragment`
method and the low-level {func}`packeteer.generator.fragmentation.fragment_ipv4` /
{func}`packeteer.generator.fragmentation.fragment_ipv6` functions.

---

## High-level — `PacketBuilder.fragment(mtu)`

Call `.fragment(mtu)` instead of `.build()`.  It returns a list of fully
assembled packet bytes, one per fragment.  When the payload fits in a single
datagram the list has exactly one element.

```python
from packeteer.generator import PacketBuilder

# Split a 4000-byte UDP payload across ~3 IPv4 fragments (MTU 1500)
fragments = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp()
    .payload(size=4000)
    .fragment(mtu=1500)
)
print(f"{len(fragments)} fragments")
for i, frag in enumerate(fragments):
    print(f"  fragment {i+1}: {len(frag)} bytes")

# IPv6 fragmentation uses the Fragment Extension Header (RFC 8200 §4.5)
fragments = (PacketBuilder()
    .ip(src="fe80::1", dst="fe80::2")
    .tcp()
    .payload(size=3000)
    .fragment(mtu=1280)   # IPv6 minimum MTU
)

# With an Ethernet header on every fragment
fragments = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp()
    .payload(size=4000)
    .fragment(mtu=1500)
)
```

The `mtu` value is the maximum IP datagram size **excluding** any prefix
headers such as Ethernet — each fragment's IP layer (plus its payload) will
fit within `mtu` bytes.

Fragmentation can also be triggered per-packet from the CLI via the
`packet_metadata.mtu` field in the {doc}`../packet-spec/format`.

---

## Low-level — `fragment_ipv4` / `fragment_ipv6`

For fine-grained control, call the underlying functions directly:

```python
import socket
from packeteer.generator import fragment_ipv4, fragment_ipv6
from packeteer.generator import IPHeader
from packeteer.generator import IPv6Header
from packeteer.generator import EthernetHeader, ETHERTYPE_IPV4, ETHERTYPE_IPV6

# IPv4 — with an Ethernet prefix
ip_hdr  = IPHeader("10.0.0.1", "10.0.0.2", socket.IPPROTO_UDP, ttl=64)
eth_hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
frags   = fragment_ipv4(ip_hdr, transport_data, mtu=576, eth_header=eth_hdr)

# IPv6 — no Ethernet prefix
ip_hdr = IPv6Header("::1", "::2", next_header=17, hop_limit=64)  # 17 = UDP
frags  = fragment_ipv6(ip_hdr, transport_data, mtu=1280, eth_header=None)
```

Pass `eth_header=None` to produce raw IP fragments with no layer-2 framing.

---

## RFC behaviour

| Detail | IPv4 (RFC 791) | IPv6 (RFC 8200 §4.5) |
|--------|----------------|----------------------|
| Fragment header | IP Flags + Fragment Offset | Fragment Extension Header (8 bytes, next header = 44) |
| DF flag | Always cleared (0) on fragments | N/A |
| MF flag | Set on all but the last fragment | M flag in extension header |
| Offset units | 8 bytes | 8 bytes |
| Identification | 16-bit, shared across all fragments | 32-bit, shared across all fragments |
| Min fragment data | 8 bytes (except last) | 8 bytes (except last) |

See {doc}`../reference/rfc-references` for the full RFC list.
