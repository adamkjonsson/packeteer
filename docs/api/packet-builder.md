# `PacketBuilder`

**Import:** `from packeteer.generate import PacketBuilder`

{class}`~packeteer.generate.builder.PacketBuilder` is the primary entry point
for constructing raw network packets.  Each fluent method **appends** one
layer to an ordered stack; call `.build()` or `.fragment()` to assemble the
final bytes with all checksums computed automatically.

Because methods append rather than overwrite, the same method can be called
multiple times to produce advanced encapsulations:

- `.vlan()` twice → QinQ (IEEE 802.1ad) double-tagged frame
- `.mpls()` multiple times → MPLS label stack (RFC 3032)
- `.ip()` twice → IP-in-IP tunnel (RFC 2003 / RFC 4213)
- `.gre()` → GRE tunnel header (RFC 2784 / RFC 2890)
- `.etherip()` → EtherIP tunnel header (RFC 3378)

## Layer method reference

| Method | Description |
|--------|-------------|
| `.ethernet(src_mac, dst_mac, pad=False)` | Ethernet II header.  `pad=True` zero-pads the frame to the IEEE 802.3 minimum of 60 bytes. |
| `.vlan(vid, pcp=0, dei=0)` | 802.1Q VLAN tag.  Call twice for QinQ. |
| `.mpls(label, tc=0, ttl=64)` | MPLS label stack entry (RFC 3032).  S bit set automatically. |
| `.pppoe(code=0, session_id=0, tags=None)` | PPPoE header (RFC 2516).  `code=0` is a session frame; any other code is a discovery frame carrying TLV `tags`. |
| `.etherip()` | EtherIP tunnel header (RFC 3378).  Call after the outer `.ip()` and before the inner `.ethernet()`. |
| `.gre(key=None, seq=None, checksum=False)` | GRE tunnel header (RFC 2784 / RFC 2890).  Protocol Type and outer IP protocol (47) are set automatically from the next layer. |
| `.ip(src, dst, ttl=64, …)` | IPv4 or IPv6 header — auto-detected from `src`.  Call twice for IP-in-IP. |
| `.tcp(src_port=12345, dst_port=80, …)` | TCP transport header. |
| `.udp(src_port=12345, dst_port=80)` | UDP transport header. |
| `.icmp(type=8, code=0, identifier=1, sequence=1)` | ICMPv4 transport header (use with IPv4). |
| `.icmpv6(type=128, code=0, identifier=1, sequence=1)` | ICMPv6 transport header (use with IPv6). |
| `.payload(size=0, data=None)` | Set the payload.  `data` (bytes) takes precedence over `size` (random bytes). |

## Assembly methods

`.build()` assembles the complete packet and returns `bytes`.

`.fragment(mtu=1500)` fragments the packet and returns `list[bytes]`.  The
first IP layer in the stack is the fragmentation point.  See
{doc}`../build/fragmentation` for details.

## Full API

```{eval-rst}
.. autoclass:: packeteer.generate.builder.PacketBuilder
   :members:
   :undoc-members:
```
