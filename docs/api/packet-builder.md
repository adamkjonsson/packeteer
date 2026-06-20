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
- `.mpls()` + `.pseudowire()` → MPLS pseudowire with RFC 4385 control word
- `.ip()` twice → IP-in-IP tunnel (RFC 2003 / RFC 4213)
- `.gre()` → GRE tunnel header (RFC 2784 / RFC 2890)
- `.etherip()` → EtherIP tunnel header (RFC 3378)
- `.udp()` + `.vxlan()` → VXLAN tunnel header (RFC 7348)
- `.udp()` + `.geneve()` → GENEVE tunnel header (RFC 8926)
- `.udp()` + `.gtpu()` → GTP-U tunnel header (3GPP TS 29.281)
- `.ah()` → IPsec Authentication Header (RFC 4302) protecting the next layer(s)
- `.esp()` → IPsec ESP header (RFC 4303) with an opaque (encrypted) payload

## Layer method reference

| Method | Description |
|--------|-------------|
| `.ethernet(src_mac, dst_mac, pad=False)` | Ethernet II header.  `pad=True` zero-pads the frame to the IEEE 802.3 minimum of 60 bytes. |
| `.arp(operation=1, sender_mac=…, sender_ip=…, target_mac=…, target_ip=…, hardware_type=1, protocol_type=0x0800)` | ARP packet (RFC 826, IPv4 over Ethernet).  Terminal — call after `.ethernet()` with no IP/transport layer.  The Ethernet EtherType is set to `0x0806` automatically. |
| `.sll(packet_type=0, arphrd_type=1, address=…)` | Linux cooked-capture v1 pseudo header (`LINKTYPE_LINUX_SLL`, used by `tcpdump -i any`).  An alternative outermost layer to `.ethernet()`; the Protocol Type is set automatically from the next layer. |
| `.sll2(packet_type=0, arphrd_type=1, address=…, if_index=0)` | Linux cooked-capture v2 pseudo header (`LINKTYPE_LINUX_SLL2`, the modern `-i any` default). |
| `.vlan(vid, pcp=0, dei=0)` | 802.1Q VLAN tag.  Call twice for QinQ. |
| `.mpls(label, tc=0, ttl=64)` | MPLS label stack entry (RFC 3032).  S bit set automatically. |
| `.pseudowire(flags=0, frag=0, length=0, sequence=0)` | RFC 4385 pseudowire control word.  Call after the bottom-of-stack `.mpls()` and before the inner `.ethernet()` or `.ip()`. |
| `.pppoe(code=0, session_id=0, tags=None)` | PPPoE header (RFC 2516).  `code=0` is a session frame; any other code is a discovery frame carrying TLV `tags`. |
| `.etherip()` | EtherIP tunnel header (RFC 3378).  Call after the outer `.ip()` and before the inner `.ethernet()`. |
| `.gre(key=None, seq=None, checksum=False)` | GRE tunnel header (RFC 2784 / RFC 2890).  Protocol Type and outer IP protocol (47) are set automatically from the next layer. |
| `.vxlan(vni=0, flags=0x08)` | VXLAN tunnel header (RFC 7348).  Call after the outer `.udp()` and before the inner `.ethernet()`.  When the preceding `.udp()` is left on its default port, the destination port is set to 4789 automatically; an explicit non-default port is preserved. |
| `.geneve(vni=0, options=None, oam=False)` | GENEVE tunnel header (RFC 8926).  Call after the outer `.udp()`.  Protocol Type is set automatically from the next layer (inner `.ethernet()` or `.ip()`); the default UDP port is rewritten to 6081 like `.vxlan()`.  `options` is a list of `GeneveOption` TLVs. |
| `.gtpu(teid=0, message_type=255, sequence=None, n_pdu=None, extension_headers=None)` | GTP-U tunnel header (3GPP TS 29.281).  Call after the outer `.udp()`; a G-PDU carries the inner `.ip()` directly (no inner Ethernet).  The Length field, E/S/PN flags, and extension-header chaining are computed automatically; the default UDP port is rewritten to 2152. |
| `.ah(spi, sequence=0, icv=None, icv_len=12)` | IPsec Authentication Header (RFC 4302).  Call after `.ip()`; the protected content follows and stays in cleartext (AH does not encrypt).  AH's Next Header and the outer IP protocol (51) are set automatically.  Transport mode protects a transport header (`.ip().ah().tcp()`); tunnel mode protects an inner `.ip()` (`.ip().ah().ip().tcp()`).  `icv` defaults to `icv_len` random bytes, padded so the header is a multiple of 4 bytes. |
| `.esp(spi, sequence=0, payload=None, size=0, icv_len=0)` | IPsec ESP header (RFC 4303).  Call after `.ip()` (outer protocol 50).  Only the SPI + Sequence prefix is cleartext; the rest is opaque.  Pass `payload`/`size` for an explicit opaque payload, or append inner layers (`.esp().ip().tcp()`) — those assembled bytes become the opaque (would-be-encrypted) payload, so the packet parses back as opaque ESP. |
| `.ip(src, dst, ttl=64, …)` | IPv4 or IPv6 header — auto-detected from `src`.  Call twice for IP-in-IP. |
| `.hop_by_hop_options(options=None)` | IPv6 Hop-by-Hop Options extension header (RFC 8200 §4.3).  Call immediately after `.ip()` for an IPv6 address and before the transport method.  `options` is a list of `RouterAlertOption`, `JumboPayloadOption`, or `RawOption` objects; padding is added automatically. |
| `.tcp(src_port=12345, dst_port=80, …)` | TCP transport header. |
| `.udp(src_port=12345, dst_port=80)` | UDP transport header. |
| `.icmp(type=8, code=0, identifier=1, sequence=1)` | ICMPv4 transport header (use with IPv4). |
| `.icmpv6(type=128, code=0, identifier=1, sequence=1)` | ICMPv6 transport header (use with IPv6). |
| `.payload(size=0, data=None)` | Set the payload.  `data` (bytes) takes precedence over `size` (random bytes). |

## Assembly methods

`.build()` assembles the complete packet and returns `bytes`.

`.fragment(mtu=1500)` fragments the packet and returns `list[bytes]`.  The
first IP layer in the stack is the fragmentation point.  See
{doc}`fragmentation` for details.

## Full API

```{eval-rst}
.. autoclass:: packeteer.generate.builder.PacketBuilder
   :members:
   :undoc-members:
```
