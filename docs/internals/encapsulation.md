# Encapsulation internals

Encapsulation in packeteer is split into two concerns:

1. **`PacketBuilder`** handles arbitrary ad-hoc encapsulation for single
   packets constructed by hand.
2. **`stream_encap.py`** provides a descriptor-based API used by the stream
   generators to wrap complete streams in a consistent encapsulation stack.

## Tag-based vs tunnel-based encapsulation

| Class | Type | What it adds |
|---|---|---|
| `VLANEncap` | tag-based | 4-byte 802.1Q tag between Ethernet and IP |
| `QinQEncap` | tag-based | two VLAN tags (8 bytes) |
| `MPLSEncap` | tag-based | one or more 4-byte MPLS label entries |
| `PPPoEEncap` | tag-based | 6-byte PPPoE header + 2-byte PPP protocol field |
| `GREEncap` | tunnel | outer IP + GRE header; stream IPs become inner |
| `EtherIPEncap` | tunnel | outer IP + 2-byte EtherIP header + inner Ethernet |
| `IPIPEncap` | tunnel | outer IP only; stream IPs become inner |
| `VXLANEncap` | tunnel | outer IP + UDP:4789 + 8-byte VXLAN header + inner Ethernet |
| `GeneveEncap` | tunnel | outer IP + UDP:6081 + GENEVE header (+ TLV options) + inner Ethernet |
| `GTPUEncap` | tunnel | outer IP + UDP:2152 + GTP-U header (+ ext headers) + inner IP (no Ethernet) |
| `AHEncap` | tunnel | outer IP (proto 51) + AH header + inner IP (visible — AH does not encrypt) |
| `ESPEncap` | tunnel | outer IP (proto 50) + ESP header + inner IP (opaque — ESP encrypts) |

Tag-based encapsulations are transparent to IP: they sit between the Ethernet
header and the first IP header and do not introduce a second IP layer.

Tunnel encapsulations wrap the entire inner IP datagram: the stream's
`client_ip` / `server_ip` become the inner IP endpoints, and the outer IP
header carries the tunnel `src_ip` / `dst_ip`.

## `_apply_encap` — inserting layers into PacketBuilder

`_apply_encap(b, encap, src_mac, dst_mac)` iterates the normalised encap list
(a `list[StreamEncap]`) and calls `_apply_single` for each entry.

`_apply_single` maps each encap type to the corresponding `PacketBuilder`
method calls:

```python
# VLAN
b.vlan(vid=encap.vid, pcp=encap.pcp, dei=encap.dei)

# GRE  (outer IP + GRE; caller adds inner IP next)
b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
b.gre(key=encap.key)   # key omitted when None

# EtherIP  (outer IP + EtherIP + inner Ethernet; caller adds inner IP next)
b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
b.etherip()
b.ethernet(src_mac=src_mac, dst_mac=dst_mac)

# VXLAN  (outer IP + UDP:4789 + VXLAN + inner Ethernet; caller adds inner IP next)
b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
b.udp(src_port=encap.udp_src_port, dst_port=VXLAN_PORT)
b.vxlan(vni=encap.vni)
b.ethernet(src_mac=src_mac, dst_mac=dst_mac)

# GENEVE  (outer IP + UDP:6081 + GENEVE + inner Ethernet; caller adds inner IP next)
b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
b.udp(src_port=encap.udp_src_port, dst_port=GENEVE_PORT)
b.geneve(vni=encap.vni, options=encap.options)
b.ethernet(src_mac=src_mac, dst_mac=dst_mac)

# GTP-U  (outer IP + UDP:2152 + GTP-U; caller adds inner IP next — no inner Ethernet)
b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
b.udp(src_port=encap.udp_src_port, dst_port=GTPU_PORT)
b.gtpu(teid=encap.teid, sequence=encap.sequence, n_pdu=encap.n_pdu,
       extension_headers=encap.extension_headers)

# IPsec AH  (outer IP proto 51 + AH; caller adds inner IP next — stays visible)
b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
b.ah(spi=encap.spi, sequence=encap.sequence, icv_len=encap.icv_len)

# IPsec ESP  (outer IP proto 50 + ESP; caller adds inner IP next — becomes opaque)
b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
b.esp(spi=encap.spi, sequence=encap.sequence, icv_len=encap.icv_len)
```

After `_apply_encap` returns, the caller appends the inner IP and transport
layers.  `PacketBuilder._assemble_range` then fills in all protocol-number
fields (EtherTypes, IP protocol numbers, GRE Protocol Types) from right to
left.

## `_encap_ip_start` — locating the fragmentation point

When `mtu` is set on a stream, each packet is fragmented at the outermost
IP header.  `_encap_ip_start(encap, include_ethernet)` computes the byte
offset of that IP header by accumulating the sizes of any tag-based
encapsulations that precede it:

```
include_ethernet=True → start with offset 14

VLANEncap   →  + 4
QinQEncap   →  + 8
MPLSEncap   →  + 4 × number of labels
PPPoEEncap  →  + 8  (6-byte PPPoE header + 2-byte PPP protocol field)

GRE / EtherIP / IPIP / VXLAN / GENEVE / GTP-U / AH / ESP  →  stop (outer IP is at current offset)
```

For example, `[VLANEncap(100), GREEncap(...)]` with Ethernet gives offset
`14 + 4 = 18`: the outer IP header for the GRE tunnel starts at byte 18 of
the assembled packet, so fragmentation applies to the GRE outer datagram, and
the VLAN tag and outer Ethernet header are copied intact to every fragment.

## `_fix_encap_prefix` — PPPoE length patching

After fragmentation, the per-fragment IP size differs from the original.  PPPoE
requires its 2-byte payload length field to equal `2 + ip_fragment_length` (the
`2` accounts for the PPP protocol field that follows the PPPoE header).

`_fix_encap_prefix(prefix, encap, ip_frag_len)` detects a `PPPoEEncap` in the
encap list and patches the PPPoE payload length in the prefix bytes.  The
PPPoE header is always the last L2 encap before the IP header, so its start
offset within `prefix` is always `len(prefix) - 8` regardless of any VLAN or
MPLS tags that precede it.

## Stacking encapsulations

`EncapSpec = StreamEncap | list[StreamEncap] | None`

Callers may pass either a single descriptor or a list.  `_as_list(encap)`
normalises both forms to a list.  Layers are applied in order, outermost
first, so:

```python
encap=[MPLSEncap(labels=[100, 200]), IPIPEncap(src_ip="203.0.113.1", dst_ip="203.0.113.2")]
```

produces: `eth → MPLS(100) → MPLS(200) → outer-IP → inner-IP → TCP`.

There is no enforcement of the encapsulation order beyond what the
`PacketBuilder` produces, but the conventional ordering (outermost first) is:
VLAN/QinQ or MPLS or PPPoE, then a tunnel type.
