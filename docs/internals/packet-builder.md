# PacketBuilder internals

`PacketBuilder` (in `packeteer/generate/builder.py`) assembles complete raw
packet bytes from a sequence of protocol layers.  Callers append layers via
fluent methods (`.ethernet()`, `.ip()`, `.tcp()`, …), then call `.build()` or
`.fragment()` to produce bytes.

## Internal representation

Every layer method appends a dataclass object to `self._layers`, a plain
Python list.  Protocol-number fields that depend on the *next* layer — `ethertype`
on Ethernet, `protocol` on IPv4, `next_header` on IPv6 — are stored as `0` at
append time and resolved during assembly.

```python
# After: builder.ethernet().ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80)
self._layers = [
    EthernetHeader(dst_mac=..., src_mac=..., ethertype=0),  # placeholder
    IPHeader(src="10.0.0.1", dst="10.0.0.2", protocol=0),  # placeholder
    TCPHeader(src_port=12345, dst_port=80, ...),
]
```

## Right-to-left assembly

`_assemble_range(start, end, data)` iterates the slice `_layers[start:end]`
from **right to left** (innermost first), prepending each layer's bytes to
`data`.  At each step, `next_layer = self._layers[i + 1]` is consulted to
fill the protocol-number placeholder.

```
  index 0         index 1         index 2
  Ethernet   <-    IP         <-    TCP         <- payload bytes
  (ethertype      (protocol         |
   filled from     filled from      |
   _layers[1])    _layers[2])       v
                                 _assemble_range builds right-to-left
```

The `next_layer` lookup always uses the **full** `self._layers` list, not the
slice boundaries, so layers at the edge of a sub-range (e.g. during
fragmentation) correctly see the layer just outside the range.

## Protocol-number maps

Three dictionaries drive the protocol-number lookups:

| Map | Key type | Value |
|-----|----------|-------|
| `_ETHERTYPE_MAP` | layer dataclass type | EtherType for Ethernet/VLAN |
| `_IP_PROTO_MAP` | layer dataclass type | IP protocol number |
| `_GRE_PROTO_MAP` | layer dataclass type | GRE Protocol Type |

A fourth map `_PPP_PROTO_MAP` maps `IPHeader` / `IPv6Header` to the 2-byte
PPP protocol number inserted after a PPPoE session header.

PPPoE is handled as a special case in `_ethertype_for()` because it needs two
different EtherTypes depending on `layer.code` (session vs discovery).

`PseudowireHeader` does not appear in any of these maps.  It is handled directly
in `_assemble_range` by calling `_build_pseudowire_header(layer, data)`, which
prepends the 4-byte RFC 4385 control word to the assembled inner payload.  The
surrounding MPLS label automatically sets its S (bottom-of-stack) bit to `1`
because `PseudowireHeader` is not an `MPLSLabel`.

## IP cloning

IP headers are immutable dataclasses.  `_assemble_range` cannot modify the
stored placeholder in place, so it creates a copy with the correct protocol
number using `_clone_ip()` or `_clone_ipv6()` before passing it to the build
function.

## Checksum computation

Checksums are computed by the individual `_build_*` functions, not by
`PacketBuilder` itself:

- **IP**: `_build_ip_header()` in `ip.py` computes the header checksum using
  RFC 1071 ones-complement addition.
- **TCP / UDP**: `_build_tcp_header()` / `_build_udp_header()` compute the
  checksum over a pseudo-header (12 bytes for IPv4, 40 bytes for IPv6) plus
  the header and payload.  The pseudo-header is constructed on-demand from the
  `(src, dst, ip_version)` tuple returned by `_ip_context()`.
- **SCTP**: `_build_sctp_packet()` in `sctp.py` uses CRC-32c (Castagnoli,
  RFC 9260 §6.8).  The CRC is initialised to zero, computed over the full
  packet, then written back into the checksum field.
- **ICMPv6**: `_build_icmpv6_header()` uses a pseudo-header with the IPv6 source
  and destination addresses, matching RFC 4443 §2.3.
- **GRE** (when `checksum=True`): `_build_gre_header()` computes an RFC 1071
  checksum over the GRE header and payload.

## Fragmentation

`.fragment(mtu)` is implemented in terms of `_assemble_range`:

1. Find the first (outermost) IP layer at index `k`.
2. Call `_assemble_range(k + 1, len(_layers), payload_bytes)` to build
   everything to the right of the IP header: transport header, any inner IP
   headers, and application payload.
3. Pass the result to `fragment_ipv4()` or `fragment_ipv6()` in
   `packeteer/generate/fragmentation.py`.
4. Build the prefix (everything to the left of the IP header) with
   `_assemble_range(0, k, b"")`.
5. Prepend the prefix to every fragment.

IPv4 fragmentation uses the standard Flags / Fragment Offset fields (RFC 791).
Each fragment (except the last) carries a payload rounded down to a multiple
of 8 bytes, as required by the RFC.

IPv6 fragmentation inserts an 8-byte Fragment Extension Header (next header =
44, RFC 8200 §4.5) between the IPv6 base header and each chunk.  The extension
header carries the original transport protocol number, a 13-bit offset, and a
32-bit identification value.

Maximum data per fragment:
- IPv4: `(mtu - 20) & ~7`  (20 = minimum IPv4 header size)
- IPv6: `(mtu - 40 - 8) & ~7`  (40 = IPv6 base header, 8 = fragment extension header)
