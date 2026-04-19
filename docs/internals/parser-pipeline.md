# Parser pipeline

`parse_packet()` (in `packeteer/parse/parser.py`) is a linear state machine that
walks a raw byte string from left to right, dispatching to one sub-parser per
layer.

## Sub-parser contract

Every layer sub-parser is a callable with the signature:

```python
def packet_parser(data: bytes) -> tuple[int, Any, Any]:
    ...
    return consumed_bytes, next_layer_id, header_object
```

| Return value | Meaning |
|---|---|
| `consumed_bytes` | How many bytes at the start of `data` belong to this header.  `0` on parse failure. |
| `next_layer_id` | A value (EtherType, IP protocol number, …) that `parse_packet` uses to select the next sub-parser.  `None` when parsing should stop. |
| `header_object` | A populated dataclass, or `None` on failure. |

The top-level `parse_packet` advances the `remaining` byte string by
`consumed_bytes` after each successful parse, then uses `next_layer_id` to
decide what to parse next.

## Layer dispatch sequence

```
link_type
  |
  +- LINKTYPE_ETHERNET --→ _ethernet_parser
  |                              |  returns EtherType
  |                              v
  |                         MPLS loop (EtherType 0x8847/0x8848)
  |                              |  _mpls_parser repeated until BOS
  |                              v
  |                         PPPoE (EtherType 0x8863/0x8864)
  |                              |  _pppoe_parser; discovery → stop
  |                              v
  |                         IP (EtherType 0x0800/0x86DD)
  |
  +- LINKTYPE_RAW -------------→ IP
                                   |  ip_proto / next_header
                                   v
                     +-------------+---------------------------+
                   TCP/UDP/      IP-in-IP    GRE          EtherIP
                   ICMP/SCTP     (4, 41)    (47)          (97)
                   ----------    ---------  ----------    --------
                   transport     recurse    _gre_parser   _etherip_parser
                   parser        with       + recurse     + recurse with
                                 LINKTYPE_  with          LINKTYPE_
                                 RAW        LINKTYPE_RAW  ETHERNET
                                            (or ETHERNET
                                            for TEB)
```

## ParsedPacket result object

`ParsedPacket` is a flat dataclass with one field per protocol layer:

```python
@dataclass
class ParsedPacket:
    ethernet:  EthernetHeader | None
    mpls:      list[MPLSLabel]        # empty list when no MPLS labels
    pppoe:     PPPoEHeader | None
    ip:        IPHeader | IPv6Header | None
    ipip:      bool                   # True → outer IP proto is 4 or 41
    gre:       GREHeader | None
    etherip:   EtherIPHeader | None
    tunneled:  ParsedPacket | None    # inner packet for ipip/gre/etherip
    transport: TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | SCTPHeader | None
    dns:       DNSMessage | None      # set when UDP port 53 or 5353
    dhcp:      DHCPMessage | None     # set when UDP port 67 or 68
    http:      HTTPMessage | None     # set when TCP port 80 or 8080
    payload:   bytes                  # leftover bytes after all headers
    ts_sec:    int                    # from pcap record
    ts_frac:   int                    # microseconds or nanoseconds
```

`ipip`, `gre`, and `etherip` are mutually exclusive: at most one tunnel type
is active per layer.  When a tunnel is present, `tunneled` holds the inner
`ParsedPacket` parsed recursively.

## Tunnel recursion

When the IP protocol field indicates a tunnel, `parse_packet` calls itself
recursively on the bytes that follow the tunnel header:

- **IP-in-IP** (proto 4 or 41): call `parse_packet(remaining, LINKTYPE_RAW)`.
  No inner Ethernet frame.
- **GRE**: call `parse_packet(remaining[gre_size:], ...)`.  Link type is
  `LINKTYPE_ETHERNET` for TEB (Protocol Type `0x6558`), `LINKTYPE_RAW` for
  IPv4/IPv6-in-GRE.
- **EtherIP**: call `parse_packet(remaining[etherip_size:], LINKTYPE_ETHERNET)`.
  EtherIP always carries a full inner Ethernet frame.

There is no recursion depth limit, so triple-nested tunnels parse correctly.

## Application-layer dispatch

After the transport header is parsed, `parse_pcap_packet` (in `core.py`)
attempts to decode the payload as an application-layer message:

| Protocol | Condition | Field set |
|---|---|---|
| DNS / mDNS | UDP port 53 or 5353 | `ParsedPacket.dns` |
| DHCP | UDP port 67 or 68 | `ParsedPacket.dhcp` |
| HTTP/1.x | TCP port 80 or 8080 | `ParsedPacket.http` |

Each attempt is best-effort: if the payload cannot be decoded as the expected
protocol, the raw bytes remain in `ParsedPacket.payload` and the corresponding
field stays `None`.  At most one application-layer field is set per packet —
DNS, DHCP, and HTTP are tested in that order and the first successful parse wins.

## Serialisation to packet spec

`parse_pcap_file()` pipes every `ParsedPacket` through `to_config.py`:

1. For each flat layer (`ethernet`, MPLS labels, `pppoe`, `ip`), call
   `update_config(cfg, header)`.  This dispatches on the header type and
   writes the appropriate JSON key (`"ethernet"`, `"mpls"`, `"pppoe"`,
   `"network"`).

2. For tunnel layers, call `apply_tunneled(cfg, pkt)`.  This dispatches on
   which tunnel is active and calls the corresponding private function
   (`_apply_ipip`, `_apply_gre`, or `_apply_etherip`), each of which recurses
   into the inner `ParsedPacket` to build the nested dict.

3. For non-tunnel packets, call `update_config(cfg, pkt.transport)`, then —
   in order — `update_config` for whichever of `dns`, `dhcp`, or `http` is
   set, or for `payload` if none are.

4. Wrap the list of per-packet dicts in a top-level `{"metadata": …, "packets": […]}`
   structure with `to_packet_spec()`, then serialise to JSON with `to_json_string()`.

The JSON key names for the `"network"` section are unified across IPv4 and
IPv6: both use `"src"`, `"dst"`, `"ttl"`, and `"protocol"`.  IPv4-only fields
(`"tos"`, `"identification"`, `"flags"`, `"fragment_offset"`) and IPv6-only
fields (`"traffic_class"`, `"flow_label"`) are written only when present and
non-default.
