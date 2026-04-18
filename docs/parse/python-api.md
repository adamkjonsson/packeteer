# Python API

## `parse_packet` — single raw packet

{func}`packeteer.parse.core.parse_packet` decodes a raw `bytes` object through
all protocol layers and returns a {class}`~packeteer.parse.core.ParsedPacket`
dataclass with each layer in its own typed field.

```python
from packeteer.generate import PacketBuilder
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW
from packeteer.parse import parse_packet

# Build a test packet, then parse it back
raw = (PacketBuilder()
    .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=443, flags=0x002)
    .payload(size=32)
    .build()
)

pkt = parse_packet(raw, link_type=LINKTYPE_ETHERNET)

print(pkt.ethernet.src_mac)       # "00:00:00:00:00:01"
print(pkt.ip.src, "->", pkt.ip.dst)  # "10.0.0.1 -> 10.0.0.2"
print(pkt.transport.dst_port)     # 443
print(pkt.transport.flags)        # 2
print(len(pkt.payload))           # 32
```

Pass `link_type=LINKTYPE_RAW` for packets without an Ethernet header:

```python
raw = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").udp().build()
pkt = parse_packet(raw, link_type=LINKTYPE_RAW)
```

## `ParsedPacket` fields

| Field | Type | Content |
|-------|------|---------|
| `ethernet` | `EthernetHeader \| None` | Ethernet II header; includes VLAN tag as `ethernet.vlan_tag` |
| `mpls` | `list[MPLSLabel]` | MPLS label stack entries, outermost first; empty when absent |
| `pppoe` | `PPPoEHeader \| None` | PPPoE session or discovery header |
| `ip` | `IPHeader \| IPv6Header \| None` | IP header (v4 or v6) |
| `ipip` | `bool` | `True` when the IP protocol field is 4 or 41 (IP-in-IP); `tunneled` holds the inner packet |
| `gre` | `GREHeader \| None` | GRE tunnel header; `tunneled` holds the inner packet |
| `etherip` | `EtherIPHeader \| None` | EtherIP tunnel header; `tunneled` holds the inner frame |
| `tunneled` | `ParsedPacket \| None` | Recursively parsed inner packet for IP-in-IP, GRE, or EtherIP; may itself have a `tunneled` field |
| `transport` | `TCPHeader \| UDPHeader \| ICMPHeader \| ICMPv6Header \| SCTPHeader \| None` | Transport-layer header |
| `dns` | `DNSMessage \| None` | Decoded DNS or mDNS message when the transport is UDP or TCP on port 53 or 5353; `None` otherwise |
| `payload` | `bytes` | Bytes after the last parsed header; empty when `dns` is set |
| `ts_sec` | `int` | Capture timestamp — whole seconds (set by `parse_pcap_packet`) |
| `ts_frac` | `int` | Capture timestamp — microsecond or nanosecond fraction (set by `parse_pcap_packet`) |

## DNS and mDNS packets

When a UDP or TCP packet has port 53 or 5353 as source or destination, the
payload is automatically decoded as a DNS message (RFC 1035) or mDNS message
(RFC 6762).  The result is stored in `pkt.dns`; `pkt.payload` is empty in that
case.

```python
from packeteer.generate import PacketBuilder, DNSMessage, DNSQuestion, DNS_TYPE_A
from packeteer.pcap import LINKTYPE_ETHERNET
from packeteer.parse import parse_packet

# Build a DNS query, then parse it back
query = DNSMessage(id=0xABCD, questions=[DNSQuestion("example.com.")])
raw = (PacketBuilder()
    .ethernet()
    .ip(src="192.168.1.1", dst="8.8.8.8")
    .udp(src_port=54321, dst_port=53)
    .dns(query)
    .build()
)

pkt = parse_packet(raw)
assert pkt.dns is not None
print(pkt.dns.id)                          # 0xABCD
print(pkt.dns.questions[0].name)           # "example.com."
print(pkt.dns.questions[0].qtype)          # 1  (DNS_TYPE_A)
```

mDNS traffic on port 5353 is parsed identically.  The parsed
`DNSQuestion.unicast_response` and `DNSResourceRecord.cache_flush` fields
reflect the QU and cache-flush bits set by the sender:

```python
from packeteer.generate import (
    PacketBuilder, DNSMessage, DNSFlags, DNSQuestion,
    DNS_TYPE_A, MDNS_PORT, MDNS_ADDR_IPV4,
)
from packeteer.parse import parse_packet

mdns_q = DNSMessage(
    id=0,
    flags=DNSFlags(qr=False, rd=False),
    questions=[DNSQuestion("mydevice.local.", DNS_TYPE_A,
                           unicast_response=True)],
)
raw = (PacketBuilder()
    .ethernet()
    .ip(src="192.168.1.2", dst=MDNS_ADDR_IPV4)
    .udp(src_port=MDNS_PORT, dst_port=MDNS_PORT)
    .dns(mdns_q)
    .build()
)

pkt = parse_packet(raw)
assert pkt.dns is not None
print(pkt.dns.questions[0].unicast_response)  # True
```

DNS over TCP is parsed the same way — the 2-byte length prefix is stripped
automatically when the transport port is 53 or 5353 and the transport is TCP.

Name compression pointers (RFC 1035 §4.1.4) are fully resolved, and pointer
loops are detected and reported as `ValueError`.  Failed DNS parses leave the
raw bytes in `pkt.payload` unchanged so nothing is silently lost.

## Tunnel packets

Tunneled packets are parsed recursively.  The inner packet is a full
`ParsedPacket` stored in `tunneled`, and may itself have its own `tunneled`
field for double-nested tunnels.

```python
# GRE tunnel: outer IP carries a GRE header, inner IP carries TCP
raw = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .gre(key=42)
    .ip(src="192.168.1.1", dst="192.168.1.2")
    .tcp(dst_port=80)
    .build()
)
pkt = parse_packet(raw)

print(pkt.ip.src)                       # "10.0.0.1" (outer)
print(pkt.gre.key)                      # 42
print(pkt.tunneled.ip.src)              # "192.168.1.1" (inner)
print(pkt.tunneled.transport.dst_port)  # 80

# IP-in-IP
raw = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .ip(src="192.168.1.1", dst="192.168.1.2")
    .udp(dst_port=53)
    .build()
)
pkt = parse_packet(raw, link_type=LINKTYPE_RAW)
assert pkt.ipip is True
print(pkt.tunneled.ip.src)             # "192.168.1.1"
print(pkt.tunneled.transport.dst_port) # 53
```

## `parse_pcap_packet` — one record from a pcap file

{func}`packeteer.parse.core.parse_pcap_packet` parses one
`(data, ts_sec, ts_frac)` tuple from a pcap file and stamps the resulting
`ParsedPacket` with the capture timestamp.

```python
from packeteer.parse import read_pcap
from packeteer.parse import parse_pcap_packet

pcap = read_pcap(path="capture.pcap")
for record in pcap.packets:
    pkt = parse_pcap_packet(record, pcap.header)
    if pkt.transport is not None:
        print(f"{pkt.ts_sec}.{pkt.ts_frac:06d}  "
              f"{pkt.ip.src}:{pkt.transport.src_port} -> "
              f"{pkt.ip.dst}:{pkt.transport.dst_port}")
```

`pcap.header.nanoseconds` tells you whether `ts_frac` is in microseconds or
nanoseconds.

## `parse_pcap_file` — whole file to JSON

{func}`packeteer.parse.core.parse_pcap_file` reads every packet in a pcap
file and returns the complete packet spec as a string — the same output as
`packeteer parse`.

```python
from packeteer.parse import parse_pcap_file

# Print JSON to stdout
json_str = parse_pcap_file(path="capture.pcap")
print(json_str)

# Save to a file
with open("config.json", "w") as f:
    f.write(parse_pcap_file(path="capture.pcap"))
```

Pass a file-like object instead of a path when the data is already in memory:

```python
import io

with open("capture.pcap", "rb") as f:
    data = f.read()

json_str = parse_pcap_file(file_object=io.BytesIO(data))
```

Pass an `output` dict to embed a top-level `metadata` block in the result (the
same effect as `--replay-pcap` on the CLI):

```python
json_str = parse_pcap_file(
    path="capture.pcap",
    output={"from_file": "capture.pcap", "type": "pcap"},
)
```

## Converting a `ParsedPacket` to a config dict

Use {func}`packeteer.parse.to_config.update_config` and
{func}`packeteer.parse.to_config.apply_tunneled` to serialise individual parsed
packets into the packet spec dict format, then wrap them with
{func}`packeteer.parse.to_config.to_packet_spec` and serialise with
{func}`packeteer.parse.to_config.to_json_string`.

```python
from packeteer.parse import read_pcap
from packeteer.parse import parse_pcap_packet
from packeteer.parse import (
    update_config, apply_tunneled, to_packet_spec, to_json_string,
)

pcap = read_pcap(path="capture.pcap")
ts_key = "timestamp_ns" if pcap.header.nanoseconds else "timestamp_us"

packet_configs = []
for record in pcap.packets:
    pkt = parse_pcap_packet(record, pcap.header)
    cfg = {}
    if pkt.ethernet is not None:
        update_config(cfg, pkt.ethernet)
    for label in pkt.mpls:
        update_config(cfg, label)
    if pkt.pppoe is not None:
        update_config(cfg, pkt.pppoe)
    if pkt.ip is not None:
        update_config(cfg, pkt.ip)
    if pkt.ipip or pkt.gre is not None or pkt.etherip is not None:
        apply_tunneled(cfg, pkt)
    elif pkt.transport is not None:
        update_config(cfg, pkt.transport)
        if pkt.payload:
            update_config(cfg, pkt.payload)
    cfg["packet_metadata"] = {"timestamp_s": pkt.ts_sec, ts_key: pkt.ts_frac}
    packet_configs.append(cfg)

json_str = to_json_string(to_packet_spec(packet_configs))
```

`update_config` dispatches on the type of the layer object:

| Argument type | Written to |
|---------------|-----------|
| `EthernetHeader` | `cfg["ethernet"]` |
| `MPLSLabel` | appended to `cfg["mpls"]` |
| `PPPoEHeader` | `cfg["pppoe"]` |
| `IPHeader` / `IPv6Header` | `cfg["network"]` |
| `TCPHeader` / `UDPHeader` / `ICMPHeader` / `ICMPv6Header` / `SCTPHeader` | `cfg["transport"]` |
| `DNSMessage` | `cfg["dns"]` |
| `bytes` | `cfg["payload"]["data"]` as hex |

`apply_tunneled` handles GRE, EtherIP, and IP-in-IP, which require the full
`ParsedPacket` context (including `tunneled`) and cannot be dispatched through
`update_config` alone.

## Per-protocol parser functions

The low-level parsers follow a uniform calling convention and can be used
independently when you only need one layer:

```python
def packet_parser(data: bytes) -> tuple[int, int | None, HeaderType | None]:
    ...
```

| Return position | Meaning |
|-----------------|---------|
| `[0]` | Bytes consumed; `0` means the parse failed |
| `[1]` | Next-layer identifier (EtherType, IP protocol number, …) |
| `[2]` | Parsed header dataclass, or `None` on failure |

```python
from packeteer.parse import ip_packet_parser, tcp_packet_parser

# Parse just the IP header from a raw IP packet
ip_size, ip_proto, ip_hdr = ip_packet_parser(raw_ip_bytes)
if ip_hdr is not None:
    print(ip_hdr.src, "->", ip_hdr.dst)

    # Continue to transport
    tcp_size, _, tcp_hdr = tcp_packet_parser(raw_ip_bytes[ip_size:])
    if tcp_hdr is not None:
        print("dst_port:", tcp_hdr.dst_port)
```

All per-protocol parsers are exported from the `packeteer.parse` top-level
package:

| Name | Module | Returns |
|------|--------|---------|
| `ethernet_packet_parser` | `packeteer.parse.ethernet` | `EthernetHeader` |
| `mpls_packet_parser` | `packeteer.parse.mpls` | `MPLSLabel` |
| `pppoe_packet_parser` | `packeteer.parse.pppoe` | `PPPoEHeader` |
| `ip_packet_parser` | `packeteer.parse.ip` | `IPHeader` / `IPv6Header` |
| `tcp_packet_parser` | `packeteer.parse.tcp` | `TCPHeader` |
| `udp_packet_parser` | `packeteer.parse.udp` | `UDPHeader` |
| `icmp_packet_parser` | `packeteer.parse.icmp` | `ICMPHeader` |
| `icmpv6_packet_parser` | `packeteer.parse.icmpv6` | `ICMPv6Header` |
| `gre_packet_parser` | `packeteer.parse.gre` | `GREHeader` |
| `etherip_packet_parser` | `packeteer.parse.etherip` | `EtherIPHeader` |
