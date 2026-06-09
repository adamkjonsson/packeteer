# Parsing Captures

packeteer can decode any pcap or pcapng file into a structured Python
representation — either a JSON packet spec or a hierarchy of typed dataclasses.

## Whole-file parsing

The simplest starting point is {func}`packeteer.parse.core.parse_pcap_file`,
which reads every packet in a file and returns the complete packet spec as a
JSON string — the same output as `packeteer parse`:

```python
from packeteer.parse import parse_pcap_file

json_str = parse_pcap_file(path="capture.pcap")
print(json_str[:200])
```

Pass `path` for a file on disk, or `file_object` for an in-memory buffer:

```python
import io

with open("capture.pcap", "rb") as f:
    data = f.read()

json_str = parse_pcap_file(file_object=io.BytesIO(data))
```

The returned string is valid JSON with a top-level `"packets"` array and a
`"metadata"` block — file type, timestamp precision, and link type are all
auto-detected from the file header.

If a capture declares the wrong link-layer type in its header — which would
otherwise garble the output — pass `link_type` to override it.  The override
also flows into `metadata.link_type`, so the resulting spec rebuilds with the
corrected type:

```python
from packeteer.pcap import LINKTYPE_RAW

json_str = parse_pcap_file(path="capture.pcap", link_type=LINKTYPE_RAW)
```

## Filtering during parse

Pass a {class}`packeteer.filter.PacketFilter` to keep only the packets you
care about.  All criteria are AND-combined:

```python
from packeteer.filter import PacketFilter
from packeteer.parse import parse_pcap_file
import json

f = PacketFilter(
    proto   = "tcp",
    port    = ["80", "443"],
    src     = ["10.0.0.0/8"],
)

spec = json.loads(parse_pcap_file(path="capture.pcap", packet_filter=f))
print(f"Kept {len(spec['packets'])} packets")
```

Prefix any value with `!` to negate it:

```python
# Non-TCP only
PacketFilter(proto="!tcp")

# Ignore port-80 traffic
PacketFilter(dst_port=["!80"])

# Hosts outside a specific subnet
PacketFilter(src=["!10.0.0.0/24"])
```

The `app` criterion filters by decoded application layer:

```python
# Only DNS traffic (UDP/TCP port 53 or 5353)
PacketFilter(app="dns")

# Everything except HTTP
PacketFilter(app="!http")
```

## Packet-level parsing

{func}`packeteer.parse.core.parse_packet` decodes a single raw `bytes` object
and returns a {class}`~packeteer.parse.core.ParsedPacket` dataclass with one
typed field per protocol layer:

```python
from packeteer.generate import PacketBuilder, TCP_SYN
from packeteer.pcap import LINKTYPE_ETHERNET
from packeteer.parse import parse_packet

raw = (PacketBuilder()
    .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=443, flags=TCP_SYN)
    .payload(size=32)
    .build()
)

pkt = parse_packet(raw, link_type=LINKTYPE_ETHERNET)

print(pkt.ethernet.src_mac)        # "00:00:00:00:00:01"
print(pkt.ip.src, "->", pkt.ip.dst)  # "10.0.0.1 -> 10.0.0.2"
print(pkt.transport.dst_port)      # 443
print(len(pkt.payload))            # 32
```

For raw-IP packets (no Ethernet header), use `LINKTYPE_RAW`:

```python
from packeteer.pcap import LINKTYPE_RAW

pkt = parse_packet(raw, link_type=LINKTYPE_RAW)
```

## Reading a pcap file packet-by-packet

When you need the capture timestamp alongside each parsed packet, read the
file with {func}`packeteer.pcap.read_pcap` and call
{func}`packeteer.parse.core.parse_pcap_packet` on each record:

```python
from packeteer.parse import parse_pcap_packet
from packeteer.pcap import read_pcap

pcap = read_pcap(path="capture.pcap")
for record in pcap.packets:
    pkt = parse_pcap_packet(record, pcap.header)
    if pkt.transport is not None:
        print(
            f"{pkt.ts_sec}.{pkt.ts_frac:06d}  "
            f"{pkt.ip.src}:{pkt.transport.src_port} -> "
            f"{pkt.ip.dst}:{pkt.transport.dst_port}"
        )
```

`pcap.header.nanoseconds` is `True` when `ts_frac` is in nanoseconds rather
than microseconds.

## Application-layer decoding

DNS, DHCP, and HTTP payloads are decoded automatically based on port number.
The result appears in `pkt.dns`, `pkt.dhcp`, or `pkt.http`:

```python
from packeteer.generate import PacketBuilder, DNSMessage, DNSQuestion
from packeteer.pcap import LINKTYPE_ETHERNET
from packeteer.parse import parse_packet

query = DNSMessage(id=0xABCD, questions=[DNSQuestion("example.com.")])
raw = (PacketBuilder()
    .ethernet()
    .ip(src="192.168.1.1", dst="8.8.8.8")
    .udp(src_port=54321, dst_port=53)
    .dns(query)
    .build()
)

pkt = parse_packet(raw)
print(pkt.dns.id)                   # 0xABCD
print(pkt.dns.questions[0].name)    # "example.com."
```

When `pkt.dns` (or `pkt.http`) is set, `pkt.payload` is empty — nothing is
silently lost.  A failed parse leaves the raw bytes in `pkt.payload` unchanged.

## Tunnel packets

Tunneled packets are parsed recursively.  The inner packet is a full
`ParsedPacket` in `pkt.tunneled`:

```python
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
```

The same pattern works for pseudowires.  The RFC 4385 control word is in
`pkt.pseudowire`; the inner frame is in `pkt.tunneled`:

```python
raw = (PacketBuilder()
    .ethernet()
    .mpls(label=100)
    .pseudowire(sequence=42)
    .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=80)
    .build()
)
pkt = parse_packet(raw)

print(pkt.mpls[0].label)               # 100
print(pkt.pseudowire.sequence)         # 42
print(pkt.tunneled.ip.src)             # "10.0.0.1" (inner)
print(pkt.tunneled.transport.dst_port) # 80
```

Note: `PacketFilter` matches on the outer layer only — the inner addresses
and ports inside a tunnel are not inspected.

## Next steps

- {doc}`sanitising` — replace sensitive fields before sharing a capture
- {doc}`../packet-spec/format` — complete field reference for every parsed layer
