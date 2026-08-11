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

## Payload boundaries and Ethernet padding

`pkt.payload` holds the bytes of the IP datagram that follow the transport
header — and nothing else.  A frame shorter than the IEEE 802.3 minimum is
zero-padded to 60 bytes by the sender, and that padding is part of the *frame*
but not of the *datagram*, so the parser discards it using the IP header's
length field:

```python
raw = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp(dst_port=9)
    .payload(data=b"\xde\xad\xbe\xef")
    .build()
)
len(raw)                    # 60 — padded up from 46
pkt = parse_packet(raw)
pkt.payload                 # b"\xde\xad\xbe\xef" — the 14 padding bytes are gone
```

The declared length is available on the parsed header, as `total_length` for
IPv4 (header + payload) and `payload_length` for IPv6 (everything after the
40-byte fixed header, including extension headers).  Both are `None` on a
header you constructed yourself — they are what the wire said, and the builder
derives the real value at build time.

Comparing the declared length against what you received detects a
snaplen-truncated capture, where the record carries fewer bytes than the
datagram claims:

```python
declared = pkt.ip.total_length - 20 - 8      # minus IPv4 and UDP headers
if declared > len(pkt.payload):
    print(f"truncated: {declared - len(pkt.payload)} bytes missing")
```

In that case the parser keeps every captured byte rather than trimming to a
length that never arrived.

## Where the payload was in the frame

`pkt.payload_offset` is the index of `payload[0]` within the frame you passed
to `parse_packet`, or `None` when there is no payload:

```python
pkt = parse_packet(frame)
frame[pkt.payload_offset:][:len(pkt.payload)] == pkt.payload    # True
```

Combined with {attr}`packeteer.pcap.PcapRecord.data_offset` it gives the
payload's position in the **capture file**, which is what a tool citing
provenance — "these bytes came from file offsets X–Y" — needs:

```python
with open_pcap(path="capture.pcap") as reader:
    for record in reader:
        pkt = parse_packet(record.data, link_type=reader.header.link_type)
        if pkt.payload:
            start = record.data_offset + pkt.payload_offset
            print(f"payload at file offsets {start}–{start + len(pkt.payload)}")
```

Do not compute this as `len(frame) - len(payload)`.  That assumes the payload
runs to the end of the frame, which is false for any frame padded to the
60-byte Ethernet minimum: the padding sits after the IP datagram and the
parser trims it out of `payload`, so the subtraction lands inside the padding
and silently yields the wrong bytes.  Searching with `frame.find(payload)` is
guesswork — a short payload can occur earlier in the frame by coincidence.

For a tunnelled packet, a nested `payload_offset` is relative to the
**outermost** frame too, so the same single addition works at any depth:

```python
inner = pkt.tunneled
frame[inner.payload_offset:][:len(inner.payload)] == inner.payload    # True
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

When `pkt.dns` (or `pkt.http`) is set, `pkt.payload` is empty.  A failed parse
leaves the raw bytes in `pkt.payload` unchanged.

### Keeping the payload as it appeared on the wire

The decoded object is not a byte-exact substitute for the payload it replaced:
re-encoding an `HTTPMessage` normalises header casing, header order,
whitespace, and duplicate headers.  When those bytes matter — reassembling a
stream, hashing a payload, feeding another decoder — pass `decode_app=False`
and the decoders are skipped entirely:

```python
pkt = parse_packet(raw, decode_app=False)

pkt.http                            # None — not decoded
pkt.payload                         # the exact bytes from the wire
```

The setting applies to every layer of a tunnelled packet, so an HTTP payload
inside VXLAN or GRE is left raw too.  Tunnel headers themselves (VXLAN,
GENEVE, GTP-U) are framing rather than application content and are always
decoded.

{func}`~packeteer.parse.core.parse_pcap_packet` and
{func}`~packeteer.parse.core.parse_pcap_file` take the same argument, and
`packeteer parse --no-decode-app` exposes it on the command line — the spec
then carries a `payload` section instead of a `dns` / `dhcp` / `http` one.

## TCP options

Options in the TCP header are decoded into `pkt.transport.options`, a
`TCPOptions` instance, or `None` when the header carries none:

```python
pkt = parse_packet(raw)
opts = pkt.transport.options

opts.mss                # 1460
opts.window_scale       # 7 — the advertised window is window << window_scale
opts.sack_permitted     # True
opts.timestamps         # (TSval, TSecr)
opts.sack_blocks        # [(left_edge, right_edge), …]
```

Window scale matters for reading `window` at all: on a scaled connection the
raw `window` field is misleading on its own.  SACK blocks tell a reassembler
which ranges actually arrived, and timestamps discriminate retransmits.

An option packeteer does not model — or a known kind carrying an unexpected
length — is kept in `opts.unknown` as `(kind, value)` pairs rather than being
dropped, and the builder re-emits it.  Structural padding (NOP, End of Option
List) is not modelled.

Options are re-encoded in a canonical order, so a parse → build round trip
preserves every option's presence and value, but the resulting header is not
guaranteed byte-identical to a capture that ordered or padded them
differently.

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
