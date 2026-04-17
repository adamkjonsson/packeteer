# `PacketBuilder` — Python API

{class}`~packeteer.generate.builder.PacketBuilder` is the fluent Python API
behind `packeteer build`.  Each method **appends** one layer to a stack and
returns `self`, so calls chain naturally.  Call `.build()` at the end to
assemble the raw bytes.

```python
from packeteer.generate import PacketBuilder

pkt = (PacketBuilder()
    .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=443, flags=0x002)
    .payload(size=64)
    .build()
)
# pkt is bytes — pass to write_pcap, send via socket, inspect, etc.
```

## Layer methods

### `.ethernet(src_mac, dst_mac, pad=False)`

Appends an Ethernet II header.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `src_mac` | `"00:00:00:00:00:01"` | Source MAC (colon- or hyphen-separated hex) |
| `dst_mac` | `"00:00:00:00:00:02"` | Destination MAC |
| `pad` | `False` | Zero-pad the frame to the IEEE 802.3 minimum of 60 bytes |

The EtherType is set automatically from the next layer added.

### `.vlan(vid, pcp=0, dei=0)`

Appends an IEEE 802.1Q VLAN tag.  Call twice (outer then inner) for QinQ
(IEEE 802.1ad) double-tagging.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `vid` | *(required)* | VLAN ID (1–4094) |
| `pcp` | `0` | Priority Code Point (0–7) |
| `dei` | `0` | Drop Eligible Indicator (0 or 1) |

```python
# QinQ: outer VID 100, inner VID 200
pkt = (PacketBuilder()
    .ethernet()
    .vlan(vid=100, pcp=5)   # outer tag
    .vlan(vid=200)          # inner tag
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=80)
    .build()
)
```

### `.mpls(label, tc=0, ttl=64)`

Appends one MPLS label stack entry (RFC 3032).  Call multiple times for a
multi-label stack; entries are written outermost first, and the bottom-of-stack
(S) bit is set automatically on the last entry.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `label` | *(required)* | 20-bit label value (0–1 048 575) |
| `tc` | `0` | Traffic Class / QoS field (0–7) |
| `ttl` | `64` | Time-to-Live (0–255) |

### `.pppoe(code=0, session_id=0, tags=None)`

Appends a PPPoE header (RFC 2516).

| Parameter | Default | Description |
|-----------|---------|-------------|
| `code` | `0` | `0` = session data frame; `9`/`7`/`25`/`101`/`167` for discovery |
| `session_id` | `0` | 16-bit PPPoE session ID |
| `tags` | `None` | List of {class}`~packeteer.generate.pppoe.PPPoETag` objects for discovery frames |

### `.ip(src, dst, ttl=64, tos=0, identification=0, flags=0b010, fragment_offset=0, traffic_class=0, flow_label=0)`

Appends an IP header.  **IPv4 or IPv6 is selected automatically** from the
format of `src` — no explicit version flag is needed.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `src` | *(required)* | Source IP address (IPv4 dotted-decimal or IPv6 colon-hex) |
| `dst` | *(required)* | Destination IP address |
| `ttl` | `64` | TTL (IPv4) / Hop Limit (IPv6) |
| `tos` | `0` | IPv4 Type of Service / DSCP byte |
| `identification` | `0` | IPv4 16-bit packet identification field |
| `flags` | `0b010` | IPv4 3-bit flags (bit 1 = Don't Fragment) |
| `fragment_offset` | `0` | IPv4 13-bit fragment offset in 8-byte units |
| `traffic_class` | `0` | IPv6 Traffic Class (8-bit, DSCP + ECN) |
| `flow_label` | `0` | IPv6 20-bit Flow Label |

The protocol/next-header field is set automatically from the next layer.  Call
`.ip()` twice — outer then inner — to build an IP-in-IP tunnel; the outer IP
protocol field (`4` or `41`) is set automatically.

```python
# IPv6 — detected from the address format
pkt = (PacketBuilder()
    .ip(src="2001:db8::1", dst="2001:db8::2", ttl=128)
    .tcp(dst_port=443)
    .build()
)
```

### `.gre(key=None, seq=None, checksum=False)`

Appends a GRE tunnel header (RFC 2784 / RFC 2890) between the outer IP layer
and the inner packet.  The outer IP protocol (47) and the GRE Protocol Type
(`0x0800` IPv4, `0x86DD` IPv6, `0x6558` TEB) are set automatically.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `key` | `None` | RFC 2890 32-bit Key field (K flag set when present) |
| `seq` | `None` | RFC 2890 32-bit Sequence Number (S flag set when present) |
| `checksum` | `False` | Compute and include RFC 1071 checksum (C flag) |

```python
# GRE tunnel — outer 10.x, inner 192.168.x
pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")     # outer IP
    .gre(key=0xDEAD)
    .ip(src="192.168.1.1", dst="192.168.1.2") # inner IP
    .tcp(dst_port=80)
    .build()
)

# TEB (Transparent Ethernet Bridging) — GRE carrying an inner Ethernet frame
pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .gre()
    .ethernet(src_mac="aa:bb:cc:00:00:01", dst_mac="aa:bb:cc:00:00:02")  # inner eth
    .ip(src="192.168.1.1", dst="192.168.1.2")
    .tcp(dst_port=8080)
    .build()
)
```

### `.etherip()`

Appends the 2-byte EtherIP header (RFC 3378) between the outer IP and inner
Ethernet frame.  The outer IP protocol (97) is set automatically.

```python
pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")      # outer IP
    .etherip()
    .ethernet(src_mac="aa:00:00:00:00:01", dst_mac="aa:00:00:00:00:02")  # inner eth
    .ip(src="192.168.1.1", dst="192.168.1.2") # inner IP
    .tcp(dst_port=22)
    .build()
)
```

### `.tcp(src_port=12345, dst_port=80, seq=0, ack=0, flags=0x002, window=65535, urgent_ptr=0, reserved=0, options=None)`

Appends a TCP transport header (RFC 9293).  The checksum and data-offset
fields are computed automatically.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `src_port` | `12345` | Source port |
| `dst_port` | `80` | Destination port |
| `seq` | `0` | Sequence number |
| `ack` | `0` | Acknowledgement number |
| `flags` | `0x010` | 8-bit control flags; common values: `0x002` SYN, `0x012` SYN+ACK, `0x010` ACK, `0x018` PSH+ACK, `0x004` RST, `0x001` FIN |
| `window` | `65535` | Receive window size in bytes |
| `urgent_ptr` | `0` | Urgent pointer (used when URG flag set) |
| `reserved` | `0` | 4-bit reserved field |
| `options` | `None` | {class}`~packeteer.generate.tcp.TCPOptions` with MSS, window scale, SACK, and timestamps |

```python
from packeteer.generate import TCPOptions

# SYN with MSS and SACK permitted options
pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(
        dst_port=80,
        flags=0x002,
        options=TCPOptions(mss=1460, sack_permitted=True, window_scale=7),
    )
    .build()
)
```

### `.udp(src_port=12345, dst_port=80)`

Appends a UDP transport header.  The checksum and length fields are computed
automatically.

### `.icmp(type=8, code=0, identifier=1, sequence=1)`

Appends an ICMPv4 header (RFC 792).  Use with an IPv4 `.ip()` layer.
The checksum is computed automatically.  Common types: `8`=Echo Request,
`0`=Echo Reply, `3`=Destination Unreachable, `11`=Time Exceeded.

### `.icmpv6(type=128, code=0, identifier=1, sequence=1)`

Appends an ICMPv6 header (RFC 4443).  Use with an IPv6 `.ip()` layer.
The pseudo-header checksum is computed automatically.  Common types:
`128`=Echo Request, `129`=Echo Reply, `135`=Neighbour Solicitation,
`136`=Neighbour Advertisement.

### `.sctp(src_port=0, dst_port=0, verification_tag=0, chunks=None)`

Appends an SCTP transport header (RFC 9260).  IP protocol number 132 is set
automatically.  The CRC-32c checksum (Castagnoli) is computed automatically.

SCTP data lives inside typed *chunk* objects rather than in a separate
`.payload()` call.

```python
from packeteer.generate import PacketBuilder
from packeteer.generate import (
    SCTPInitChunk, SCTPDataChunk,
    SCTP_DATA_FLAG_BEGINNING, SCTP_DATA_FLAG_ENDING,
)

# INIT chunk (first packet of an SCTP handshake)
init = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .sctp(
        src_port=1234, dst_port=9999,
        verification_tag=0,
        chunks=[SCTPInitChunk(
            initiate_tag=0xDEADBEEF,
            a_rwnd=131072,
            outbound_streams=1,
            inbound_streams=1,
            initial_tsn=0,
        )],
    )
    .build()
)

# DATA chunk carrying a complete message
data_pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .sctp(
        src_port=1234, dst_port=9999,
        verification_tag=0xCAFEBABE,
        chunks=[SCTPDataChunk(
            tsn=42,
            stream_id=0,
            stream_seq=0,
            ppid=0,
            data=b"hello sctp",
            flags=SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING,
        )],
    )
    .build()
)
```

See {doc}`../api/header-dataclasses` for all SCTP chunk types and constants.

### `.payload(size=0, data=None)`

Appends raw payload bytes.  `data` (bytes) takes precedence over `size`
(which generates that many random bytes).

```python
# Explicit payload
pkt = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp(dst_port=9000)
    .payload(data=b"\x01\x02\x03\x04")
    .build()
)

# Random payload — useful for generating realistic-looking traffic at scale
pkt = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=80)
    .payload(size=1400)
    .build()
)
```

## Assembly

### `.build() → bytes`

Assembles all layers in stack order and returns the raw packet as `bytes`.
All checksums and length fields are computed at this point.

### `.fragment(mtu=1500) → list[bytes]`

Fragments the packet at the first IP layer so each IP datagram fits within
`mtu` bytes, and returns a list of fully assembled raw-packet `bytes` objects.
When the payload already fits in one datagram the list has a single element.
The Ethernet header (if any) is replicated on every fragment.

```python
# A 4000-byte UDP payload split into three IPv4 fragments (MTU 1500)
fragments = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp(dst_port=5000)
    .payload(size=4000)
    .fragment(mtu=1500)
)
print(f"produced {len(fragments)} fragments")

# IPv6 uses the Fragment Extension Header automatically
fragments = (PacketBuilder()
    .ip(src="2001:db8::1", dst="2001:db8::2")
    .tcp(dst_port=443)
    .payload(size=3000)
    .fragment(mtu=1280)   # IPv6 minimum MTU
)
```

See {doc}`fragmentation` for IPv4/IPv6 fragmentation details and the low-level
`fragment_ipv4` / `fragment_ipv6` functions.

## Checksums

All of the following are computed automatically by `.build()` and
`.fragment()`:

| Layer | What is computed |
|-------|-----------------|
| IPv4 | Header checksum (RFC 791 §3.1) |
| TCP | Pseudo-header checksum (RFC 9293 §3.1) |
| UDP | Pseudo-header checksum (RFC 768) |
| ICMPv4 | Header checksum (RFC 792) |
| ICMPv6 | Pseudo-header checksum (RFC 4443 §2.3) |
| GRE | Optional RFC 1071 checksum when `checksum=True` |
| SCTP | CRC-32c (Castagnoli) per RFC 9260 §6.8 |

You never need to compute or supply checksums manually.

## Writing to pcap files

{func}`~packeteer.pcap.write_pcap` and {func}`~packeteer.pcap.write_pcapng`
accept a list of `(bytes, ts_sec, ts_frac)` tuples.

```python
import time
from packeteer.generate import PacketBuilder
from packeteer.pcap import write_pcap, write_pcapng, LINKTYPE_ETHERNET

t = int(time.time())

packets = [
    (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
        .tcp(dst_port=80, flags=0x002).build(),   t,       0),
    (PacketBuilder().ethernet().ip(src="10.0.0.2", dst="10.0.0.1")
        .tcp(dst_port=54321, flags=0x012).build(), t,  500_000),
    (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
        .tcp(dst_port=80, flags=0x010).build(),    t, 1_000_000),
]

# libpcap — microsecond timestamps
write_pcap(packets, path="handshake.pcap", link_type=LINKTYPE_ETHERNET)

# pcapng — nanosecond timestamps
write_pcapng(packets, path="handshake.pcapng", link_type=LINKTYPE_ETHERNET,
             nanoseconds=True)
```

Fragments from `.fragment()` fit directly into the same list:

```python
t = int(time.time())
frags = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp(dst_port=5000)
    .payload(size=4000)
    .fragment(mtu=1500)
)
pcap_tuples = [(f, t, i * 1000) for i, f in enumerate(frags)]
write_pcap(pcap_tuples, path="fragmented.pcap", link_type=LINKTYPE_ETHERNET)
```

Use `link_type=LINKTYPE_RAW` when the packets have no Ethernet header:

```python
from packeteer.pcap import LINKTYPE_RAW

pkt = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build()
write_pcap([(pkt, 0, 0)], path="raw.pcap", link_type=LINKTYPE_RAW)
```

See {doc}`../api/pcap-io` for the full I/O reference including `read_pcap` and
`read_pcapng`.
