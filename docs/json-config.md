# JSON Config File Format

The JSON config file is the input to `packet_lab.py build` and the output of
`packet_lab.py parse`.  It contains a top-level `packets` array with one
object per packet, and an optional `file_metadata` block.

```json
{
  "file_metadata": {
    "from_file": "capture.pcap",
    "type": "pcap",
    "nanoseconds": false
  },
  "packets": [
    {
      "ethernet": { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
      "network":  { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp" },
      "transport": { "dst_port": 80 },
      "metadata": { "timestamp_s": 1000, "timestamp_us": 0 }
    }
  ]
}
```

All packets in a multi-packet file must use the same link-layer type: either
all with `ethernet` or all with `ethernet.enabled: false`.

---

(json-config-ethernet)=
## `ethernet`

An optional Ethernet II header.  Omit the key entirely to produce a raw IP
packet with no layer-2 framing.

| Field | Default | Description |
|-------|---------|-------------|
| `src_mac` | `"00:00:00:00:00:01"` | Source MAC address (colon- or hyphen-separated hex) |
| `dst_mac` | `"00:00:00:00:00:02"` | Destination MAC address |
| `enabled` | `true` | Set to `false` to omit the Ethernet header |
| `pad` | `false` | Zero-pad the frame to the IEEE 802.3 minimum of 60 bytes when `true` |
| `vlan.id` | — | VLAN ID 1–4094; omit `vlan` entirely to disable VLAN tagging |
| `vlan.pcp` | `0` | Priority Code Point (0–7) |
| `vlan.dei` | `0` | Drop Eligible Indicator (0 or 1) |

Call `.vlan()` twice in the builder (or nest two `vlan` keys) for QinQ
(IEEE 802.1ad) double-tagged frames.

---

(json-config-mpls)=
## `mpls`

An optional array of MPLS label stack entries inserted between the Ethernet
layer and the IP layer.  Entries are ordered outermost first.

```json
"mpls": [
  { "label": 100, "ttl": 64 },
  { "label": 200, "tc": 3, "ttl": 32 }
]
```

| Field | Default | Description |
|-------|---------|-------------|
| `label` | *(required)* | 20-bit MPLS label value (0–1048575) |
| `tc` | `0` | Traffic Class — 3-bit QoS/ECN field (0–7) |
| `ttl` | `64` | Time-to-Live (0–255) |

The bottom-of-stack (S) bit is set automatically: `1` on the last entry,
`0` on all others.

---

(json-config-pppoe)=
## `pppoe`

An optional PPPoE header inserted between the Ethernet layer and the IP layer.

```json
"pppoe": { "session_id": 4660 }
```

For discovery frames, set `code` and include a `tags` array:

```json
"pppoe": {
  "code": 9,
  "tags": [{ "type": 257, "data": "" }]
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `session_id` | `0` | 16-bit PPPoE session identifier |
| `code` | `0` | `0`=session, `9`=PADI, `7`=PADO, `25`=PADR, `101`=PADS, `167`=PADT |
| `tags` | `[]` | Array of `{type, data}` TLV entries for discovery frames.  `data` is a hex string. |

Tag type constants (decimal): `257`=Service-Name, `258`=AC-Name,
`259`=Host-Uniq, `260`=AC-Cookie, `515`=Generic-Error.

---

(json-config-etherip)=
## `etherip`

An optional EtherIP tunnel header (RFC 3378).  Set `network.protocol` to
`"etherip"` in the enclosing packet, then provide the inner packet spec as
the value of `"etherip"`.

```json
"network": { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "etherip" },
"etherip": {
  "ethernet":  { "src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02" },
  "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp" },
  "transport": { "dst_port": 80 }
}
```

The outer IP protocol number (97) and the 2-byte EtherIP header
(`0x30 0x00`) are set automatically.  Double-nested EtherIP uses a nested
`"etherip"` key inside the inner spec.

---

(json-config-ipip)=
## `ipip`

An optional IP-in-IP inner packet spec (RFC 2003 / RFC 4213).  Set
`network.protocol` to `"ipip"`, then provide the inner spec — which has
**no** `"ethernet"` key — as the value of `"ipip"`.

```json
"network": { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "ipip", "ttl": 64 },
"ipip": {
  "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp", "ttl": 64 },
  "transport": { "src_port": 12345, "dst_port": 80 }
}
```

The outer IP protocol field (`4` for IPv4 inner, `41` for IPv6 inner) is
set automatically from the inner `network.src` address.  Double-nested
IP-in-IP uses a nested `"ipip"` key.

---

(json-config-gre)=
## `gre`

An optional GRE tunnel header (RFC 2784 / RFC 2890).  Set
`network.protocol` to `"gre"`, then provide the inner spec as the value of
`"gre"`.

**Basic IPv4-in-GRE:**

```json
"network": { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "gre", "ttl": 64 },
"gre": {
  "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp", "ttl": 64 },
  "transport": { "src_port": 12345, "dst_port": 80 }
}
```

**With Key and Sequence Number (RFC 2890):**

```json
"gre": {
  "key": 1234,
  "seq": 0,
  "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "udp" },
  "transport": { "dst_port": 53 }
}
```

**With Checksum (RFC 2784):**

```json
"gre": {
  "checksum": true,
  "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp" },
  "transport": { "dst_port": 443 }
}
```

**TEB — GRE carrying an inner Ethernet frame:**

The presence of `"ethernet"` inside the `"gre"` spec activates TEB mode
(Protocol Type `0x6558` is set automatically).

```json
"gre": {
  "key": 42,
  "ethernet": { "src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02" },
  "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp" },
  "transport": { "dst_port": 80 }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `key` | — | RFC 2890 32-bit Key field (K flag set when present) |
| `seq` | — | RFC 2890 32-bit Sequence Number field (S flag set when present) |
| `checksum` | `false` | Set C flag and compute RFC 1071 checksum when `true` |

The outer IP protocol (47) and the GRE Protocol Type (`0x0800` IPv4,
`0x86DD` IPv6, `0x6558` TEB) are set automatically.  Nested GRE uses a
nested `"gre"` key with `"protocol": "gre"` in the inner `"network"` spec.

---

(json-config-network)=
## `network`

| Field | Required | Description |
|-------|----------|-------------|
| `src` | yes | Source IP address (IPv4 dotted-decimal or IPv6 colon-hex) |
| `dst` | yes | Destination IP address in the same format |
| `protocol` | yes | `"tcp"`, `"udp"`, `"icmp"`, `"icmpv6"`, `"gre"`, `"etherip"`, or `"ipip"` |
| `ttl` | no (default `64`) | TTL (IPv4) / Hop Limit (IPv6) |
| `tos` | no (default `0`) | IPv4 Type of Service / DSCP byte |
| `identification` | no (default `0`) | IPv4 16-bit packet identification |
| `flags` | no (default `2`) | IPv4 3-bit flags field — bit 1 is Don't Fragment (DF) |
| `fragment_offset` | no (default `0`) | IPv4 13-bit fragment offset in 8-byte units |
| `traffic_class` | no (default `0`) | IPv6 Traffic Class (DSCP + ECN, 8-bit) |
| `flow_label` | no (default `0`) | IPv6 20-bit Flow Label |

IPv4 or IPv6 is detected automatically from `src`.  IPv4-specific fields
are ignored when `src` is an IPv6 address and vice versa.

---

(json-config-transport)=
## `transport`

| Field | Default | Description |
|-------|---------|-------------|
| `src_port` | `12345` | Source port (TCP/UDP) |
| `dst_port` | `80` | Destination port (TCP/UDP) |
| `seq` | `0` | TCP sequence number |
| `ack` | `0` | TCP acknowledgement number |
| `reserved` | `0` | TCP 4-bit reserved field |
| `flags` | `2` | TCP 8-bit control flags integer (e.g. `18` = SYN+ACK, `24` = PSH+ACK) |
| `window` | `65535` | TCP receive-window size in bytes |
| `urgent_ptr` | `0` | TCP urgent pointer (relevant only when URG flag is set) |
| `options.mss` | — | TCP MSS option — Maximum Segment Size in bytes |
| `options.window_scale` | — | TCP Window Scale shift count 0–14 (RFC 7323) |
| `options.sack_permitted` | `false` | TCP SACK Permitted option |
| `options.sack` | `[]` | TCP SACK blocks — array of `[left_edge, right_edge]` pairs |
| `options.timestamps` | — | TCP Timestamps option — `[TSval, TSecr]` array (RFC 7323) |
| `type` | `8` / `128` | ICMP type (`8`=Echo Request) or ICMPv6 type (`128`=Echo Request) |
| `code` | `0` | ICMP/ICMPv6 sub-type code |
| `identifier` | `1` | ICMP/ICMPv6 16-bit identifier |
| `sequence` | `1` | ICMP/ICMPv6 16-bit sequence number |

TCP flag bit values: `TCP_FIN`=1, `TCP_SYN`=2, `TCP_RST`=4, `TCP_PSH`=8,
`TCP_ACK`=16, `TCP_URG`=32, `TCP_ECE`=64, `TCP_CWR`=128.  Add values to
combine (e.g. `24` for PSH+ACK).

---

(json-config-payload)=
## `payload`

`size` and `data` are mutually exclusive; `data` takes precedence.

| Field | Description |
|-------|-------------|
| `size` | Generate this many random bytes as the payload |
| `data` | Explicit payload as a hex string (e.g. `"48656c6c6f"` = `Hello`) |

---

(json-config-file-metadata)=
## `file_metadata` (top-level)

Written by `packet_lab.py parse`; read by `packet_lab.py build` for format
settings (`type`, `nanoseconds`).  `from_file` is informational only.

| Field | Description |
|-------|-------------|
| `from_file` | Path of the pcap or pcapng file the config was parsed from |
| `type` | Source file format: `"pcap"` or `"pcapng"` |
| `nanoseconds` | `true` when timestamps are nanosecond-resolution |

---

(json-config-metadata)=
## `metadata` (per-packet)

| Field | Default | Description |
|-------|---------|-------------|
| `mtu` | — | Fragment the packet so each IP datagram is at most this many bytes — see {doc}`fragmentation` |
| `timestamp_s` | `0` | Capture timestamp — whole seconds |
| `timestamp_us` | `0` | Microsecond fraction (0–999999); used when `file_metadata.nanoseconds` is `false` |
| `timestamp_ns` | `0` | Nanosecond fraction (0–999999999); used when `file_metadata.nanoseconds` is `true` |
