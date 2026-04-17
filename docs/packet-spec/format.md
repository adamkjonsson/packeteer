# Format Reference

The packet spec is the input to `packeteer build` and the output of
`packeteer parse`.  It contains a top-level `packets` array with one
object per packet, and a mandatory top-level `metadata` block.

```json
{
  "metadata": {
    "from_file": "capture.pcap",
    "type": "pcap",
    "nanoseconds": false
  },
  "packets": [
    {
      "ethernet": { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
      "network":  { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp" },
      "transport": { "dst_port": 80 },
      "packet_metadata": { "timestamp_s": 1000, "timestamp_us": 0 }
    }
  ]
}
```

All packets in a multi-packet file must use the same link-layer type: either
all with `ethernet` or all with `ethernet.enabled: false`.

---

(packet-spec-ethernet)=
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

(packet-spec-mpls)=
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

(packet-spec-pppoe)=
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

(packet-spec-etherip)=
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

(packet-spec-ipip)=
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

(packet-spec-gre)=
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

(packet-spec-network)=
## `network`

| Field | Required | Description |
|-------|----------|-------------|
| `src` | yes | Source IP address (IPv4 dotted-decimal or IPv6 colon-hex) |
| `dst` | yes | Destination IP address in the same format |
| `protocol` | yes | `"tcp"`, `"udp"`, `"sctp"`, `"icmp"`, `"icmpv6"`, `"gre"`, `"etherip"`, or `"ipip"` |
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

(packet-spec-transport)=
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

(packet-spec-sctp)=
## SCTP transport

When `network.protocol` is `"sctp"` the `transport` object has a different
shape — SCTP data lives inside typed **chunks** rather than in a separate
`payload` key.  Do not include a `payload` key for SCTP packets.

```json
"network":   { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "sctp", "ttl": 64 },
"transport": {
  "src_port": 1234,
  "dst_port": 9999,
  "verification_tag": 3735928559,
  "chunks": [
    {
      "type":       "data",
      "flags":      3,
      "tsn":        0,
      "stream_id":  0,
      "stream_seq": 0,
      "ppid":       0,
      "data":       "68656c6c6f2073637470"
    }
  ]
}
```

**SCTP transport fields:**

| Field | Default | Description |
|-------|---------|-------------|
| `src_port` | `0` | SCTP source port (16-bit) |
| `dst_port` | `0` | SCTP destination port (16-bit) |
| `verification_tag` | `0` | Verification Tag negotiated during the handshake (32-bit) |
| `chunks` | `[]` | Array of chunk objects (see below).  An empty array produces a single empty DATA chunk. |

**Chunk object fields by type:**

| `type` | Extra fields |
|--------|-------------|
| `"data"` | `tsn` (int), `stream_id` (int), `stream_seq` (int), `ppid` (int), `data` (hex string), `flags` (int: B=2, E=1, U=4) |
| `"init"` / `"init_ack"` | `initiate_tag`, `a_rwnd`, `outbound_streams`, `inbound_streams`, `initial_tsn` (all ints); `params` (hex string, optional) |
| `"sack"` | `cum_tsn_ack`, `a_rwnd` (ints); `gap_ack_blocks` (array of `[start, end]`); `dup_tsns` (array of ints) |
| `"heartbeat"` / `"heartbeat_ack"` | `info` (hex string) |
| `"abort"` | `flags` (int); `causes` (hex string, optional) |
| `"shutdown"` | `cum_tsn_ack` (int) |
| `"shutdown_ack"` | *(no fields)* |
| `"error"` | `causes` (hex string, optional) |
| `"cookie_echo"` | `cookie` (hex string) |
| `"cookie_ack"` | *(no fields)* |
| `"shutdown_complete"` | `flags` (int) |
| `"generic"` | `chunk_type` (int), `flags` (int), `value` (hex string) |

The CRC-32c checksum (Castagnoli, RFC 9260 §6.8) is computed automatically.

---

(packet-spec-dns)=
## `dns`

An optional DNS message (RFC 1035).  When present, `dns` is encoded as the
packet payload and the `payload` key is ignored.  Set `transport.dst_port` or
`transport.src_port` to `53` and use `"udp"` or `"tcp"` as the protocol.

For TCP, the builder prepends the mandatory 2-byte big-endian length field
automatically (RFC 1035 §4.2.2) when the enclosing transport is TCP.

```json
"transport": { "src_port": 54321, "dst_port": 53 },
"dns": {
  "id": 4660,
  "flags": {
    "qr":     false,
    "opcode": 0,
    "aa":     false,
    "tc":     false,
    "rd":     true,
    "ra":     false,
    "rcode":  0
  },
  "questions": [
    { "name": "example.com.", "qtype": 1, "qclass": 1 }
  ],
  "answers":    [],
  "authority":  [],
  "additional": []
}
```

### `dns` top-level fields

| Field | Description |
|-------|-------------|
| `id` | 16-bit transaction identifier |
| `flags` | Header flags object (see below) |
| `questions` | Array of question section entries |
| `answers` | Array of resource records in the answer section |
| `authority` | Array of resource records in the authority section |
| `additional` | Array of resource records in the additional section |

### `dns.flags`

| Field | Default | Description |
|-------|---------|-------------|
| `qr` | `false` | `false` = query, `true` = response |
| `opcode` | `0` | 4-bit opcode: `0`=QUERY, `1`=IQUERY, `2`=STATUS |
| `aa` | `false` | Authoritative Answer |
| `tc` | `false` | TrunCated |
| `rd` | `true` | Recursion Desired |
| `ra` | `false` | Recursion Available |
| `rcode` | `0` | 4-bit response code: `0`=NOERROR, `1`=FORMERR, `2`=SERVFAIL, `3`=NXDOMAIN, `4`=NOTIMP, `5`=REFUSED |

### Question entry

| Field | Default | Description |
|-------|---------|-------------|
| `name` | *(required)* | Domain name, trailing dot optional |
| `qtype` | `1` | Query type integer (e.g. `1`=A, `28`=AAAA, `5`=CNAME) |
| `qclass` | `1` | Query class (`1` = IN) |

### Resource record entry

| Field | Default | Description |
|-------|---------|-------------|
| `name` | *(required)* | Owner name |
| `rtype` | *(required)* | Record type integer |
| `rclass` | `1` | Record class (`1` = IN) |
| `ttl` | `0` | Time-to-live in seconds |
| `rdata` | *(required)* | Record data object — shape depends on `rtype` (see below) |

### `rdata` shape by type

| `rtype` | Fields | Description |
|---------|--------|-------------|
| `1` (A) | `address` (string) | IPv4 address in dotted-decimal notation |
| `28` (AAAA) | `address` (string) | IPv6 address |
| `2` (NS) | `name` (string) | Name server domain name |
| `5` (CNAME) | `name` (string) | Canonical name |
| `12` (PTR) | `name` (string) | Pointer target name |
| `15` (MX) | `preference` (int), `exchange` (string) | Mail exchange |
| `6` (SOA) | `mname`, `rname` (strings); `serial`, `refresh`, `retry`, `expire`, `minimum` (ints) | Start of authority |
| `16` (TXT) | `strings` (array of strings) | Text strings — each element is one length-prefixed string in the wire format |
| *(other)* | `data` (hex string) | Raw RDATA bytes for unrecognised types |

### Full DNS response example

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet":  { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "network":   { "src": "8.8.8.8", "dst": "192.168.1.1", "protocol": "udp" },
    "transport": { "src_port": 53, "dst_port": 54321 },
    "dns": {
      "id": 4660,
      "flags": { "qr": true, "opcode": 0, "aa": false, "tc": false,
                 "rd": true, "ra": true, "rcode": 0 },
      "questions": [
        { "name": "example.com.", "qtype": 1, "qclass": 1 }
      ],
      "answers": [
        { "name": "example.com.", "rtype": 1, "rclass": 1, "ttl": 300,
          "rdata": { "address": "93.184.216.34" } }
      ],
      "authority": [
        { "name": "example.com.", "rtype": 2, "rclass": 1, "ttl": 3600,
          "rdata": { "name": "ns1.example.com." } }
      ],
      "additional": [
        { "name": "ns1.example.com.", "rtype": 1, "rclass": 1, "ttl": 3600,
          "rdata": { "address": "205.251.196.1" } }
      ]
    },
    "packet_metadata": { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
```

---

(packet-spec-payload)=
## `payload`

`size` and `data` are mutually exclusive; `data` takes precedence.

| Field | Description |
|-------|-------------|
| `size` | Generate this many random bytes as the payload |
| `data` | Explicit payload as a hex string (e.g. `"48656c6c6f"` = `Hello`) |

---

(packet-spec-metadata)=
## `metadata` (top-level)

Always present in configs produced by `packeteer parse` and
`packeteer stream --json`.  Read by `packeteer build` for format settings.

| Field | Required | Description |
|-------|----------|-------------|
| `nanoseconds` | **yes** | `true` when `packet_metadata` timestamps use nanosecond resolution; `false` for microsecond.  Always `false` in stream JSON output. |
| `from_file` | no | Path of the source pcap or pcapng file (informational only) |
| `type` | no | Source file format: `"pcap"` or `"pcapng"` |

---

(packet-spec-packet-metadata)=
## `packet_metadata` (per-packet)

| Field | Default | Description |
|-------|---------|-------------|
| `mtu` | — | Fragment the packet so each IP datagram is at most this many bytes — see {doc}`../build/fragmentation` |
| `timestamp_s` | `0` | Capture timestamp — whole seconds |
| `timestamp_us` | `0` | Microsecond fraction (0–999999); used when `metadata.nanoseconds` is `false` |
| `timestamp_ns` | `0` | Nanosecond fraction (0–999999999); used when `metadata.nanoseconds` is `true` |
| `direction` | — | *(stream JSON only)* `"c2s"` (client→server) or `"s2c"` (server→client); written by `packeteer stream --json`, ignored by `packeteer build` |
| `label` | — | *(stream JSON only)* Human-readable role label (e.g. `"SYN"`, `"DATA[3]"`, `"FRAG[DATA[0]][1]"`); written by `packeteer stream --json`, ignored by `packeteer build` |
