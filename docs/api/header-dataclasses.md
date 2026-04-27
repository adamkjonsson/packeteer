# Header Dataclasses

**Import:** All classes and constants on this page are exported from `packeteer.generate` and can be imported directly from there, e.g. `from packeteer.generate import EthernetHeader, IPHeader, TCPHeader`.

Every protocol layer is represented by a plain dataclass.
{class}`~packeteer.generate.builder.PacketBuilder` stores instances of these
classes internally and they are also returned by the parser functions in
{doc}`parser`.

---

## Layer 2 — Ethernet

```{eval-rst}
.. autoclass:: packeteer.generate.ethernet.EthernetHeader
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.ethernet.VLANTag
   :members:
```

---

## Layer 2.5 — MPLS

```{eval-rst}
.. autoclass:: packeteer.generate.mpls.MPLSLabel
   :members:
```

EtherType constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `ETHERTYPE_MPLS_UNICAST` | `0x8847` | MPLS unicast — used for most MPLS traffic |
| `ETHERTYPE_MPLS_MULTICAST` | `0x8848` | MPLS multicast |

---

## Layer 2 — PPPoE

```{eval-rst}
.. autoclass:: packeteer.generate.pppoe.PPPoEHeader
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.pppoe.PPPoETag
   :members:
```

PPPoE code constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `PPPOE_CODE_SESSION` | `0x00` | Session data frame |
| `PPPOE_CODE_PADI` | `0x09` | Active Discovery Initiation |
| `PPPOE_CODE_PADO` | `0x07` | Active Discovery Offer |
| `PPPOE_CODE_PADR` | `0x19` | Active Discovery Request |
| `PPPOE_CODE_PADS` | `0x65` | Active Discovery Session-confirmation |
| `PPPOE_CODE_PADT` | `0xa7` | Active Discovery Terminate |

PPPoE tag type constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `PPPOE_TAG_SERVICE_NAME` | `0x0101` | Service-Name |
| `PPPOE_TAG_AC_NAME` | `0x0102` | AC-Name |
| `PPPOE_TAG_HOST_UNIQ` | `0x0103` | Host-Uniq |
| `PPPOE_TAG_AC_COOKIE` | `0x0104` | AC-Cookie |
| `PPPOE_TAG_GENERIC_ERROR` | `0x0203` | Generic-Error |

EtherType and PPP protocol constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `ETHERTYPE_PPPOE_DISCOVERY` | `0x8863` | PPPoE discovery frames |
| `ETHERTYPE_PPPOE_SESSION` | `0x8864` | PPPoE session frames |
| `PPP_IPV4` | `0x0021` | PPP protocol number for IPv4 |
| `PPP_IPV6` | `0x0057` | PPP protocol number for IPv6 |

---

## Pseudowire — RFC 4385 control word

```{eval-rst}
.. autoclass:: packeteer.generate.pseudowire.PseudowireHeader
   :members:
```

| Constant | Value | Description |
|----------|-------|-------------|
| `ETHERTYPE_PW_CW` | `0xFFFE` | Internal sentinel used by the parse pipeline to signal that a pseudowire control word follows the last MPLS label.  Never appears on the wire. |

---

## Tunnels — EtherIP

```{eval-rst}
.. autoclass:: packeteer.generate.etherip.EtherIPHeader
   :members:
```

| Constant | Value | Description |
|----------|-------|-------------|
| `IPPROTO_ETHERIP` | `97` | IP protocol number for EtherIP (RFC 3378) |

---

## Tunnels — GRE

```{eval-rst}
.. autoclass:: packeteer.generate.gre.GREHeader
   :members:
```

| Constant | Value | Description |
|----------|-------|-------------|
| `IPPROTO_GRE` | `47` | IP protocol number for GRE (RFC 2784) |
| `GRE_PROTO_IPV4` | `0x0800` | GRE Protocol Type for IPv4 payload |
| `GRE_PROTO_IPV6` | `0x86DD` | GRE Protocol Type for IPv6 payload |
| `GRE_PROTO_TEB` | `0x6558` | GRE Protocol Type for Transparent Ethernet Bridging |

---

## Layer 3 — IPv4

```{eval-rst}
.. autoclass:: packeteer.generate.ip.IPHeader
   :members:
```

---

## Layer 3 — IPv6

```{eval-rst}
.. autoclass:: packeteer.generate.ipv6.IPv6Header
   :members:
```

### Hop-by-Hop Options (RFC 8200 §4.3)

The Hop-by-Hop Options extension header is represented by a container
dataclass and three option dataclasses.  Attach it to an `IPv6Header` via the
`hop_by_hop` field, or insert it into a `PacketBuilder` stack with
`.hop_by_hop_options()`.  Padding to the required 8-byte boundary is computed
automatically.

```{eval-rst}
.. autoclass:: packeteer.generate.ipv6.HopByHopOptions
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.ipv6.RouterAlertOption
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.ipv6.JumboPayloadOption
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.ipv6.RawOption
   :members:
```

Hop-by-Hop constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `HBH_NEXT_HEADER` | `0` | IPv6 next_header value that signals a Hop-by-Hop Options extension header |
| `HBH_OPT_ROUTER_ALERT` | `0x05` | Option type for the Router Alert option (RFC 2711) |
| `HBH_OPT_JUMBO_PAYLOAD` | `0xC2` | Option type for the Jumbo Payload option (RFC 2675) |

---

## Layer 4 — TCP

```{eval-rst}
.. autoclass:: packeteer.generate.tcp.TCPHeader
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.tcp.TCPOptions
   :members:
```

TCP flag constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `TCP_FIN` | `0x01` | No more data from sender |
| `TCP_SYN` | `0x02` | Synchronise sequence numbers |
| `TCP_RST` | `0x04` | Reset the connection |
| `TCP_PSH` | `0x08` | Push buffered data to the application |
| `TCP_ACK` | `0x10` | Acknowledgement field is significant |
| `TCP_URG` | `0x20` | Urgent pointer field is significant |
| `TCP_ECE` | `0x40` | ECN-Echo |
| `TCP_CWR` | `0x80` | Congestion Window Reduced |

Combine flags with `|`: `TCP_PSH | TCP_ACK` = `0x18` (data segment),
`TCP_SYN | TCP_ACK` = `0x12` (handshake reply).

---

## Layer 4 — UDP

```{eval-rst}
.. autoclass:: packeteer.generate.udp.UDPHeader
   :members:
```

---

## Layer 4 — ICMPv4

```{eval-rst}
.. autoclass:: packeteer.generate.icmp.ICMPHeader
   :members:
```

---

## Layer 4 — ICMPv6

```{eval-rst}
.. autoclass:: packeteer.generate.icmpv6.ICMPv6Header
   :members:
```

---

## Layer 4 — SCTP

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPHeader
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPDataChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPInitChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPInitAckChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPSackChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPHeartbeatChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPHeartbeatAckChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPAbortChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPShutdownChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPShutdownAckChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPErrorChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPCookieEchoChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPCookieAckChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPShutdownCompleteChunk
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp.SCTPGenericChunk
   :members:
```

SCTP DATA chunk flag constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `SCTP_DATA_FLAG_ENDING` | `0x01` | E — last (or only) fragment of a user message |
| `SCTP_DATA_FLAG_BEGINNING` | `0x02` | B — first (or only) fragment of a user message |
| `SCTP_DATA_FLAG_UNORDERED` | `0x04` | U — unordered delivery |
| `SCTP_DATA_FLAG_IMMEDIATE` | `0x08` | I — immediate send (RFC 9260 §3.3.1) |

For a single, complete (unfragmented) message set both B and E:
`SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING` = `0x03`.

SCTP chunk type constants:

| Constant | Value |
|----------|-------|
| `SCTP_CHUNK_DATA` | `0` |
| `SCTP_CHUNK_INIT` | `1` |
| `SCTP_CHUNK_INIT_ACK` | `2` |
| `SCTP_CHUNK_SACK` | `3` |
| `SCTP_CHUNK_HEARTBEAT` | `4` |
| `SCTP_CHUNK_HEARTBEAT_ACK` | `5` |
| `SCTP_CHUNK_ABORT` | `6` |
| `SCTP_CHUNK_SHUTDOWN` | `7` |
| `SCTP_CHUNK_SHUTDOWN_ACK` | `8` |
| `SCTP_CHUNK_ERROR` | `9` |
| `SCTP_CHUNK_COOKIE_ECHO` | `10` |
| `SCTP_CHUNK_COOKIE_ACK` | `11` |
| `SCTP_CHUNK_SHUTDOWN_COMPLETE` | `14` |

| Constant | Value | Description |
|----------|-------|-------------|
| `IPPROTO_SCTP` | `132` | IP protocol number for SCTP (RFC 9260) |
