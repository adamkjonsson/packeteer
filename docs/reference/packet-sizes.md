# Packet Sizes

Fixed header sizes for every supported protocol, and example total sizes for
common layer stacks.

---

## Fixed header sizes

| Protocol | Header size (bytes) | Notes |
|----------|--------------------:|-------|
| Ethernet II | 14 | `dst_mac` (6) + `src_mac` (6) + EtherType (2) |
| 802.1Q VLAN tag | +4 | Replaces EtherType with `0x8100` + TCI (2) + inner EtherType (2) |
| QinQ (802.1ad) | +8 | Two VLAN tags stacked |
| MPLS label entry | 4 per label | Label (20 bits) + TC (3) + S (1) + TTL (8) |
| PPPoE | 6 | VER+TYPE (1) + Code (1) + Session ID (2) + Length (2) |
| IPv4 | 20 | Minimum; no options |
| IPv6 | 40 | Fixed; extension headers add more |
| IPv6 Fragment Extension Header | +8 | Added per fragment by `.fragment()` |
| TCP | 20 | Minimum; no options |
| TCP MSS option | +4 | Kind (1) + Len (1) + MSS (2) |
| TCP Window Scale option | +3 (+1 pad) | Kind (1) + Len (1) + Shift (1) |
| TCP SACK Permitted option | +2 | Kind (1) + Len (1) |
| TCP SACK block | +8 per block | Left edge (4) + Right edge (4) |
| TCP Timestamps option | +10 | Kind (1) + Len (1) + TSval (4) + TSecr (4) |
| UDP | 8 | Src port (2) + Dst port (2) + Length (2) + Checksum (2) |
| SCTP common header | 12 | Src port (2) + Dst port (2) + Verification Tag (4) + CRC-32c checksum (4) |
| SCTP chunk header | 4 per chunk | Type (1) + Flags (1) + Length (2); each chunk padded to 4-byte boundary |
| SCTP DATA chunk (fixed) | 16 | 4 chunk header + TSN (4) + Stream ID (2) + Stream Seq (2) + PPID (4) |
| SCTP INIT / INIT ACK (fixed) | 20 | 4 chunk header + Initiate Tag (4) + a_rwnd (4) + streams (2+2) + ISN (4) |
| SCTP SACK (fixed) | 16 | 4 chunk header + Cum TSN (4) + a_rwnd (4) + gap/dup counts (2+2) |
| ICMPv4 | 8 | Type (1) + Code (1) + Checksum (2) + ID (2) + Seq (2) |
| ICMPv6 | 8 | Same layout as ICMPv4 |
| EtherIP | 2 | Version+reserved (2); IP protocol 97 |
| GRE | 4 | Fixed header; optional fields add more |
| GRE Checksum field | +4 | Present when C flag set |
| GRE Key field | +4 | Present when K flag set (RFC 2890) |
| GRE Sequence Number field | +4 | Present when S flag set (RFC 2890) |

---

## Tunnel overhead

| Tunnel type | Outer overhead (bytes) | Inner Ethernet? |
|-------------|----------------------:|-----------------|
| IP-in-IP (IPv4 outer) | 20 | No |
| IP-in-IP (IPv6 outer) | 40 | No |
| GRE (IPv4 outer, no options) | 20 + 4 = **24** | No |
| GRE with Key (IPv4 outer) | 20 + 4 + 4 = **28** | No |
| GRE TEB (IPv4 outer, no options) | 20 + 4 + 14 = **38** | Yes |
| EtherIP (IPv4 outer) | 20 + 2 + 14 = **36** | Yes |

---

## Common full-packet sizes

Ethernet + IPv4 + TCP (minimum, no payload):

```
14 (Ethernet) + 20 (IPv4) + 20 (TCP) = 54 bytes
```

Ethernet + IPv4 + UDP + 100-byte payload:

```
14 + 20 + 8 + 100 = 142 bytes
```

Ethernet + 802.1Q VLAN + IPv4 + TCP (minimum):

```
14 + 4 + 20 + 20 = 58 bytes
```

Ethernet + IPv4 (GRE) + GRE + Ethernet + IPv4 + TCP (TEB tunnel, minimum):

```
14 + 20 + 4 + 14 + 20 + 20 = 92 bytes
```

Ethernet + IPv4 (EtherIP) + EtherIP + Ethernet + IPv4 + TCP (minimum):

```
14 + 20 + 2 + 14 + 20 + 20 = 90 bytes
```

---

## MTU and fragmentation

The default Ethernet MTU is **1500 bytes** for the IP payload (excludes the
14-byte Ethernet header).  When the IP datagram (header + transport + payload)
exceeds the MTU, call `.fragment(mtu=1500)`.

See {doc}`../fragmentation` for details on how fragmentation works and how the
overhead is distributed across fragments.
