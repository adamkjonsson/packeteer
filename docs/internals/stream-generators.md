# Stream generator internals

The three stream generator modules (`tcp_stream.py`, `udp_stream.py`,
`sctp_stream.py`) produce sequences of fully assembled, timestamped packets
that represent realistic network exchanges.

Shared utilities live in `packeteer/generate/_stream_common.py`.

## TCP stream

### Connection state — `_TCPEndpoint`

Each side of the connection is modelled by a `_TCPEndpoint` dataclass:

```python
@dataclass
class _TCPEndpoint:
    ip:     str
    port:   int
    mac:    str
    seq:    int   # next sequence number to send
    ack:    int   # next sequence number expected from the peer
    window: int   # TCP receive window
```

`_advance_seq(ep, flags, payload_len)` updates `ep.seq` after each send.  SYN
and FIN each consume one sequence number in addition to the payload length; the
modulo wraps correctly at `2 ** 32`.

### Packet assembly

`_build_packet(src, dst, flags, payload, ...)` calls `PacketBuilder` with the
current `seq` and `ack` from the `_TCPEndpoint` objects and returns the raw
bytes.  Encapsulation layers (if any) are inserted between the Ethernet header
and the inner IP header by `_apply_encap()`.

### Sequence of events

`generate_tcp_stream()` builds the packet list in this order:

1. **Handshake**: SYN (client), SYN-ACK (server), ACK (client).
2. **Data transfer loop**: for each of *n* data packets:
   - `DATA[i]` (client→server, PSH set with probability `config.psh_probability`)
   - `ACK[i]` (server→client)
3. **Teardown**: FIN-ACK (client), ACK (server), FIN-ACK (server), ACK (client).

### Anomaly injection

Anomalies are injected into the already-assembled packet list *after* the main
loop, keeping the main loop clean:

| `TCPStreamConfig` field | Effect |
|---|---|
| `packet_loss_probability` | Each packet is independently dropped from the output list.  Seq/ack numbers are not affected. |
| `retransmission_probability` | A copy of each data packet (same seq, flags, payload) is appended at `original_ts + retransmission_timeout`. |
| `server_rst_probability` | Picks a random split point *k*; replaces the tail of the data exchange with a RST from the server and any extra unACKed data from the client, then drops the four-way teardown. |
| `payload_corruption_probability` | XOR-flips the last byte of the payload, invalidating the TCP checksum.  The ACK for that packet is delayed to follow a retransmission. |
| `stray_packet_count` | Injects forged client→server packets with stolen seq/ack values and random `'x'`-filled payloads.  Timestamps are scattered across the data-transfer window (or within `stray_timing_window` of their reference packet). |

### Timestamps and uniqueness — `_alloc_usec`

Each packet is assigned a capture timestamp.  The baseline is
`config.base_time + n * inter_packet_gap`, optionally perturbed by
`random.uniform(0, config.gap_jitter)`.  This can produce duplicate microsecond
timestamps when jitter is small relative to the packet gap.

`_alloc_usec(desired_usec, used_ts: set[int])` guarantees uniqueness by
incrementing `desired_usec` until it finds a value not in `used_ts`.  The set
is updated in place so subsequent calls see the newly allocated timestamp.

After all anomaly packets are added the final list is **sorted by timestamp**,
so jitter-reordered packets appear in the same order as a real capture would
show them.

### Payload content

Application data is a repeating tile of `b"\x00\x01\x02…\xff\x00\x01…"`.
`_repeat_payload(size)` from `_stream_common.py` slices the appropriate
number of bytes.  The same tile is used for retransmissions, so a retransmit
carries byte-identical content to the original — matching real TCP behaviour.

### Fragmentation at the stream level

When `mtu` is set, every packet whose IP-layer size exceeds the MTU is split
into fragments after it is built.  `_fragment_packet()` calls
`_fragment_ip_raw(raw, ip_start, mtu, encap)` from `_stream_common.py`, which
delegates to `fragment_ipv4` or `fragment_ipv6` from
`packeteer/generate/fragmentation.py`.

`_encap_ip_start(encap, include_ethernet)` computes the byte offset of the
outermost IP header so that the fragmentation point is always the outer
datagram (keeping tunnel headers intact).

Fragment timestamps are allocated with `_alloc_usec`: the original timestamp
is removed from `used_ts` and replaced by one unique timestamp per fragment.

## UDP stream

`generate_udp_stream()` is simpler: it produces exactly *n* datagrams, all
client→server, with no connection state, handshake, or teardown.  Each
datagram is assembled with `PacketBuilder().ip().udp().payload()`.

## SCTP stream

`generate_sctp_stream()` follows the same high-level structure as the TCP
stream but models the SCTP association lifecycle per RFC 9260:

1. **Four-way handshake**: INIT (client), INIT-ACK (server), COOKIE-ECHO
   (client), COOKIE-ACK (server).
2. **Data transfer**: DATA chunk (client, with TSN), SACK chunk (server).
3. **Graceful shutdown**: SHUTDOWN (client), SHUTDOWN-ACK (server),
   SHUTDOWN-COMPLETE (client).

TSN (Transmission Sequence Number) is tracked independently from the TCP
sequence number concept.  Each DATA chunk increments the TSN counter; each
SACK carries the cumulative TSN acknowledgement.

SCTP checksums (CRC-32c) are computed inside `build_sctp_packet()` and cover
the entire SCTP header and all chunks.
