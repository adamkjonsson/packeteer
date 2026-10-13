# Tunnelling through your own code

Testing a decoder for an encrypted tunnel — WireGuard, OpenVPN, a protocol
of your own — needs traffic sealed the way that tunnel seals it, with keys
and cleartexts the test knows.  packeteer does no cryptography, and will
not.  What it does instead is hand every packet of a generated stream to
**your code**, in the order a tunnel would see them, and build the UDP
datagrams your code returns.  The traffic inside stays packeteer's: a DNS
conversation, an HTTP session, a lossy TCP transfer, with every impairment
it supports.

## A wrapper

A wrapper is any object with one method:

```python
def wrap(self, inner: bytes, direction: str, timestamp: float
         ) -> Sequence[tuple[str, bytes]]: ...
```

- `inner` is the inner packet from its IP header on.
- `direction` is `"c2s"` or `"s2c"`, the way the inner packet travels.
- `timestamp` is when it was sent, in seconds since the epoch.

It returns the outer datagrams to send at this point, each with its own
direction.  Usually that is one, `[(direction, sealed)]`.  It can be more,
for a handshake before the first packet or a rekey, or none, to swallow a
packet.  {class}`~packeteer.generate.udp_tunnel.TunnelWrapper` is the
protocol it satisfies.

```python
from packeteer.generate import (
    TCPStreamConfig, UDPTunnel, generate_tcp_stream, tunnel_stream,
)
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.pcap import write_pcap


class Counted:
    """Prefix a counter per direction: the shape of a real sealing tunnel."""

    def __init__(self) -> None:
        self.sent = {"c2s": 0, "s2c": 0}

    def wrap(self, inner, direction, timestamp):
        n = self.sent[direction]
        self.sent[direction] += 1
        return [(direction, n.to_bytes(8, "big") + inner)]


# The inner stream starts at its IP headers: no Ethernet, no tunnel encap.
inner = generate_tcp_stream(
    client_ip="10.0.0.2", server_ip="10.0.0.1", num_data_packets=50,
    include_ethernet=False,
    config=TCPStreamConfig(seed=7, base_time=1_700_000_000.0,
                           packet_loss_probability=0.05, retransmit_lost=True),
)
outer = tunnel_stream(
    inner,
    UDPTunnel(src_ip="198.51.100.7", dst_ip="203.0.113.9", port=51820,
              wrapper=Counted()),
    impairments=ImpairmentConfig(payload_corruption_probability=0.02),
    seed=7,
)
write_pcap(outer.to_pcap_tuples(), path="tunnel.pcap")
```

## What `tunnel_stream` promises

**Wire order, after the inner impairments.**  The inner packets are taken
in timestamp order, and `wrap` is called once for each.  That is once per
time a packet was *sent*.  In the example, a segment lost on the inner
connection is never wrapped, and its retransmission is wrapped, with the
next counter, as a real tunnel would seal it.  A wrapper that counts,
numbers, or rekeys after *N* packets is right without trying.

This is why it is a function over a finished stream and not an `encap=`
layer.  An encap is applied as each packet is built, before any impairment
has decided which packets are sent, lost, or sent twice.

**Outer impairments after wrapping.**  `impairments=` applies loss,
corruption, reordering and duplication to the outer datagrams, with the
same {class}`~packeteer.generate.impairments.ImpairmentConfig` as anywhere
else.  Corruption flips a byte of the *sealed* payload, so a decoder that
checks a tag sees it fail.  Losing an outer datagram loses everything it
carried.  These are separate from the inner stream's impairments, so
"the network inside the tunnel dropped a segment" and "the tunnel lost a
datagram" can both be in one capture.

**Direction maps to the endpoints.**  An outer datagram returned as `c2s`
travels from `src_ip` to `dst_ip`, and `s2c` the reverse.  The ports are
`port` at `dst_ip` and `src_port` (default `port`) at `src_ip`.

**Seeded and reproducible.**  The outer impairments draw from an RNG
derived from `seed` and separate from the inner stream's, so turning them on
never changes what `wrap` is given.  packeteer gives the wrapper nothing
random: if it needs randomness, a nonce for instance, it seeds its own.

## Timestamps and labels

The first datagram a call returns takes the inner packet's timestamp, and
each further one the next microsecond, so the outer datagrams keep the order
`wrap` returned them in.  Each is labelled `TUNNEL[<inner label>]`, with
`+1`, `+2` for further ones from the same call, and outer impairments derive
their labels from these (`CORRUPT[TUNNEL[DATA[3]]]`).

## From the command line

`packeteer stream --udp-tunnel` does the same: see
{doc}`../cli/stream`.  There the wrapper comes from a module, which defines
`make_wrapper(args)` and is given the `--tunnel-arg KEY=VALUE` pairs.
{func}`~packeteer.generate.udp_tunnel.load_wrapper` is the same step from
Python.  `examples/udp_tunnel/xor_seal.py` is a complete wrapper to start
from: a handshake each way on the first call, a counter per direction, a
rekey every *N* packets, and an `open_datagram` that reverses it, for a test
to check a decoder against.  **It is not cryptography**, and says so.

**Keep the cipher in a file of its own.**  The wrapper that seals traffic
and the decoder that opens it share one cipher, and one file of it, checked
once against its specification's test vectors, is the point: a copy per
tool can drift, and a fault in a shared one shows in its own tests rather
than cancelling out in a round trip.  A tunnel module can import a module
beside it, `from my_cipher import seal`, because its directory is appended
to `sys.path` when it loads — appended, so nothing beside it can stand in
for the standard library.  kober's `--load-transforms` follows the same
rule, so the decoder's module can import the same file.
