# Overview

packeteer is a pure-Python toolkit for crafting, capturing, and generating
network traffic.  It comes with a **command-line interface** for common
tasks and a **Python API** for everything else.

The CLI (`packeteer parse`, `packeteer sanitise`, `packeteer build`,
`packeteer stream`) solves well-defined problems with a single command.
The Python API exposes the same machinery through
`packeteer.parse`, `packeteer.generate`, `packeteer.filter`,
`packeteer.sanitise`, and `packeteer.pcap`, giving you the flexibility to
combine, script, or extend those building blocks however your project needs.

## The core workflow

```
+-----------+              +-------------+              +-------------+
| pcap file | -- parse --> | packet spec | -- clean --> | packet spec |
+-----------+              | (JSON file) |              | (JSON file) |
                           +-------------+              +------+------+
                                                               |
                                                             build
                                                               |
                                                               v
                                                        +-----------+
                                                        | pcap file |
                                                        +-----------+
```

**Parsing** (`packeteer parse`) reads a `.pcap` or `.pcapng` capture and
writes a JSON file that describes every packet as a set of named fields — MAC
addresses, IP addresses, ports, flags, payload size, and so on.  Each protocol
layer has its own JSON key so the structure mirrors the actual packet layout.

**Building** (`packeteer build`) reads that JSON file and assembles the
packets back into a new pcap.  All checksums (IP, TCP, UDP, SCTP CRC-32c,
ICMP, GRE, …) are recomputed from scratch, so edits to any field
automatically produce a byte-perfect result without manual recalculation.

**Streaming** (`packeteer stream`) generates a complete, realistic network
stream from scratch — full TCP connections, UDP flows, or SCTP associations —
without any live traffic or capture setup.  Common impairments such as packet
loss, retransmissions, payload corruption, and server resets can be injected to
simulate real-world network conditions.  It writes the result directly to a
pcap or exports it as a packet spec for further editing.

**Fuzzing** (`packeteer fuzz`) takes a correctly-formed capture or packet spec
and produces a suite of adversarial variants.  Spec-level mutations introduce
boundary values, unusual flag combinations, and pathological payloads;
byte-level mutations corrupt checksums, lengths, and raw bytes in ways that
cannot be expressed in a spec at all.

## Supported protocols

packeteer can parse, build, sanitise and (where applicable) stream the following
protocols:

| Layer | Protocols |
|-------|-----------|
| Data link | Ethernet, VLAN (802.1Q), QinQ (stacked VLANs), PPPoE |
| Tunnelling / encapsulation | MPLS, GRE, EtherIP, IP-in-IP, pseudowire |
| Network | IPv4, IPv6 |
| Transport | TCP, UDP, SCTP, ICMP, ICMPv6 |
| Application | HTTP, DNS, DHCP |

Stream generation (`packeteer stream`) supports TCP, UDP, and SCTP as the
primary transport.  Any supported encapsulation layer can be stacked on top of
a stream.  Fragmentation is available for IPv4 and IPv6 packets that exceed a
configured MTU.

## Use cases

### Sanitising captured traffic

Real captures often contain sensitive data — credentials, personal information,
internal hostnames or addresses — that cannot leave a controlled environment.
Parse the capture to JSON, edit or replace the sensitive fields, then rebuild
a clean pcap that preserves the original timing, structure, and protocol
behaviour but contains only the data you choose.

For HTTP captures, add `--http-headers` to redact sensitive header values
(Host, Cookie, Authorization, and others) while preserving the message
structure.

Common sanitisation tasks in the packet spec:

- Replace IP addresses with RFC 1918 or documentation-range addresses
- Zero out or randomise payload bytes (`"size"` instead of `"data"`)
- Replace MAC addresses with locally-administered addresses
- Strip or overwrite VLAN IDs, MPLS labels, GRE keys, or pseudowire sequence numbers

The rebuilt pcap can then be shared, stored in a test fixture, or loaded into
a traffic replay tool such as `tcpreplay`.

### Synthetic test data

Networks and security tools need realistic traffic to test against, but
generating it by hand is tedious and error-prone.  The JSON format is easy to
write, template, or generate programmatically — produce thousands of packets
covering specific edge cases (unusual flag combinations, tunnel stacks, large
fragments, rare protocol combinations) without having to capture live traffic.

The Python API gives full control when scripting is more convenient than JSON:

```python
from packeteer.generate import PacketBuilder
from packeteer.pcap import write_pcap

packets = []
for dst_port in [80, 443, 8080]:
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .tcp(dst_port=dst_port, flags=0x02)   # SYN
        .build()
    )
    packets.append((pkt, 0, 0))

write_pcap(packets, path="syn-sweep.pcap")
```

### Packet stream generation

`packeteer stream` generates a complete, realistic network stream — a full TCP
connection, UDP datagram flow, or SCTP association — without any live traffic
or capture setup.  It handles all the protocol mechanics automatically:
three-way handshakes, correct sequence and acknowledgement numbers, CRC-32c
checksums, inter-packet timestamps, and graceful teardowns.

A few flags control the shape of the traffic:

```bash
# 50-packet HTTP session with bimodal payload sizes written to pcap
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 80 --packets 50 --distribution bimodal --pcap session.pcap

# UDP flow, output as a packet spec for further editing
packeteer stream --protocol udp --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 53 --packets 5 --json dns.json
```

Optional features let you inject realistic impairments — packet loss,
retransmissions, payload corruption, server RST — and wrap every packet in
one or more encapsulation layers (VLAN, QinQ, MPLS, PPPoE, GRE, EtherIP,
IP-in-IP, pseudowire) to match the encapsulation stack of the network under test.  The
`--mtu` flag causes packets that exceed the limit to be fragmented as they
would be by a real low-MTU middlebox.

Streams can be written directly to pcap or pcapng, or exported as a JSON
config so they can be edited and rebuilt with `packeteer build`, or sanitised
with `packeteer sanitise` before sharing.

### Fuzzing decoders

`packeteer fuzz` takes a correctly-formed capture or packet spec and produces a
suite of adversarial variants for testing how a parser or decoder handles unusual
and malformed input.  Two mutation families are available: *spec-level* mutations
(boundary values, reserved flag bits, pathological TCP flag combinations,
truncated or extended payloads) produce well-formed but unusual packets;
*byte-level* mutations (bit flips, corrupted checksums, wrong length fields)
produce structurally invalid encodings that cannot be expressed in a spec at all.

```bash
packeteer fuzz capture.pcap --pcap fuzzed.pcap
```

The same capability is available through `packeteer.fuzz` in Python, where
`fuzz()` returns a list of `FuzzVariant` objects — each carrying the mutated
packet spec and a human-readable label — and `fuzz_bytes()` operates directly on
raw bytes.
