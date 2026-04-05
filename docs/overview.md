# Overview

packeteer is built around a two-way workflow between pcap capture files
and a human-readable JSON config format.

## The core workflow

```
pcap file  ──parse──▶  JSON config  ──build──▶  pcap file
```

**Parsing** (`packeteer parse`) reads a `.pcap` or `.pcapng` capture and
writes a JSON file that describes every packet as a set of named fields — MAC
addresses, IP addresses, ports, flags, payload size, and so on.  Each protocol
layer has its own JSON key so the structure mirrors the actual packet layout.

**Building** (`packeteer build`) reads that JSON file and assembles the
packets back into a new pcap.  All checksums (IP, TCP, UDP, SCTP CRC-32c,
ICMP, GRE, …) are recomputed from scratch, so edits to any field
automatically produce a byte-perfect result without manual recalculation.

## Use cases

### Synthetic test data

Networks and security tools need realistic traffic to test against, but
generating it by hand is tedious and error-prone.  The JSON format is easy to
write, template, or generate programmatically — produce thousands of packets
covering specific edge cases (unusual flag combinations, tunnel stacks, large
fragments, rare protocol combinations) without having to capture live traffic.

The Python API gives full control when scripting is more convenient than JSON:

```python
from packet_generator import PacketBuilder
from packet_generator.pcap import write_pcap

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

### Sanitising captured traffic

Real captures often contain sensitive data — credentials, personal information,
internal hostnames or addresses — that cannot leave a controlled environment.
Parse the capture to JSON, edit or replace the sensitive fields, then rebuild
a clean pcap that preserves the original timing, structure, and protocol
behaviour but contains only the data you choose.

Common sanitisation tasks in the JSON config:

- Replace IP addresses with RFC 1918 or documentation-range addresses
- Zero out or randomise payload bytes (`"size"` instead of `"data"`)
- Replace MAC addresses with locally-administered addresses
- Strip or overwrite VLAN IDs, MPLS labels, or GRE keys

The rebuilt pcap can then be shared, stored in a test fixture, or loaded into
a traffic replay tool such as `tcpreplay`.
