# packeteer

packeteer is a pure-Python toolkit for crafting, capturing, and generating
network traffic without any external dependencies.

Use it to build hand-crafted packets from a JSON description, parse real
pcap captures back into that same format, sanitise sensitive fields before
sharing, or generate complete synthetic network streams — TCP, UDP, or SCTP
— with realistic protocol state, timestamps, and optional impairments.

Everything runs from a CLI or directly from Python. No root, no libpcap, no
compiled extensions — Python 3.10+ and the standard library only.

## Features and supported protocols

- **Ethernet II**, 802.1Q VLAN (single/QinQ), MPLS label stacks, PPPoE
- **IPv4** (RFC 791) and **IPv6** (RFC 8200) with automatic checksums; IPv6 Hop-by-Hop Options extension header (RFC 8200 §4.3) including Router Alert and Jumbo Payload
- **TCP**, **UDP**, **SCTP** (RFC 9260), **ICMPv4**, **ICMPv6** with correct checksums
- **Tunnels**: IP-in-IP (RFC 2003/4213), EtherIP (RFC 3378), GRE (RFC 2784/2890) with Key, Sequence, Checksum, and TEB
- **DNS** (RFC 1035) and **mDNS** (RFC 6762) — parse, build, and sanitise A, AAAA, NS, CNAME, MX, SOA, PTR, and TXT records over UDP or TCP; mDNS QU and cache-flush bits; port 5353 dispatch
- **DHCP** (RFC 2131 / RFC 2132) — parse, build, and sanitise DHCP messages including all common option types; dispatch on ports 67/68
- **HTTP/1.x** (RFC 7230) — parse, build, and sanitise HTTP requests and responses over TCP; automatic port 80/8080 dispatch; sensitive header redaction
- **UTF-8 payload encoding** — packet specs use readable strings for text-protocol payloads; `packeteer parse` auto-detects printable ASCII and encodes accordingly
- **IPv4 and IPv6 fragmentation** in one call
- **pcap and pcapng** file I/O with microsecond or nanosecond timestamps
- **Stream generation** — complete TCP / UDP / SCTP flows written to pcap, pcapng, or packet spec; all streams can be wrapped in any encapsulation layer (VLAN, QinQ, MPLS, PPPoE, GRE, EtherIP, IP-in-IP), combined as a stack, and fragmented through a simulated low-MTU middlebox
- **Capture filtering** — `packeteer parse` accepts filter flags (`--proto`, `--port`, `--src`, `--dst`, `--host`, `--app`, …) to keep only the traffic you care about; values can be negated with `!` and addresses accept CIDR notation for both IPv4 and IPv6
- **PII scanning** — `packeteer sanitise` scans UTF-8 payloads for email addresses and personal names by default; findings are consolidated across packets and reported as structured `PersonalDataWarning` instances (`--no-scan-pii` to disable)
- **Fuzzing** — `packeteer fuzz` produces adversarial packet variants for decoder robustness testing: boundary values, reserved-bit settings, pathological TCP flag combinations, truncated/extended payloads, bit flips, wrong checksums, and wrong length fields; full Python API via `packeteer.fuzz`
- **CLI** (`packeteer`) — build packets from a packet spec, parse captures to a packet spec, sanitise specs by replacing sensitive fields with synthetic data, generate synthetic streams with `packeteer stream`, or generate adversarial variants with `packeteer fuzz`

## Quick start

### CLI

```bash
# Parse a capture to an editable packet spec
packeteer parse capture.pcap --output capture.json

# Rebuild it as a new pcap
packeteer build capture.json --pcap replayed.pcap

# Sanitise a capture in one step (parse + sanitise + build)
packeteer sanitise capture.pcap --pcap clean.pcap

# Or keep the intermediate packet spec too
packeteer sanitise capture.pcap --pcap clean.pcap --output clean.json

# Parse only TCP traffic on port 443 from a specific subnet
packeteer parse capture.pcap --proto tcp --dst-port 443 --src 10.0.0.0/24 --output https.json

# Generate a complete TCP stream (50 packets, bimodal payload sizes)
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 80 --packets 50 --distribution bimodal --pcap session.pcap

# Generate a UDP flow and export as a packet spec for further editing
packeteer stream --protocol udp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 53 --packets 5 --json dns.json

# Produce adversarial variants of every packet in a capture
packeteer fuzz capture.pcap --pcap fuzzed.pcap

# Apply only boundary-value and TCP-flag mutations, reproducibly
packeteer fuzz capture.pcap --mutations boundary tcp-flags --seed 42 --pcap fuzzed.pcap
```

### Python API

```python
from packeteer.generate import PacketBuilder

# TCP SYN packet
pkt = (PacketBuilder()
    .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=80)
    .payload(size=64)
    .build()
)

# SCTP (RFC 9260) — data lives inside chunks, not a separate payload layer
from packeteer.generate import SCTPDataChunk

pkt = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .sctp(
        src_port=1234,
        dst_port=9999,
        verification_tag=0xDEADBEEF,
        chunks=[SCTPDataChunk(tsn=0, data=b"hello sctp")],
    )
    .build()
)

# DNS query over UDP (RFC 1035)
from packeteer.generate import DNSMessage, DNSQuestion, DNS_TYPE_A

pkt = (PacketBuilder()
    .ethernet()
    .ip(src="192.168.1.1", dst="8.8.8.8")
    .udp(src_port=54321, dst_port=53)
    .dns(DNSMessage(id=0x1234, questions=[DNSQuestion("example.com.")]))
    .build()
)

# DHCP DISCOVER (RFC 2131)
from packeteer.generate import (
    DHCPMessage, DHCPOptMessageType, DHCP_MSG_DISCOVER,
    DHCP_OP_REQUEST, DHCP_PORT_CLIENT, DHCP_PORT_SERVER,
)

pkt = (PacketBuilder()
    .ethernet(src_mac="aa:bb:cc:dd:ee:ff", dst_mac="ff:ff:ff:ff:ff:ff")
    .ip(src="0.0.0.0", dst="255.255.255.255")
    .udp(src_port=DHCP_PORT_CLIENT, dst_port=DHCP_PORT_SERVER)
    .dhcp(DHCPMessage(
        op=DHCP_OP_REQUEST,
        xid=0x12345678,
        chaddr=bytes.fromhex("aabbccddeeff") + b"\x00" * 10,
        options=[DHCPOptMessageType(DHCP_MSG_DISCOVER)],
    ))
    .build()
)
```

```python
# IPv6 with Hop-by-Hop Router Alert (MLD — RFC 2711)
from packeteer.generate import RouterAlertOption

pkt = (PacketBuilder()
    .ip(src="::1", dst="ff02::1")
    .hop_by_hop_options([RouterAlertOption(value=0)])
    .udp(dst_port=9999)
    .build()
)
```

```python
# HTTP GET request (RFC 7230)
from packeteer.generate.http import HTTPRequest, HTTP_PORT

pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(src_port=54321, dst_port=HTTP_PORT, flags=0x018)
    .http(HTTPRequest(
        method="GET", path="/api/data",
        headers={"Host": "example.com", "Accept": "application/json"},
    ))
    .build()
)
```

```python
# Session builder — queue application payloads and let the protocol be handled
from packeteer.generate import TCPSession
from packeteer.pcap import write_pcap

stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=80)
    .send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    .recv(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!")
    .build()
)
write_pcap(stream.to_pcap_tuples(), path="http.pcap")
# Produces: SYN, SYN-ACK, ACK, DATA, ACK, DATA, ACK, FIN-ACK, ACK, FIN-ACK, ACK
```

```python
# Generate a GRE-tunnelled TCP stream and write it to pcap
from packeteer.generate import generate_tcp_stream
from packeteer.generate import GREEncap, MPLSEncap, IPIPEncap
from packeteer.pcap import write_pcap

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    encap=GREEncap(src_ip="203.0.113.1", dst_ip="203.0.113.2"),
    num_data_packets=20,
)
write_pcap(stream.to_pcap_tuples(), path="gre_tunnel.pcap")

# Stack MPLS labels + IP-in-IP tunnel
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    encap=[MPLSEncap(labels=[100, 200]), IPIPEncap("203.0.113.1", "203.0.113.2")],
)
```

```python
# Fuzz a capture for decoder robustness testing
import json
from packeteer.fuzz import fuzz, fuzz_bytes, FuzzOptions
from packeteer.pcap import read_pcap

with open("capture.json") as f:
    config = json.load(f)

# Spec-level variants — boundary values, bad TCP flags, truncated payloads
variants = fuzz(config, FuzzOptions(mutations=["boundary", "tcp-flags"], seed=42))
for v in variants:
    print(f"[pkt {v.source_idx}] {v.label}")

# Byte-level variants — bit flips, wrong checksums, wrong lengths
frames = read_pcap("capture.pcap")
raw, _ts = frames[0]
for label, corrupted in fuzz_bytes(raw, FuzzOptions(seed=42)):
    print(label, len(corrupted))
```

## Documentation

Full documentation lives in [`docs/`](docs/).  Build it locally:

```bash
pip install -r docs/requirements.txt
make -C docs html
# open docs/_build/html/index.html
```

Or read the source pages directly.  The documentation is organised in four parts:

**Introduction**

| Page | Content |
|------|---------|
| [docs/overview.md](docs/overview.md) | Purpose, workflow, and use cases |
| [docs/installation.md](docs/installation.md) | Install, run tests, build docs |

**CLI reference**

| Page | Content |
|------|---------|
| [docs/cli/parse.md](docs/cli/parse.md) | `packeteer parse` — arguments, filtering, output format |
| [docs/cli/sanitise.md](docs/cli/sanitise.md) | `packeteer sanitise` — what gets replaced, application-layer sanitisation |
| [docs/cli/build.md](docs/cli/build.md) | `packeteer build` — packet spec structure, supported layers, fragmentation |
| [docs/cli/stream.md](docs/cli/stream.md) | `packeteer stream` — all flags, encapsulation, INI config |
| [docs/cli/fuzz.md](docs/cli/fuzz.md) | `packeteer fuzz` — mutation types, flags, examples |

**Python API guide**

| Page | Content |
|------|---------|
| [docs/guide/parsing.md](docs/guide/parsing.md) | Parsing pcap files and individual packets |
| [docs/guide/sanitising.md](docs/guide/sanitising.md) | Sanitising captures with `sanitise` / `SanitiseOptions` |
| [docs/guide/generating.md](docs/guide/generating.md) | Generating synthetic data — session builders, stream generators, `PacketBuilder` |
| [docs/guide/pcap.md](docs/guide/pcap.md) | Reading and writing pcap / pcapng files |
| [docs/guide/fuzzing.md](docs/guide/fuzzing.md) | Fuzzing packets with `fuzz` / `fuzz_bytes` / `FuzzOptions` |

**Reference**

| Page | Content |
|------|---------|
| [docs/packet-spec/](docs/packet-spec/) | Packet spec format — field-by-field reference for every layer |
| [docs/api/packet-builder.md](docs/api/packet-builder.md) | `PacketBuilder` API reference |
| [docs/api/stream-generators.md](docs/api/stream-generators.md) | Stream generators and session builders API reference |
| [docs/api/stream-encap.md](docs/api/stream-encap.md) | Encapsulation type API reference |
| [docs/api/header-dataclasses.md](docs/api/header-dataclasses.md) | Header dataclasses and constants |
| [docs/api/pcap-io.md](docs/api/pcap-io.md) | `write_pcap`, `write_pcapng`, `read_pcap` API reference |
| [docs/api/parser.md](docs/api/parser.md) | Parser API reference |
| [docs/api/fuzzer.md](docs/api/fuzzer.md) | `fuzz`, `fuzz_bytes`, `FuzzOptions`, `FuzzVariant` API reference |
| [docs/reference/packet-sizes.md](docs/reference/packet-sizes.md) | Header size tables |
| [docs/reference/rfc-references.md](docs/reference/rfc-references.md) | RFC index |
| [docs/internals/](docs/internals/) | Developer internals: architecture, parser pipeline, stream generators, encapsulation, sanitiser |

## Running tests

```bash
python -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
.venv/bin/pytest
```
