# CLI Reference

`packeteer` is the command-line entry point with four subcommands:
`build` constructs packets and writes them to a pcap or pcapng file;
`parse` reads a capture and produces a JSON config that can be fed back
to `build` for replay;
`sanitise` replaces sensitive field values in a JSON config with synthetic
data drawn from IANA-reserved ranges;
`stream` generates a complete synthetic network stream (TCP, UDP, or SCTP)
and writes it to a pcap, pcapng, or JSON config file.

Supported transport protocols for `build` / `parse`: TCP, UDP, SCTP (RFC 9260),
ICMPv4, ICMPv6.  See {doc}`json-config` for the JSON format, including the
SCTP chunk structure.

---

## `build`

```
packeteer build <config.json> (--pcap FILE | --pcapng FILE)
```

Reads the JSON config file, builds each packet, and writes them all to the
output file.  `--pcap` and `--pcapng` are mutually exclusive; one is required.

| Argument | Description |
|----------|-------------|
| `config.json` | *(required)* Path to a JSON file with a top-level `packets` array |
| `--pcap FILE` | Write to a libpcap (`.pcap`) file |
| `--pcapng FILE` | Write to a pcapng (`.pcapng`) file |

### Examples

```bash
# Build from a JSON config and write a pcap file
packeteer build packets.json --pcap out.pcap

# Build from a JSON config and write a pcapng file
packeteer build packets.json --pcapng out.pcapng
```

Per-packet fragmentation is controlled via the `metadata.mtu` field in the
JSON config — see {doc}`json-config` and {doc}`build/fragmentation`.

### Programmatic equivalent

{class}`packet_generator.PacketBuilder` is the Python API that `build` calls
internally.  Use it to assemble and write packets without invoking the CLI:

```python
from packet_generator import PacketBuilder, write_pcap

pkt = (
    PacketBuilder()
    .ethernet(src_mac="00:11:22:33:44:55", dst_mac="66:77:88:99:aa:bb")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(src_port=12345, dst_port=80, flags=0x002)
    .payload(size=64)
    .build()
)
write_pcap([(pkt, 0, 0)], path="out.pcap")
```

See {doc}`api/packet-builder` for the full builder API.

---

## `parse`

```
packeteer parse <capture> [options]
```

Reads every packet in a pcap or pcapng file, parses it through all layers, and
outputs a JSON config that can be passed back to `build`.  Both file formats
are auto-detected from the first four bytes — no extension checking needed.

| Option | Description |
|--------|-------------|
| `capture` | *(required)* Path to a `.pcap` or `.pcapng` file |
| `--output FILE`, `-o FILE` | Write the JSON config to FILE instead of printing to stdout |
| `--replay-pcap FILE` | Embed `metadata.type = "pcap"` and `metadata.from_file = FILE` in the generated config |
| `--replay-pcapng FILE` | Embed `metadata.type = "pcapng"` (mutually exclusive with `--replay-pcap`) |

### Examples

```bash
# Print JSON config to stdout
packeteer parse capture.pcap

# Save JSON config to a file
packeteer parse capture.pcap --output replay.json

# Save and embed a replay pcap path in the config
packeteer parse capture.pcap --output replay.json --replay-pcap replayed.pcap

# Parse a pcapng file (auto-detected)
packeteer parse capture.pcapng --output replay.json

# Round-trip: parse pcapng → config → rebuild as pcapng
packeteer parse capture.pcapng --output config.json
packeteer build config.json --pcapng out.pcapng
```

### Programmatic equivalent

{func}`packet_parser.parser.parse_pcap_file` is the Python API that `parse`
calls internally.  Use it to read a capture and get back the same JSON string
without invoking the CLI:

```python
from packet_parser.parser import parse_pcap_file

json_str = parse_pcap_file(path="capture.pcap")
print(json_str)
```

See {doc}`api/parser` for the full parsing API and {doc}`json-config` for the
JSON config format that `parse` produces and `build` consumes.

---

## `sanitise`

```
packeteer sanitise <input.json> [--output FILE]
                              [--no-ips] [--no-macs]
                              [--ports] [--payload] [--timestamps]
```

Reads *input.json* (a config produced by `parse`), replaces sensitive field
values with synthetic equivalents, and writes the result.  The same original
value always maps to the same synthetic value across all packets, preserving
the communication structure.

| Argument | Description |
|----------|-------------|
| `input` | JSON config file to sanitise |
| `--output FILE` / `-o FILE` | Write result to FILE (default: stdout) |
| `--no-ips` | Keep original IP addresses (default: replaced) |
| `--no-macs` | Keep original MAC addresses (default: replaced) |
| `--ports` | Replace TCP/UDP port numbers (default: kept) |
| `--payload` | Zero out payload data (default: kept) |
| `--timestamps` | Zero out packet timestamps (default: kept) |

**Example** — full sanitise-and-replay workflow:

```bash
# Step 1: parse the original capture
packeteer parse capture.pcap --output capture.json

# Step 2: sanitise (replace IPs, MACs; optionally ports and payload)
packeteer sanitise capture.json --ports --payload --output clean.json

# Step 3: rebuild a shareable pcap
packeteer build clean.json --pcap clean.pcap
```

### Programmatic equivalent

{func}`replacer.sanitise` is the Python API that `sanitise` calls internally:

```python
import json
from replacer import sanitise, SanitiseOptions

with open("capture.json") as f:
    config = json.load(f)

result = sanitise(config, SanitiseOptions(ports=True, payload=True))

with open("clean.json", "w") as f:
    json.dump(result, f, indent=2)
```

See {doc}`sanitiser/index` for the full reference including all `SanitiseOptions` fields.

---

## `stream`

```
packeteer stream --client-ip IP --server-ip IP (--pcap FILE | --pcapng FILE | --json FILE) [options]
```

Generates a complete synthetic network stream and writes it to a pcap, pcapng,
or JSON config file.  The `--protocol` flag selects the transport:

| Protocol | Description |
|----------|-------------|
| `tcp` *(default)* | Three-way handshake, data transfer, four-way teardown |
| `udp` | Datagram sequence (client→server only, no connection state) |
| `sctp` | Full SCTP association: 4-way handshake, DATA+SACK pairs, graceful shutdown (RFC 9260) |

| Argument | Default | Description |
|----------|---------|-------------|
| `--config FILE` | — | INI config file with a `[stream]` section; CLI flags override file values |
| `--client-ip IP` | *(required)* | Client IP address (IPv4 or IPv6) |
| `--server-ip IP` | *(required)* | Server IP address (same family) |
| `--pcap FILE` | *(required*)* | Write to a libpcap (`.pcap`) file |
| `--pcapng FILE` | *(required*)* | Write to a pcapng (`.pcapng`) file |
| `--json FILE` | *(required*)* | Write as a JSON config file (same format as `packeteer parse` output; replayable with `packeteer build`) |
| `--protocol` | `tcp` | Transport protocol: `tcp`, `udp`, or `sctp` |
| `--client-port PORT` | `54321` | Client source port |
| `--server-port PORT` | `80` | Server destination port |
| `--client-mac MAC` | `00:00:00:00:00:01` | Client MAC address |
| `--server-mac MAC` | `00:00:00:00:00:02` | Server MAC address |
| `--packets N` | `10` | Number of data packets sent by the client |
| `--min-payload BYTES` | `40` | Minimum payload size |
| `--max-payload BYTES` | `1460` | Maximum payload size |
| `--distribution` | `uniform` | Payload size strategy: `uniform`, `bimodal`, or `fixed` |
| `--ttl N` | `64` | IP TTL / hop limit |
| `--window BYTES` | `65535` | TCP receive window size (TCP only) |
| `--gap SECONDS` | `0.001` | Inter-packet gap (1 ms) |
| `--gap-jitter SECONDS` | `0.0` | Max additional delay per gap, drawn from `[gap, gap+jitter]`; output is re-sorted by timestamp |
| `--psh-probability PROB` | `0.5` | Probability (0.0–1.0) that PSH is set on each data segment (TCP only) |
| `--packet-loss PROB` | `0.0` | Probability (0.0–1.0) that any packet is silently dropped from the capture (TCP only) |
| `--retransmission-probability PROB` | `0.0` | Probability (0.0–1.0) that each data segment gets a spurious retransmission (TCP only) |
| `--retransmission-timeout SECONDS` | `0.2` | Seconds after original send that the retransmission timer fires (TCP only) |
| `--payload-corruption PROB` | `0.0` | Probability (0.0–1.0) that each data segment's payload is corrupted in transit (TCP only) |
| `--server-rst PROB` | `0.0` | Probability (0.0–1.0) that the server terminates mid-stream with a RST (TCP only) |
| `--rst-propagation-delay SECONDS` | `0.0` | Seconds for the RST to reach the client; client sends data during this window (TCP only) |
| `--mtu BYTES` | off | Fragment packets as if they passed through a middlebox with this IP MTU (e.g. 576, 1280, 1400) |
| `--stray-packets N` | `0` | Inject N forged TCP hijack packets with stolen seq/ack values and all-`x` payload (TCP only) |
| `--stray-timing-window N` | off | Constrain each stray timestamp to within N packets of its reference DATA packet (TCP only) |
| `--no-ethernet` | off | Omit Ethernet headers (raw IP packets) |

`--pcap`, `--pcapng`, and `--json` are mutually exclusive; exactly one is required.

### Encapsulation flags

Wrap every packet in one or more encapsulation layers.  Layers are applied in
the fixed order VLAN/QinQ → MPLS → PPPoE → tunnel.  `--vlan` and `--qinq`
are mutually exclusive; at most one tunnel type may be used.

| Flag | Description |
|------|-------------|
| `--vlan VID` | Single 802.1Q VLAN tag |
| `--vlan-pcp N` | VLAN Priority Code Point (0–7, default 0) |
| `--vlan-dei N` | VLAN Drop Eligible Indicator (0 or 1, default 0) |
| `--qinq OUTER INNER` | Double 802.1Q tags (QinQ): outer and inner VID |
| `--qinq-outer-pcp N` | Outer tag PCP (default 0) |
| `--qinq-outer-dei N` | Outer tag DEI (default 0) |
| `--qinq-inner-pcp N` | Inner tag PCP (default 0) |
| `--qinq-inner-dei N` | Inner tag DEI (default 0) |
| `--mpls LABEL…` | MPLS label stack (one or more 20-bit labels, outermost first) |
| `--mpls-tc N` | MPLS Traffic Class for all labels (0–7, default 0) |
| `--mpls-ttl N` | MPLS TTL for all labels (default 64) |
| `--pppoe SESSION_ID` | PPPoE session frame with given 16-bit session ID |
| `--gre SRC_IP DST_IP` | GRE tunnel; stream IPs become inner; outer IPs are SRC/DST |
| `--gre-key N` | RFC 2890 GRE Key field (omitted by default) |
| `--gre-ttl N` | Outer IP TTL for GRE (default 64) |
| `--etherip SRC_IP DST_IP` | EtherIP tunnel (RFC 3378) |
| `--etherip-ttl N` | Outer IP TTL for EtherIP (default 64) |
| `--ipip SRC_IP DST_IP` | IP-in-IP tunnel (RFC 2003 / 4213) |
| `--ipip-ttl N` | Outer IP TTL for IPIP (default 64) |

A template config file is provided at
[stream.ini.template](../stream.ini.template) — copy it, edit as needed, and
pass it with `--config`.  All keys are optional except `client_ip`,
`server_ip`, and one of `pcap`/`pcapng`/`json`.  CLI flags always override
config file values, so the file works as a saved profile.

### Examples

```bash
# Generate from a config file
packeteer stream --config my_stream.ini

# Config file as base profile, override packets on the CLI
packeteer stream --config my_stream.ini --packets 100 --distribution bimodal

# TCP: 50-packet HTTP session
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --packets 50 --pcap out.pcap

# UDP: DNS-like datagram flow (5 queries to port 53)
packeteer stream --protocol udp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 53 --packets 5 --pcap dns.pcap

# SCTP: full association with bimodal payloads
packeteer stream --protocol sctp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 9999 --packets 20 --distribution bimodal --pcap sctp.pcap

# HTTPS session with bimodal payload sizes
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 443 --distribution bimodal --pcapng tls.pcapng

# IPv6, fixed 512-byte payloads, 10 ms inter-packet gap
packeteer stream --client-ip 2001:db8::1 --server-ip 2001:db8::2 \
    --server-port 8080 --distribution fixed --max-payload 512 \
    --gap 0.01 --pcap out.pcap

# Raw IP (no Ethernet headers)
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --no-ethernet --packets 20 --pcap raw.pcap

# VLAN-tagged TCP stream (802.1Q VID 100, PCP 3)
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --vlan 100 --vlan-pcp 3 --packets 20 --pcap vlan.pcap

# MPLS label stack (two labels) + IP-in-IP tunnel
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --mpls 100 200 --ipip 203.0.113.1 203.0.113.2 --pcap mpls_ipip.pcap

# GRE tunnel with key
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --gre 203.0.113.1 203.0.113.2 --gre-key 12345 --pcap gre.pcap

# QinQ (double VLAN) with 576-byte middlebox fragmentation
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --qinq 100 200 --mtu 576 --pcap qinq_frag.pcap

# Generate a JSON config instead of a pcap (replayable with 'packeteer build')
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --packets 10 --json stream.json

# JSON then sanitise then rebuild — full generate→sanitise→replay workflow
packeteer stream --client-ip 192.168.1.1 --server-ip 192.168.1.2 \
    --protocol sctp --packets 20 --json raw.json
packeteer sanitise raw.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap
```

### Programmatic equivalent

The `stream` subcommand calls one of three generators depending on `--protocol`:

```python
# TCP (default)
from packet_generator.tcp_stream import generate_tcp_stream
from packet_generator import write_pcap, LINKTYPE_ETHERNET

stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    server_port=443, num_data_packets=50,
    payload_distribution="bimodal", retransmission_probability=0.05,
)
write_pcap(stream.to_pcap_tuples(), path="out.pcap", link_type=LINKTYPE_ETHERNET)

# UDP
from packet_generator.udp_stream import generate_udp_stream

stream = generate_udp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    server_port=53, num_data_packets=5,
)
write_pcap(stream.to_pcap_tuples(), path="dns.pcap")

# SCTP
from packet_generator.sctp_stream import generate_sctp_stream

stream = generate_sctp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    server_port=9999, num_data_packets=20,
    payload_distribution="bimodal",
)
write_pcap(stream.to_pcap_tuples(), path="sctp.pcap")
```

To get the JSON config equivalent of `--json`, parse the raw bytes back through
the standard parser pipeline — the same approach `packeteer stream --json` uses
internally:

```python
import json
from packet_generator.tcp_stream import generate_tcp_stream
from packet_parser.parser import parse_packet
from packet_parser.to_config import update_config, to_json_config, to_json_string
from packet_generator.pcap import LINKTYPE_ETHERNET

stream = generate_tcp_stream(client_ip="10.0.0.1", server_ip="10.0.0.2",
                              num_data_packets=5)
packet_configs = []
for pkt in stream.packets:
    parsed = parse_packet(pkt.raw, link_type=LINKTYPE_ETHERNET)
    cfg = {}
    if parsed.ethernet:
        update_config(cfg, parsed.ethernet)
    if parsed.ip:
        update_config(cfg, parsed.ip)
    if parsed.transport:
        update_config(cfg, parsed.transport)
        if parsed.payload:
            update_config(cfg, parsed.payload)
    cfg["metadata"] = {"timestamp_s": pkt.ts_sec, "timestamp_us": pkt.ts_usec,
                        "direction": pkt.direction, "label": pkt.label}
    packet_configs.append(cfg)

with open("stream.json", "w") as f:
    f.write(to_json_string(to_json_config(packet_configs)))
```

See {doc}`stream` for the full Python API, payload distribution options,
timing jitter, packet loss, retransmissions, and per-protocol details.
