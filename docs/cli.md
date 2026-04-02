# CLI Reference

`packeteer` is the command-line entry point with four subcommands:
`build` constructs packets and writes them to a pcap or pcapng file;
`parse` reads a capture and produces a JSON config that can be fed back
to `build` for replay;
`sanitise` replaces sensitive field values in a JSON config with synthetic
data drawn from IANA-reserved ranges;
`stream` generates a complete synthetic TCP stream directly to pcap or pcapng.

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
JSON config — see {doc}`json-config` and {doc}`fragmentation`.

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
| `--replay-pcap FILE` | Embed `file_metadata.type = "pcap"` and `file_metadata.pcap = FILE` in the generated config |
| `--replay-pcapng FILE` | Embed `file_metadata.type = "pcapng"` (mutually exclusive with `--replay-pcap`) |

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

See {doc}`sanitiser` for the full reference including all `SanitiseOptions` fields.

---

## `stream`

```
packeteer stream --client-ip IP --server-ip IP (--pcap FILE | --pcapng FILE) [options]
```

Generates a complete synthetic TCP stream — three-way handshake,
`--packets` data segments from client to server, and four-way teardown —
and writes it directly to a pcap or pcapng file.  Sequence and
acknowledgement numbers are computed correctly for every packet.

| Argument | Default | Description |
|----------|---------|-------------|
| `--config FILE` | — | INI config file with a `[stream]` section; CLI flags override file values |
| `--client-ip IP` | *(required)* | Client IP address (IPv4 or IPv6) |
| `--server-ip IP` | *(required)* | Server IP address (same family) |
| `--pcap FILE` | *(required*)* | Write to a libpcap (`.pcap`) file |
| `--pcapng FILE` | *(required*)* | Write to a pcapng (`.pcapng`) file |
| `--client-port PORT` | `54321` | Client source port |
| `--server-port PORT` | `80` | Server destination port |
| `--client-mac MAC` | `00:00:00:00:00:01` | Client MAC address |
| `--server-mac MAC` | `00:00:00:00:00:02` | Server MAC address |
| `--packets N` | `10` | Number of data packets sent by the client |
| `--min-payload BYTES` | `40` | Minimum payload size |
| `--max-payload BYTES` | `1460` | Maximum payload size |
| `--distribution` | `uniform` | Payload size strategy: `uniform`, `bimodal`, or `fixed` |
| `--ttl N` | `64` | IP TTL / hop limit |
| `--window BYTES` | `65535` | TCP receive window size |
| `--gap SECONDS` | `0.001` | Inter-packet gap (1 ms) |
| `--gap-jitter SECONDS` | `0.0` | Max additional delay per gap, drawn from `[gap, gap+jitter]`; output is re-sorted by timestamp |
| `--psh-probability PROB` | `0.5` | Probability (0.0–1.0) that PSH is set on each data segment |
| `--packet-loss PROB` | `0.0` | Probability (0.0–1.0) that any packet is silently dropped from the capture |
| `--retransmission-probability PROB` | `0.0` | Probability (0.0–1.0) that each data segment gets a spurious retransmission |
| `--retransmission-timeout SECONDS` | `0.2` | Seconds after original send that the retransmission timer fires |
| `--payload-corruption PROB` | `0.0` | Probability (0.0–1.0) that each data segment's payload is corrupted in transit |
| `--server-rst PROB` | `0.0` | Probability (0.0–1.0) that the server terminates mid-stream with a RST |
| `--rst-propagation-delay SECONDS` | `0.0` | Seconds for the RST to reach the client; client sends data during this window |
| `--no-ethernet` | off | Omit Ethernet headers (raw IP packets) |

`--pcap` and `--pcapng` are mutually exclusive; one is required.

A template config file is provided at
[src/packet_generator/stream.ini.template](../src/packet_generator/stream.ini.template) — copy it, edit as needed, and
pass it with `--config`.  All keys are optional except `client_ip`,
`server_ip`, and one of `pcap`/`pcapng`.  CLI flags always override config
file values, so the file works as a saved profile.

### Examples

```bash
# Generate from a config file
packeteer stream --config my_stream.ini

# Config file as base profile, override packets on the CLI
packeteer stream --config my_stream.ini --packets 100 --distribution bimodal

# 50-packet HTTP session (no config file)
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --packets 50 --pcap out.pcap

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
```

### Programmatic equivalent

{func}`packet_generator.tcp_stream.generate_tcp_stream` is the Python API
that `stream` calls internally:

```python
from packet_generator.tcp_stream import generate_tcp_stream
from packet_generator.pcap import write_pcap, LINKTYPE_ETHERNET

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    server_port=443,
    num_data_packets=50,
    payload_distribution="bimodal",
    retransmission_probability=0.05,
)
write_pcap(stream.to_pcap_tuples(), path="out.pcap", link_type=LINKTYPE_ETHERNET)
```

See {doc}`stream` for the full Python API, payload distribution options,
timing jitter, packet loss, retransmissions, and IPv6 usage.
