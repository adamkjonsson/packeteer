# `packeteer stream` — CLI

```
packeteer stream --client-ip IP --server-ip IP
                 (--pcap FILE | --pcapng FILE | --json FILE)
                 [options]
```

Generates a complete synthetic network stream and writes it to the chosen
output format.  All required arguments can come from the command line, from an
INI config file (`--config`), or from a combination of both — CLI flags always
take precedence over config file values.

## Output formats

Exactly one output flag is required; they are mutually exclusive.

| Flag | Output |
|------|--------|
| `--pcap FILE` | libpcap (`.pcap`) file with microsecond timestamps |
| `--pcapng FILE` | pcapng (`.pcapng`) file |
| `--json FILE` | packet spec file — same format produced by `packeteer parse`, replayable with `packeteer build`.  Each packet's `packet_metadata` block gains two extra fields: `direction` (`"c2s"` or `"s2c"`) and `label` (e.g. `"SYN"`, `"DATA[3]"`) that identify the packet's role in the stream. |

## General arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--config FILE` | — | INI config file with a `[stream]` section |
| `--protocol` | `tcp` | Transport protocol: `tcp`, `udp`, or `sctp` |
| `--client-ip IP` | *(required)* | Client IP address (IPv4 or IPv6) |
| `--server-ip IP` | *(required)* | Server IP address (same family as client) |
| `--client-port PORT` | `54321` | Client source port |
| `--server-port PORT` | `80` | Server destination port |
| `--client-mac MAC` | `00:00:00:00:00:01` | Client Ethernet MAC address |
| `--server-mac MAC` | `00:00:00:00:00:02` | Server Ethernet MAC address |
| `--no-ethernet` | off | Omit Ethernet headers (produces raw IP packets) |
| `--packets N` | `10` | Number of data packets sent by the client |
| `--min-payload BYTES` | `40` | Minimum payload size per data packet |
| `--max-payload BYTES` | `1460` | Maximum payload size per data packet |
| `--distribution` | `uniform` | Payload size strategy: `uniform`, `bimodal`, or `fixed` (see [Payload distribution](python-api.md#payload-distribution)) |
| `--ttl N` | `64` | IP TTL / hop limit |
| `--gap SECONDS` | `0.001` | Base inter-packet gap (1 ms) |
| `--gap-jitter SECONDS` | `0.0` | Maximum additional delay per packet; output is re-sorted by timestamp |
| `--mtu BYTES` | off | Fragment packets exceeding this IP-layer size, simulating a low-MTU middlebox |

## TCP-only arguments

These flags are silently ignored for `--protocol udp` and `--protocol sctp`.

| Argument | Default | Description |
|----------|---------|-------------|
| `--window BYTES` | `65535` | TCP receive window size |
| `--psh-probability PROB` | `0.5` | Probability (0–1) that PSH is set on each data segment |
| `--packet-loss PROB` | `0.0` | Probability (0–1) that any packet is dropped from the capture |
| `--retransmission-probability PROB` | `0.0` | Probability (0–1) that each data segment is spuriously retransmitted |
| `--retransmission-timeout SECONDS` | `0.2` | RTO — time after original send that the retransmit fires |
| `--payload-corruption PROB` | `0.0` | Probability (0–1) that a segment's payload is corrupted in transit |
| `--server-rst PROB` | `0.0` | Probability (0–1) that the server terminates mid-stream with a RST |
| `--rst-propagation-delay SECONDS` | `0.0` | Seconds for the RST to reach the client |
| `--stray-packets N` | `0` | Number of forged TCP hijack packets to inject |
| `--stray-timing-window N` | off | Constrain each stray packet's timestamp to within N packets of its target |

## Encapsulation flags

Wrap every packet in one or more encapsulation layers.  Layers are applied in
the fixed order VLAN/QinQ → MPLS → PPPoE → tunnel.  At most one of `--vlan`
and `--qinq` may be given; at most one tunnel type (`--gre`, `--etherip`,
`--ipip`) may be given.

| Flag | Description |
|------|-------------|
| `--vlan VID` | Single 802.1Q VLAN tag |
| `--vlan-pcp N` | VLAN Priority Code Point (0–7, default 0) |
| `--vlan-dei N` | VLAN Drop Eligible Indicator (0 or 1, default 0) |
| `--qinq OUTER INNER` | QinQ double VLAN tag (outer VID then inner VID) |
| `--qinq-outer-pcp N` | Outer tag PCP (default 0) |
| `--qinq-outer-dei N` | Outer tag DEI (default 0) |
| `--qinq-inner-pcp N` | Inner tag PCP (default 0) |
| `--qinq-inner-dei N` | Inner tag DEI (default 0) |
| `--mpls LABEL…` | MPLS label stack (one or more 20-bit labels, outermost first) |
| `--mpls-tc N` | MPLS Traffic Class for all labels (0–7, default 0) |
| `--mpls-ttl N` | MPLS TTL for all labels (default 64) |
| `--pppoe SESSION_ID` | PPPoE session frame with given 16-bit session ID |
| `--gre SRC_IP DST_IP` | GRE tunnel; stream IPs become inner; outer IPs are SRC/DST |
| `--gre-key N` | RFC 2890 32-bit GRE Key field |
| `--gre-ttl N` | Outer IP TTL for GRE (default 64) |
| `--etherip SRC_IP DST_IP` | EtherIP tunnel (RFC 3378) |
| `--etherip-ttl N` | Outer IP TTL for EtherIP (default 64) |
| `--ipip SRC_IP DST_IP` | IP-in-IP tunnel (RFC 2003 / 4213) |
| `--ipip-ttl N` | Outer IP TTL for IP-in-IP (default 64) |

## INI config file

All parameters can be stored in a `[stream]` section of an INI file and passed
with `--config`.  Key names match the CLI long flags with hyphens replaced by
underscores (e.g. `gap_jitter`, `psh_probability`).  Two keys differ from their
flag names: `packet_loss` (flag: `--packet-loss`) and `server_rst` (flag:
`--server-rst`).

A fully commented template is at
[stream.ini.template](../../src/packeteer/generator/stream.ini.template).

```ini
[stream]
client_ip  = 10.0.0.1
server_ip  = 10.0.0.2
pcap       = out.pcap
protocol   = tcp
packets    = 50
distribution = bimodal
gap        = 0.002
gap_jitter = 0.001
mtu        = 576
psh_probability            = 0.3   # TCP only
packet_loss                = 0.02  # TCP only
retransmission_probability = 0.05  # TCP only
```

CLI flags override config file values, so the file acts as a saved profile that
individual runs can still adjust:

```bash
packeteer stream --config session.ini
packeteer stream --config session.ini --packets 200 --distribution bimodal
```

## Examples

**TCP: 50-packet HTTP session:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 80 --packets 50 --pcap session.pcap
```

**UDP: DNS-like datagram flow:**

```bash
packeteer stream --protocol udp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 53 --packets 5 --pcap dns.pcap
```

**SCTP: full association with bimodal payload sizes:**

```bash
packeteer stream --protocol sctp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 9999 --packets 20 --distribution bimodal --pcap sctp.pcap
```

**IPv6, fixed 512-byte payloads, 10 ms inter-packet gap:**

```bash
packeteer stream --client-ip 2001:db8::1 --server-ip 2001:db8::2 \
    --server-port 8080 --distribution fixed --max-payload 512 \
    --gap 0.01 --pcapng out.pcapng
```

**VLAN-tagged stream with middlebox fragmentation:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --vlan 100 --mtu 576 --pcap vlan_frag.pcap
```

**GRE tunnel with MPLS labels:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --mpls 100 200 --gre 203.0.113.1 203.0.113.2 --pcap mpls_gre.pcap
```

**Generate JSON for downstream editing or sanitisation:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 --packets 10 \
    --json stream.json
packeteer sanitise stream.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap
```
