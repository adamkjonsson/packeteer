# packeteer stream

```
packeteer stream --client-ip IP --server-ip IP
                 (--pcap FILE | --pcapng FILE | --json FILE)
                 [options]
```

Generates a complete synthetic network stream and writes it to the chosen
output format.  Parameters can come from the command line, from an INI config
file (`--config`), or both — CLI flags always take precedence.

## Output formats

Exactly one output flag is required; they are mutually exclusive.

| Flag | Output |
|------|--------|
| `--pcap FILE` | libpcap (`.pcap`) file |
| `--pcapng FILE` | pcapng (`.pcapng`) file |
| `--json FILE` | Packet spec — same format as `packeteer parse` output, replayable with `packeteer build`.  Each `packet_metadata` block gains `direction` (`"c2s"` / `"s2c"`) and `label` (e.g. `"SYN"`, `"DATA[3]"`) fields. |

## General arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--config FILE` | — | INI file with a `[stream]` section |
| `--protocol` | `tcp` | `tcp`, `udp`, or `sctp` |
| `--client-ip IP` | *(required)* | Client IP address (IPv4 or IPv6) |
| `--server-ip IP` | *(required)* | Server IP (same family as client) |
| `--client-port PORT` | `54321` | Client source port |
| `--server-port PORT` | `80` | Server destination port |
| `--client-mac MAC` | `00:00:00:00:00:01` | Client Ethernet MAC |
| `--server-mac MAC` | `00:00:00:00:00:02` | Server Ethernet MAC |
| `--no-ethernet` | off | Omit Ethernet headers |
| `--sessions N` | `1` | Number of independent sessions (IP pairs) to generate (see below) |
| `--session-stagger SECONDS` | `1.0` | Window over which session start times are spread when `--sessions > 1` |
| `--packets N` | `10` | Number of data packets sent by the client |
| `--min-payload BYTES` | `40` | Minimum payload size |
| `--max-payload BYTES` | `1460` | Maximum payload size |
| `--distribution` | `uniform` | `uniform`, `bimodal`, or `fixed` |
| `--ttl N` | `64` | IP TTL / hop limit |
| `--gap SECONDS` | `0.001` | Base inter-packet gap |
| `--gap-jitter SECONDS` | `0.0` | Maximum extra delay per packet; output is re-sorted |
| `--seed N` | off | Integer RNG seed; two runs with the same seed produce byte-identical captures |
| `--mtu BYTES` | off | Fragment packets exceeding this IP-layer size |

## TCP-only arguments

Silently ignored for `--protocol udp` and `--protocol sctp`.

| Argument | Default | Description |
|----------|---------|-------------|
| `--window BYTES` | `65535` | TCP receive window size |
| `--psh-probability PROB` | `0.5` | Probability (0–1) PSH is set on each data segment |
| `--packet-loss PROB` | `0.0` | Probability a packet is dropped from the capture |
| `--retransmission-probability PROB` | `0.0` | Probability each data segment is retransmitted |
| `--retransmission-timeout SECONDS` | `0.2` | RTO — seconds after send that the retransmit fires |
| `--payload-corruption PROB` | `0.0` | Probability a segment payload is corrupted |
| `--server-rst PROB` | `0.0` | Probability the server terminates mid-stream with RST |
| `--rst-propagation-delay SECONDS` | `0.0` | Seconds for the RST to reach the client |
| `--stray-packets N` | `0` | Number of forged TCP hijack packets to inject |
| `--stray-timing-window N` | off | Constrain stray timestamps to within N packets of target |

## Multiple sessions

`--sessions N` generates `N` independent conversations in one capture instead of
one.  Each session is a complete stream of the chosen protocol with its own IP
pair: session `i` uses `client-ip + i` and `server-ip + i`.  The sessions are
**interleaved** — each starts at a random offset within `--session-stagger`
seconds and the packets are merged in timestamp order, so the output looks like
concurrent traffic rather than one flow after another.

Clients and servers are kept in **clearly separated address ranges**: the client
IPs occupy `client-ip .. client-ip + (N-1)` and the server IPs occupy
`server-ip .. server-ip + (N-1)`.  If those two ranges would overlap, the
command fails with an error rather than emitting traffic where one session's
client address is another session's server.  Pick base addresses at least `N`
apart — typically different subnets, e.g. `--client-ip 10.0.0.1 --server-ip
10.1.0.1`.

MAC addresses are shared across all sessions, modelling traffic that crosses a
common layer-2 next-hop.  With `--seed`, the whole multi-session mix is
reproducible.

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.1.0.1 \
    --sessions 20 --packets 5 --seed 42 --pcap busy.pcap
```

## Encapsulation flags

Layers are applied in the order VLAN/QinQ → MPLS → PPPoE → tunnel.
At most one of `--vlan` / `--qinq` may be given; at most one tunnel type.

| Flag | Description |
|------|-------------|
| `--vlan VID` | Single 802.1Q VLAN tag |
| `--vlan-pcp N` | Priority Code Point (0–7, default 0) |
| `--vlan-dei N` | Drop Eligible Indicator (0 or 1, default 0) |
| `--qinq OUTER INNER` | QinQ double VLAN (outer VID then inner VID) |
| `--mpls LABEL…` | MPLS label stack, outermost first |
| `--mpls-tc N` | Traffic Class for all labels (0–7, default 0) |
| `--mpls-ttl N` | TTL for all labels (default 64) |
| `--pppoe SESSION_ID` | PPPoE session frame |
| `--gre SRC_IP DST_IP` | GRE tunnel — stream IPs become inner |
| `--gre-key N` | RFC 2890 32-bit GRE Key |
| `--gre-ttl N` | Outer IP TTL (default 64) |
| `--etherip SRC_IP DST_IP` | EtherIP tunnel (RFC 3378) |
| `--etherip-ttl N` | Outer IP TTL (default 64) |
| `--ipip SRC_IP DST_IP` | IP-in-IP tunnel (RFC 2003 / 4213) |
| `--ipip-ttl N` | Outer IP TTL (default 64) |

## INI config file

All parameters can be stored in a `[stream]` section.  Key names match long
flag names with hyphens replaced by underscores.  Two keys differ from their
flag names: `packet_loss` (flag: `--packet-loss`) and `server_rst` (flag:
`--server-rst`).

```ini
[stream]
client_ip    = 10.0.0.1
server_ip    = 10.0.0.2
pcap         = out.pcap
protocol     = tcp
packets      = 50
distribution = bimodal
gap          = 0.002
gap_jitter   = 0.001
seed         = 42
psh_probability            = 0.3
packet_loss                = 0.02
retransmission_probability = 0.05
```

CLI flags override config file values:

```bash
packeteer stream --config session.ini
packeteer stream --config session.ini --packets 200
```

A fully commented template is at
`src/packeteer/generate/stream.ini.template`.

## Examples

**TCP — 50-packet HTTP session:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 80 --packets 50 --pcap session.pcap
```

**UDP — DNS-like datagram flow:**

```bash
packeteer stream --protocol udp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 53 --packets 5 --pcap dns.pcap
```

**SCTP — full association with bimodal payload sizes:**

```bash
packeteer stream --protocol sctp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 9999 --packets 20 --distribution bimodal --pcap sctp.pcap
```

**VLAN-tagged stream with middlebox fragmentation:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --vlan 100 --mtu 576 --pcap vlan_frag.pcap
```

**GRE tunnel:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --gre 203.0.113.1 203.0.113.2 --pcap gre.pcap
```

**Generate packet spec for downstream editing:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --packets 10 --json stream.json
packeteer sanitise stream.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap
```
