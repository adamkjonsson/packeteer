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
| `--payload TYPE` | off | Application-layer payload to generate instead of random bytes; `http` or `vpn` (see below) |
| `--requests N` | `10` | HTTP only: total request/response transactions |
| `--requests-per-connection K` | all | HTTP only: transactions per connection (`1` = a new connection per request) |
| `--error-rate P` | `0.1` | HTTP only: probability a response is a 4xx/5xx error |
| `--chunked-rate P` | `0.0` | HTTP only: probability a response with a body is framed `Transfer-Encoding: chunked` |
| `--min-chunk BYTES` | `8` | HTTP only: minimum bytes per chunk, before the last |
| `--max-chunk BYTES` | `32` | HTTP only: maximum bytes per chunk, before the last |
| `--trailer-rate P` | `0.0` | HTTP only: probability a chunked body carries a trailer section |
| `--mss BYTES` | `1460` | HTTP only: maximum segment size for splitting a message across TCP segments |
| `--vpn-epochs E` | `4` | VPN only: number of key negotiations (data rekeys every `--packets`) |
| `--vpn-data-port PORT` | `51820` | VPN only: UDP port of the data channel |
| `--vpn-key-port PORT` | `51821` | VPN only: UDP port of the key-exchange channel |
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
| `--packet-loss PROB` | `0.0` | Probability a packet is lost on the wire (see below) |
| `--retransmit-lost` | off | Retransmit a lost segment so the connection recovers |
| `--no-tcp-options` | off | Send a bare SYN with no TCP options (see below) |
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

## HTTP REST payloads

`--payload http` replaces the random byte payloads with a simulated REST client:
the client issues realistic, randomly generated HTTP/1.1 requests (varied
methods, resource paths with IDs, query strings, headers, and JSON request
bodies) and the server replies with correlated responses (status codes matched
to the method, plus JSON response bodies).  Unlike the default unidirectional
data flow, this produces a genuine **bidirectional** request/response exchange,
and the generated traffic is valid HTTP that round-trips through
`packeteer parse`.

`--requests N` sets the total number of request/response transactions.
`--requests-per-connection K` controls how they are grouped onto TCP
connections:

- omitted (default) — all `N` transactions share **one keep-alive connection**;
- `K` — keep-alive connections of `K` transactions each (ceil(N/K) connections);
- `1` — a **new connection per request** (each opens, exchanges once, closes).

Connections within a run use successive client ports and staggered start times,
and combine with `--sessions` (each IP pair runs the full request workload).
`--seed` makes the whole capture reproducible.

### Response framing

Responses are framed with `Content-Length` by default.  `--chunked-rate P`
frames that proportion of the responses **that have a body** with
`Transfer-Encoding: chunked` instead — HTTP/1.1's other framing mechanism, and
the harder one to decode, since the body's extent is discovered by walking hex
size lines rather than read from a header.

A rate between the extremes is usually what you want: a decoder that has to
*choose* between the two framings is where the interesting bugs are, and
choosing needs both to appear in the same capture.

`--min-chunk` / `--max-chunk` set the bytes per chunk before the last.  The
defaults split the generated JSON bodies (~70 bytes) into several chunks, which
matters: a single-chunk body does not distinguish a decoder that walks the size
lines from one that reads to the end.

`--trailer-rate P` adds a trailer section after the terminating chunk on that
proportion of chunked bodies, announced by a `Trailer` header.  Trailers are
legal per RFC 7230 §4.4 and widely forgotten by decoders.  The flag needs
`--chunked-rate`; a trailer section only exists in a chunked body.

```bash
# Half the responses chunked, a fifth of those carrying trailers
packeteer stream --client-ip 10.0.0.1 --server-ip 10.1.0.1 \
    --payload http --requests 200 --chunked-rate 0.5 --trailer-rate 0.2 \
    --seed 42 --pcap rest-mixed-framing.pcap
```

Request bodies are always counted with `Content-Length`; the framing knobs
apply to responses only.

### The handshake

The generated handshake advertises what a modern client does: a Maximum
Segment Size, SACK permitted, and a window scale.  A SYN carrying **no**
options at all — a bare 20-byte header — is the most conspicuous mark of
generated traffic in a TCP capture, and packeteer exists to feed tools that
read captures.

The advertised MSS follows `--mss` where that applies, so a capture does not
contradict its own segmentation: `--mss 512` both splits the payload at 512
bytes and says so on the SYN.

`--no-tcp-options` sends a bare SYN instead, for a test that wants one.

Timestamps are deliberately not advertised.  A connection that negotiates them
carries one on **every** segment, and only the handshake carries options, so
advertising them and then never sending one would be a worse inconsistency than
leaving them out.  Carrying them properly is
[#90](https://github.com/adamkjonsson/packeteer/issues/90).

### What packet loss means

`--packet-loss` loses a packet **on the wire**: neither the capture point nor
the far end sees it.  So a lost segment is never acknowledged, and the
receiver's acknowledgement number stops advancing at the gap — the segments
after it are answered with **duplicate ACKs**, which is the signal an analyser
looks for around a loss event.  A sender's own sequence numbers are unaffected,
since it sent those bytes, so the hole stays visible.

Two consequences worth knowing:

- **The SYNs are never lost.**  Each side learns the other's initial sequence
  number from them, so losing one would leave every later segment carrying an
  acknowledgement number of zero — a capture that could not have happened.
  Everything after the handshake, teardown included, is subject to loss.
- **Nothing retransmits by default.**  A lost segment leaves a permanent hole
  in the byte range: the stream never recovers, which is the harsher input to
  test a decoder against.  `--retransmit-lost` turns that off — the segment is
  resent after `--retransmission-timeout` and delivered, and the
  acknowledgement that follows jumps forward over everything the receiver had
  been holding, which is what recovery looks like on the wire.

  Do not confuse it with `--retransmission-probability`, which duplicates a
  segment that **did** arrive.  One models recovery, the other a spurious
  retransmission; a capture can contain both.

### Impairing HTTP traffic

Every anomaly option works with `--payload http`: `--packet-loss`,
`--retransmission-probability`, `--payload-corruption`, `--server-rst` and
`--stray-packets`.  They are applied **per connection**, so a RST cuts one
connection short rather than reaching across the capture, and with
`--sessions` each session's connections are impaired independently.

Pair them with `--mss`.  A generated HTTP message is small enough to fit in a
single 1460-byte segment, so at the default MSS losing a segment loses a whole
request or response.  Lower the MSS and a message is spread over several
segments, where loss or corruption leaves a gap *inside* a message a decoder is
already part-way through — which is the case worth testing and the one hardest
to build by hand:

```bash
# Chunked responses, split across small segments, with 15% of segments lost
packeteer stream --client-ip 10.0.0.1 --server-ip 10.1.0.1 \
    --payload http --requests 200 --chunked-rate 0.5 \
    --mss 128 --packet-loss 0.15 --seed 42 --pcap rest-impaired.pcap
```

In `--json` output a damaged segment's `label` names the message it came from,
so `CORRUPT[GET /api/v1/orders [2/5]]` reads as "the second of five segments
carrying that request".

### Other notes

`--payload http` requires `--protocol tcp` (the default).  In `--json` output,
each data segment's `label` carries the HTTP semantics (e.g.
`GET /api/v1/orders/4821`, `201 Created`).

```bash
# 50 REST calls over one keep-alive connection
packeteer stream --client-ip 10.0.0.1 --server-ip 10.1.0.1 \
    --payload http --requests 50 --seed 42 --pcap rest.pcap

# 50 short connections (one request each), 10 concurrent clients
packeteer stream --client-ip 10.0.0.1 --server-ip 10.1.0.1 \
    --payload http --requests 50 --requests-per-connection 1 \
    --sessions 10 --pcap rest-many.pcap
```

## VPN payloads

`--payload vpn` generates traffic for a small, fictive binary VPN protocol over
two UDP channels:

- a **key-exchange channel** (`--vpn-key-port`, default 51821) that performs a
  three-message handshake — INIT (client random) → RESPONSE (server random) →
  CONFIRM — at the start of every key *epoch*;
- a **data channel** (`--vpn-data-port`, default 51820) carrying packets
  "encrypted" with a block cipher in counter (CTR) mode; each packet includes a
  counter.  The ciphertext is random bytes (nothing is actually encrypted).

`--vpn-epochs E` sets the number of key negotiations; after each handshake,
`--packets N` data packets flow (so a rekey happens every `N` packets).  Data is
**bidirectional** with an independent per-direction counter that resets to zero
at each rekey.  Each message begins with an 8-byte header
(`magic | version | type | key_epoch`); data packets add a 64-bit counter before
the ciphertext.  Ciphertext sizes are drawn from `--min-payload`/`--max-payload`.

The complete binary wire format — message headers, the key-exchange handshake,
and the data record layout — is specified RFC-style, with packet diagrams, under
[Application-layer payloads](../api/stream-generators.md#application-layer-payloads).

It composes with `--sessions` (each IP pair runs the full workload) and `--seed`
makes the capture reproducible.  In `--json` output, labels read e.g.
`KEY-INIT[epoch=0]`, `KEY-RESPONSE[epoch=0]`, `DATA c2s ctr=3 epoch=0`.

`--payload vpn` is UDP, which splits the anomaly options in two.
`--packet-loss` and `--payload-corruption` describe what a wire does to a
datagram and apply here unchanged, per channel.
`--retransmission-probability`, `--server-rst` and `--stray-packets` describe
TCP connection behaviour — a retransmission timer, a connection reset, a
hijacked sequence number — none of which exists in UDP; they are ignored with a
warning naming them, rather than approximated.

```bash
# 4 key epochs, 20 data packets each, on the default UDP ports
packeteer stream --client-ip 10.0.0.1 --server-ip 10.1.0.1 \
    --payload vpn --vpn-epochs 4 --packets 20 --seed 42 --pcap vpn.pcap
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
| `--vxlan SRC_IP DST_IP` | VXLAN tunnel (RFC 7348) over UDP:4789 |
| `--vxlan-vni N` | 24-bit VXLAN Network Identifier (default 0) |
| `--vxlan-ttl N` | Outer IP TTL (default 64) |
| `--vxlan-src-port N` | Outer UDP source port (default 4789) |
| `--geneve SRC_IP DST_IP` | GENEVE tunnel (RFC 8926) over UDP:6081 |
| `--geneve-vni N` | 24-bit GENEVE Virtual Network Identifier (default 0) |
| `--geneve-ttl N` | Outer IP TTL (default 64) |
| `--geneve-src-port N` | Outer UDP source port (default 6081) |
| `--gtpu SRC_IP DST_IP` | GTP-U tunnel (3GPP TS 29.281) over UDP:2152 |
| `--gtpu-teid N` | 32-bit GTP-U Tunnel Endpoint Identifier (default 0) |
| `--gtpu-ttl N` | Outer IP TTL (default 64) |
| `--gtpu-src-port N` | Outer UDP source port (default 2152) |
| `--ah SRC_IP DST_IP` | IPsec AH tunnel (RFC 4302); inner stack stays **visible** (integrity only) |
| `--esp SRC_IP DST_IP` | IPsec ESP tunnel (RFC 4303); inner stack is **scrambled** into opaque high-entropy ciphertext |
| `--ipsec-spi N` | 32-bit Security Parameters Index for `--ah` / `--esp` (default 256) |
| `--ipsec-ttl N` | Outer IP TTL for `--ah` / `--esp` (default 64) |

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

### Starting from a template

`--write-config` writes a fully commented template listing every recognised
key with its default, so you do not have to assemble one from this page:

```bash
packeteer stream --write-config my_stream.ini
```

Edit it — at minimum uncomment an output path — and run it back:

```bash
packeteer stream --config my_stream.ini
```

Pass `-` instead of a filename to write it to stdout.  Every commented example
in the template can be uncommented as-is, and the same text is available from
Python as {func}`packeteer.generate.stream_template.stream_config_template`:

```python
from packeteer.generate import stream_config_template

print(stream_config_template())
```

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

**VXLAN tunnel:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --vxlan 203.0.113.1 203.0.113.2 --vxlan-vni 5000 --pcap vxlan.pcap
```

**GENEVE tunnel:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --geneve 203.0.113.1 203.0.113.2 --geneve-vni 5000 --pcap geneve.pcap
```

**GTP-U tunnel:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --gtpu 203.0.113.1 203.0.113.2 --gtpu-teid 5000 --pcap gtpu.pcap
```

**IPsec AH tunnel (inner stack stays visible):**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --ah 203.0.113.1 203.0.113.2 --ipsec-spi 0x1000 --pcap ah.pcap
```

**IPsec ESP tunnel (inner stack opaque, like real encrypted traffic):**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --esp 203.0.113.1 203.0.113.2 --ipsec-spi 0x2000 --pcap esp.pcap
```

**Generate packet spec for downstream editing:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --packets 10 --json stream.json
packeteer sanitise stream.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap
```
