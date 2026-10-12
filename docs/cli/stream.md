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
| `--payload NAME` | off | Application-layer payload to generate instead of random bytes: `http`, `vpn`, or any registered protocol's name (see below) |
| `--protocol-messages FILE` | — | JSON array of packet-spec sections for `--payload <protocol>`, sent in order and cycled; the packets `packeteer parse` writes are accepted as they are.  On UDP each is sent in its own direction (see [Payloads from your own protocol](#payloads-from-your-own-protocol)).  With `--payload http`, the messages to send instead of generated ones (see [Given messages](#given-messages)) |
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
| `--gap-jitter SECONDS` | `0.0` | Maximum random delay.  On TCP each packet's capture time is delayed by up to this, so a packet can overtake the one before it.  On UDP and SCTP each gap is lengthened by up to this, so nothing overtakes anything; use `--reorder` for that |
| `--seed N` | off | Integer RNG seed; two runs with the same seed produce byte-identical captures: the same packets, and timestamps from the same start |
| `--start-time SECONDS` | see description | Unix time at which the stream starts.  Defaults to `1700000000` (2023-11-14) with `--seed`, so that a seeded capture reproduces as a file, and to the current time without it |
| `--mtu BYTES` | off | Fragment packets exceeding this IP-layer size |

## TCP-only arguments

They shape the TCP header and handshake, so they have no effect on
`--protocol udp` or `--protocol sctp`, which have no TCP header.

| Argument | Default | Description |
|----------|---------|-------------|
| `--window BYTES` | `65535` | TCP receive window size |
| `--psh-probability PROB` | `0.5` | Probability (0–1) PSH is set on each data segment |
| `--no-tcp-options` | off | Send a bare handshake with no TCP options, and therefore no timestamps on any segment (see below) |

## Impairments

What a wire or a misbehaving peer does to the stream.  The **UDP** column
covers `--protocol udp` and `--payload vpn`, which is UDP.  An option is
**refused**, naming it, on a stream it cannot apply to: a flag accepted and
then ignored makes a clean capture look like an impaired one.  On
`--protocol sctp` every impairment is refused, because the SCTP stream takes
none yet.

| Argument | Default | TCP | UDP | Description |
|----------|---------|-----|-----|-------------|
| `--packet-loss PROB` | `0.0` | yes | yes | Probability a packet is lost on the wire (see below) |
| `--payload-corruption PROB` | `0.0` | yes | yes | Probability a data packet's payload is corrupted (last byte flipped).  On TCP the segment is then retransmitted cleanly |
| `--retransmit-lost` | off | yes | refused | Retransmit a lost segment so the connection recovers |
| `--retransmission-probability PROB` | `0.0` | yes | refused | Probability each data segment is retransmitted |
| `--retransmission-timeout SECONDS` | `0.2` | yes | — | RTO: seconds after send that the retransmit fires |
| `--server-rst PROB` | `0.0` | yes | refused | Probability the server terminates mid-stream with RST |
| `--rst-propagation-delay SECONDS` | `0.0` | yes | — | Seconds for the RST to reach the client |
| `--stray-packets N` | `0` | yes | refused | Number of forged TCP hijack packets to inject |
| `--stray-timing-window N` | off | yes | — | Constrain stray timestamps to within N packets of target |
| `--duplicate PROB` | `0.0` | yes | yes | Probability a packet is captured twice: identical bytes, 1 µs later, labelled `DUP[…]` |
| `--reorder PROB` | `0.0` | refused | yes | Probability a datagram is held back and delivered after the next *K* going the same way, labelled `REORDER[…]` (see below) |
| `--reorder-depth K` | `3` | — | — | The most datagrams a reordered one is overtaken by: *K* is drawn from `1..K` |

A **—** is a setting of the option above it.  It changes nothing on its own,
so it is not refused.

On UDP, a lost datagram has no further consequence: there is no
acknowledgement to withhold, and the datagrams around it are unchanged.
With `--mtu`, a lost datagram is never fragmented, and a corrupted one is
fragmented with its corruption.

### Reordering and duplication

Reordering and duplication are what a datagram protocol is built to survive:
a replay window, a sequence number carried in the message, a nonce derived
from a counter.  They are also what a decoder that keeps no state between
messages should be shown not to care about.

`--reorder` holds a datagram back in the network.  It is delivered after the
next *K* datagrams **going the same way**, with *K* drawn from
`1..--reorder-depth`, and is captured where it arrives, labelled
`REORDER[i]`.  It is a real overtake, independent of timing:
`--gap-jitter` on UDP only lengthens gaps.  Datagrams going the other way
neither count towards *K* nor are held up, because reordering happens along
one path.  A datagram with fewer than *K* behind it arrives after the last of
them, and one with none behind it is not reordered.  On TCP, `--reorder` is
refused: a reordered segment changes what the receiver acknowledges, and that
is not modelled.

`--duplicate` captures a packet twice: the copy has identical bytes, is
1 µs later, and is labelled `DUP[i]`.  On TCP it is the capture point seeing
the packet twice, such as a mirror port or two interfaces.  The sender did
nothing, so the copy keeps the original's TSval, which is how an analyser
tells it from a retransmission.  On UDP a duplicate made by the network
looks the same.

The four datagram impairments run in the order loss, corruption,
reordering, duplication, so a copy of a corrupted datagram is corrupted too.

```bash
packeteer stream --protocol udp --payload dns --protocol-messages dns.json \
    --client-ip 10.0.0.2 --server-ip 10.0.0.1 --server-port 53 \
    --packets 100 --reorder 0.1 --reorder-depth 4 --duplicate 0.05 \
    --seed 7 --pcap shuffled.pcap
```

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

## Payloads from your own protocol

`--payload <name>` takes any protocol registered with packeteer — one you
compiled from a spec, or one you wrote by hand — so a generated conversation
can carry your own traffic instead of random bytes.

A protocol describes what a message *looks like*, not what conversation to
have, so the two are separate: `--protocol-messages` is a JSON array of
packet-spec sections, sent in order and cycled when the stream is longer than
the list.

```bash
packeteer stream --load-protocol ./sensor.py \
    --protocol udp --payload sensor --protocol-messages msgs.json \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 --server-port 9000 \
    --packets 100 --pcap sensors.pcap
```

```json
[
  { "magic": 21317, "owner": "alice", "value": 21 },
  { "magic": 21317, "owner": "bob",   "value": 42 }
]
```

`--load-protocol` is what registers the protocol; see
{doc}`../protocols/index`.  The name must match the protocol's own, and the
protocol must be carried over the transport you asked for — a UDP protocol
with `--protocol tcp` is refused rather than quietly mis-encoded.

**A parsed capture replays as it is.**  The file may also be what
`packeteer parse` writes — the whole document, or an array of its packets —
and the protocol's section is taken from each packet that carries one; a
packet that carries none, such as an ACK, is not a message and is passed
over.  So captured messages go through an impaired stream without editing
the file:

```bash
packeteer parse --load-protocol ./sensor.py sensors.pcap --output msgs.json
packeteer stream --load-protocol ./sensor.py \
    --protocol udp --payload sensor --protocol-messages msgs.json \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 --server-port 9000 \
    --packets 100 --packet-loss 0.05 --seed 5 --pcap impaired.pcap
```

**Each message travels its own way on UDP.**  A request/response protocol
needs its replies to leave from the server, so on `--protocol udp` each
message is sent in its own direction (#195).  An `s2c` message goes from the
server's address, port and MAC to the client's.  The direction is:

- a packet's `packet_metadata.direction`, as `stream --json` writes it;
- for a packet without one, as `packeteer parse` writes it, read from its
  addresses.  The side on one of the protocol's ports, such as 53 for DNS,
  is the server.  When neither side is, or both are, the first sender in the
  flow is the client;
- for a section wrapped under the protocol's name, a `"direction"` key
  beside it.  Nothing else may be beside it, so a misspelt key is refused
  rather than ignored;
- `c2s` for a bare section.

```json
[
  { "dns": { "id": 1,
             "questions": [{ "name": "www.example.com.", "qtype": 1, "qclass": 1 }] } },
  { "dns": { "id": 1, "flags": { "qr": true },
             "questions": [{ "name": "www.example.com.", "qtype": 1, "qclass": 1 }],
             "answers": [{ "name": "www.example.com.", "rtype": 1, "rclass": 1,
                           "ttl": 60, "rdata": { "address": "192.0.2.7" } }] },
    "direction": "s2c" }
]
```

On `--protocol tcp`, every message is still sent from the client, and a
message that travels `s2c` is **refused**: sending a reply from the client
would be wrong in silence.  A TCP stream that carries data both ways is
[#198](https://github.com/adamkjonsson/packeteer/issues/198).

An element that is none of these — an object with no key the protocol reads
— is refused, naming its index and the keys a section has.  It used to build
a default message in silence, which for DNS is a bare 12-byte header: a
stream of those converts cleanly and a decoder run over it reports every
message decoded, so the failure was indistinguishable from success (#137).
The same is available from Python as
{func}`packeteer.app.protocol_conversation`, which returns each message
encoded with its direction for `UDPStreamConfig.messages`;
{func}`packeteer.app.protocol_payload_fn`, which returns the `payload_fn` the
stream generators take, and sends everything from the client; and
{func}`packeteer.app.protocol_messages`, which returns the messages
themselves.

**Every anomaly option applies**, because this is the ordinary stream
generator with the payloads fed in rather than a path of its own: the packet
labels stay `DATA[i]` and `ACK[i]`, which is what the impairment passes look
for.

This deliberately stays out of the spec grammar.  Which messages to send is a
property of the traffic you want, not of the protocol, and putting it in a
spec would make every spec carry test data.

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

### Given messages

With `--protocol-messages FILE`, `--payload http` sends the file's messages
instead of generating them, over the same conversation: the handshake, both
directions, segmentation at `--mss`, and every impairment.  That is how a
capture gets exact HTTP bytes, a `Content-Encoding: gzip` body for instance,
into a lossy stream.  Loss alone leaves a permanent gap where a segment went;
add `--retransmit-lost` for the resend that fills it, when the body should
still arrive whole.

```bash
packeteer stream --client-ip 10.0.0.2 --server-ip 10.0.0.1 \
    --payload http --protocol-messages messages.json \
    --requests 20 --mss 600 --packet-loss 0.05 --seed 1 --pcap gzip-lossy.pcap
```

```json
[
  { "http": { "type": "request", "method": "GET", "path": "/doc",
              "headers": { "Host": "example.com", "Accept-Encoding": "gzip" } } },
  { "http": { "type": "response", "status_code": 200, "reason": "OK",
              "headers": { "Content-Encoding": "gzip", "Content-Length": "2523" },
              "body": "1f8b0800…" } }
]
```

- **Direction comes from the message.**  A request goes client to server and
  a response server to client.  A transaction is a request and the responses
  after it, so the list must start with a request.
- **The list repeats** to make up `--requests` transactions, as it does for
  any other `--payload`, and `--requests-per-connection` cuts it into
  connections at transaction boundaries.  Each `--sessions` pair replays it
  from the start.
- **Messages go as written.**  `body` is hex and sent verbatim, and headers are
  not rewritten, `Connection` included.  `Content-Length` is added only to a
  body that has neither it nor `Transfer-Encoding`, as for any HTTP section.
- **The generation knobs are refused beside it**: `--error-rate`,
  `--chunked-rate`, `--min-chunk`, `--max-chunk` and `--trailer-rate`, whether
  on the command line or in a `--config` file.  Each shapes generated traffic,
  and would otherwise be accepted and ignored.
- **For exact bytes, give `raw`.**  A section may be just
  `{"http": {"raw": "<hex>"}}`, sent as written, whatever its spacing, line
  endings or repeated headers.  A start line beginning `HTTP/` makes it a
  response; `type` beside it, `"request"` or `"response"`, says otherwise.
  See [`http.raw`](http-raw).
- **A repeated header can also be written as a list**,
  `"Transfer-Encoding": ["gzip", "chunked"]`, one line per item, without
  `raw`.

The file may be what `packeteer parse` writes, as for any other protocol.
Messages that spanned several segments in the capture parse per packet, so
replay a capture's HTTP from sections written by hand or from a single-segment
capture.

### The handshake, and timestamps

The generated handshake advertises what a modern client does: a Maximum
Segment Size, SACK permitted, a window scale, and timestamps.  A SYN carrying
**no** options at all — a bare 20-byte header — is the most conspicuous mark
of generated traffic in a TCP capture, and packeteer exists to feed tools that
read captures.

The advertised MSS follows `--mss` where that applies, so a capture does not
contradict its own segmentation: `--mss 512` both splits the payload at 512
bytes and says so on the SYN.

**Timestamps are negotiated and then carried on every segment** (RFC 7323),
the way every modern connection carries them.  Each side runs a 1 ms clock
from a seeded random start; TSval is that clock, TSecr echoes the latest
value that arrived in order from the peer — so after a loss the duplicate
ACKs echo the last in-sequence segment, as their acknowledgement number
repeats it — and a retransmission, whether spurious or recovering a loss,
carries the clock at the moment it was *re*sent rather than a copy of the
original's, which is how an analyser tells the two apart, and acknowledges
what its sender had received by then rather than what the original did.  A corrupted
segment keeps its original stamp: it is the original transmission with a
byte flipped in flight — and since it fails its checksum on arrival, the
receiver never acknowledges it: the ACKs between it and its retransmission
repeat the hole's start and echo the last in-order TSval, and the one after
the retransmission (`ACK-RECOVER`) jumps past everything held meanwhile and
echoes the retransmission's.  The option takes 12 bytes of every segment, so data
is segmented at the MSS less twelve, as a real sender does; a full-size
segment is 1448 bytes of payload on a 1500-byte MTU.

`--no-tcp-options` sends a bare handshake instead, for a test that wants one
— and with nothing advertised, nothing is negotiated, so no segment carries
a timestamp either.

### What packet loss means

`--packet-loss` loses a packet **on the wire**: neither the capture point nor
the far end sees it.  On UDP that is all it does.  On TCP, a lost segment is never acknowledged, and the
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
`--packet-loss`, `--payload-corruption`, `--reorder` and `--duplicate`
describe what a wire does to a datagram and apply here unchanged, per
channel.
`--retransmission-probability`, `--retransmit-lost`, `--server-rst` and
`--stray-packets` describe TCP connection behaviour — a retransmission timer,
a connection reset, a hijacked sequence number — none of which exists in UDP;
they are refused, naming them, rather than approximated.

```bash
# 4 key epochs, 20 data packets each, on the default UDP ports
packeteer stream --client-ip 10.0.0.1 --server-ip 10.1.0.1 \
    --payload vpn --vpn-epochs 4 --packets 20 --seed 42 --pcap vpn.pcap
```

## UDP tunnels through your own code

`--udp-tunnel` carries the whole stream through a UDP tunnel, as WireGuard
or OpenVPN over UDP do.  packeteer does no cryptography, so what goes in each
outer datagram is computed by **your own code**: a Python module, named by
`--tunnel-module`, defining

```python
def make_wrapper(args: dict[str, str]) -> TunnelWrapper: ...
```

where the wrapper has one method,
`wrap(inner, direction, timestamp) -> [(direction, payload), ...]`.  `args`
are the `--tunnel-arg KEY=VALUE` pairs.  **A module is code, and loading it
runs that code**, as with `--load-protocol`.

```bash
packeteer stream --protocol udp --payload dns --protocol-messages dns.json \
    --client-ip 10.0.0.2 --server-ip 10.0.0.1 --server-port 53 --packets 20 \
    --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 51820 \
    --tunnel-module examples/udp_tunnel/xor_seal.py \
    --tunnel-arg key=secret --tunnel-arg rekey_after=8 \
    --tunnel-packet-loss 0.05 --tunnel-corruption 0.02 --seed 7 --pcap tunnel.pcap
```

What it promises:

- **The wrapper sees each inner packet once per time it is sent, in wire
  order**, after the inner stream's own impairments: a retransmitted segment
  again, a lost one never.  So a counter, a sequence number, or a rekey
  after *N* packets is correct by construction.  The timestamp lets it
  rekey after a time, or send a keepalive after an idle period.
- **Outer impairments apply after wrapping.**  `--tunnel-corruption` lands
  on the sealed bytes, so it breaks an authentication tag, and a lost outer
  datagram loses everything it carried.  The inner options (`--packet-loss`
  and the rest) still impair the inner stream, independently, except
  `--duplicate`, which is refused: it is the capture point seeing a packet
  twice, and the capture point is outside the tunnel.  Use
  `--tunnel-duplicate`.
- **Direction maps to the endpoints.**  A datagram `wrap` returns as `c2s`
  goes from the first endpoint to the second, and `s2c` the other way.  It
  is what `wrap` *returns* that counts, so a handshake reply can come back
  while a client packet is being sealed.
- **It is seeded and reproducible.**  The outer impairments draw from an RNG
  of their own, so adding one never changes what the wrapper is given.

`wrap` may return several datagrams, for a handshake or a rekey before the
sealed packet, or none, to swallow one.  Each outer datagram is labelled
`TUNNEL[<inner label>]`, with `+1`, `+2` for further ones from the same
call.  Layer-2 tags (`--vlan`, `--mpls`, …) go on the outer packet, and
`--udp-tunnel` cannot be combined with another tunnel.  It works with every
payload and with `--sessions`: one tunnel carries every session.

`examples/udp_tunnel/xor_seal.py` is a toy wrapper to start from, with a
handshake, a counter per direction, and a rekey.  It is not cryptography.
See {doc}`../guide/tunnelling` for the same from Python.

## Encapsulation flags

Layers are applied in the order VLAN/QinQ → MPLS → PPPoE → tunnel.
At most one of `--vlan` / `--qinq` may be given; at most one tunnel type.

The `--vlan-*` flags apply to a single tag and the `--qinq-*` flags name which
of the two tags they set, so `--vlan-pcp` has no effect alongside `--qinq`.

| Flag | Description |
|------|-------------|
| `--vlan VID` | Single 802.1Q VLAN tag |
| `--vlan-pcp N` | Priority Code Point (0–7, default 0) |
| `--vlan-dei N` | Drop Eligible Indicator (0 or 1, default 0) |
| `--qinq OUTER INNER` | QinQ double VLAN (outer VID then inner VID) |
| `--qinq-outer-pcp N` | Outer tag's Priority Code Point (0–7, default 0) |
| `--qinq-outer-dei N` | Outer tag's Drop Eligible Indicator (0 or 1, default 0) |
| `--qinq-inner-pcp N` | Inner tag's Priority Code Point (0–7, default 0) |
| `--qinq-inner-dei N` | Inner tag's Drop Eligible Indicator (0 or 1, default 0) |
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
| `--udp-tunnel SRC_IP DST_IP` | UDP tunnel whose payloads your own code computes; see [UDP tunnels through your own code](#udp-tunnels-through-your-own-code) |
| `--tunnel-port PORT` | UDP port of `--udp-tunnel` (required) |
| `--tunnel-src-port PORT` | UDP port at the tunnel's `SRC_IP` (default: `--tunnel-port`) |
| `--tunnel-ttl N` | Outer IP TTL for `--udp-tunnel` (default 64) |
| `--tunnel-module FILE` | The module whose `make_wrapper(args)` computes the outer payloads (required with `--udp-tunnel`; no INI key) |
| `--tunnel-arg KEY=VALUE` | An argument for `make_wrapper`; repeatable (no INI key) |
| `--tunnel-packet-loss PROB` | Probability an outer tunnel datagram is lost |
| `--tunnel-corruption PROB` | Probability an outer tunnel datagram's last byte is flipped |
| `--tunnel-reorder PROB` | Probability an outer tunnel datagram is held back behind the next *K* going its way |
| `--tunnel-reorder-depth K` | The most outer datagrams a reordered one is overtaken by (default 3) |
| `--tunnel-duplicate PROB` | Probability an outer tunnel datagram is captured twice |

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
