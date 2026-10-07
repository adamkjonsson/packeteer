# packeteer sanitise

```
packeteer sanitise <FILE> [--output FILE] [--pcap FILE] [--pcapng FILE]
                          [--link-type TYPE]
                          [--no-ips] [--no-macs]
                          [--ports] [--payload] [--timestamps]
                          [--dns-ids] [--dhcp-xids] [--http-headers]
                          [--no-scan-pii]
```

Replaces sensitive field values with synthetic equivalents, producing a
structurally faithful capture that contains no real addressing information.

`FILE` may be a JSON packet spec **or** a pcap/pcapng capture file.  When a
capture is given it is parsed automatically — no separate `packeteer parse`
step is needed.  The file type is detected from its magic number, not its
extension.

## Output options

`--output`, `--pcap`, and `--pcapng` are independent and may be combined.
When none are given, the sanitised packet spec is printed to stdout.

| Flag | Effect |
|------|--------|
| `--output FILE` / `-o FILE` | Write sanitised packet spec (JSON) to FILE |
| `--pcap FILE` | Build sanitised packets and write to a libpcap file |
| `--pcapng FILE` | Build sanitised packets and write to a pcapng file |
| `--load-protocol FILE` | Import a protocol module first, so its sections are redacted rather than passed through.  Repeatable; see [`packeteer parse`](parse) |

## What gets replaced

| Field | Default | Flag to change |
|-------|---------|----------------|
| IP `src` / `dst` | **replaced** | `--no-ips` to keep |
| Ethernet `src_mac` / `dst_mac` | **replaced** | `--no-macs` to keep |
| TCP/UDP port numbers | kept | `--ports` to replace |
| `payload.data` | kept | `--payload` to zero (same byte length; encoding field removed after zeroing) |
| HTTP bodies | kept | `--payload` to zero (same byte length; a chunked body within one TCP segment keeps its chunk framing, and its extension and trailer values go too) |
| `packet_metadata` timestamps | kept | `--timestamps` to zero |
| DNS transaction IDs | kept | `--dns-ids` to zero |
| DHCP transaction IDs (`xid`) | kept | `--dhcp-xids` to zero |
| Sensitive HTTP header values | kept | `--http-headers` to redact |
| PII scan of payloads, app sections and HTTP bodies | **on** | `--no-scan-pii` to disable |

Replacements are **consistent within a single run**: the same original value
always maps to the same synthetic value across all packets and tunnel nesting
levels.

## Application-layer sanitisation

**DNS** — applied automatically when a `dns` section is present.  Domain name
labels are replaced consistently (`label0`, `label1`, …); A/AAAA RDATA
addresses use the same replacement pool as IP headers.

**DHCP** — applied automatically when a `dhcp` section is present.  IP fields
(`ciaddr`, `yiaddr`, `siaddr`, `giaddr`) and `chaddr` (MAC portion) are
replaced.

**HTTP** — bodies and header values are kept by default, and each of the
two flags below takes one of them out.

*Bodies, with `--payload`.*  A body is zeroed in place, at its length, as any
payload is.  A chunked body keeps its framing, so it still parses, and loses
whatever can carry its data: the chunk data, each chunk extension's value
(zeroed at its length) and each trailer field's value (redacted at its
length), since a trailer is where a checksum over the body is sent.

**Framing is kept only for a message within one TCP segment.**  `sanitise`
works packet by packet, and a body that spans segments, which is most bodies
larger than the MSS, cannot be walked from its first segment.  It is zeroed
whole, framing included, and so are the segments that continue it, which do
not parse as HTTP and are zeroed as payloads.  Nothing of the body is kept,
but neither is its shape: a decoder reading the sanitised capture loses that
message's end, and any message after it in the same segment.  Keeping the
framing would mean reassembling each TCP direction, which is out of scope for
packeteer.

*Headers, with `--http-headers`.*  The values of `Host`, `Cookie`,
`Set-Cookie`, `Authorization`, `Location`, `Referer` and `Origin` are
redacted.  Header names, and every other header, are kept.

**A redacted value keeps its length.**  It becomes `[redacted]` cut or padded
with spaces to the length of what it replaces — `shop.example.com` becomes
`[redacted]      `, a four-byte value `[red` — so no TCP segment changes
size.  `sanitise` rebuilds each packet with the sequence number it was
captured with, and a segment that shrank or grew would leave every sequence
number after it false: a reassembler would find gaps or overlaps the capture
never had.  Trailing spaces in a header value are optional whitespace, so a
parser still reads `[redacted]`.

*Exact bytes.*  A message the capture kept byte for byte — its
[`raw`](http-raw), written by `parse` when a message is not in the form
packeteer would rebuild — is redacted and zeroed **inside those bytes**, and
everything else stays as captured: the order and repetition of headers,
spacing, line endings.  When its head cannot be read line by line, a folded
continuation line above all, the bytes are dropped instead and the message is
rebuilt from its sanitised fields.  That rebuild groups a repeated header,
combines every one but `Set-Cookie` into one line, and can change the
message's length.

## PII scanning

PII scanning is **enabled by default** (`--scan-pii`; `--no-scan-pii` turns it
off).  Three things are scanned for email addresses and personal names:

- every UTF-8 encoded **payload**,
- every string in an **application-protocol section** — a decoded field is
  where a name is likeliest to be, and until 0.12.0 only the payload was
  looked at — and
- every **HTTP body** that is UTF-8 text.  A body is hex in its section, so
  until 0.17.0 the string scan passed over it.  One compressed by
  `Content-Encoding` is not text and is not scanned.

A warning is emitted for each unique finding, consolidated across all packets
in the run: if the same email address appears in several packets, one warning
lists all packet numbers.

```{note}
**A report is not a redaction.**  Scanning tells you a field carries something
identifying; it does not remove it.  For a protocol compiled from a spec, the
fix is to mark that field [`sensitive: true`](sensitive) and recompile — see
{doc}`../guide/sanitising`.
```

```bash
packeteer sanitise capture.pcap --pcap clean.pcap
```

Example warning output (on stderr):

```
UserWarning: [PII] email 'alice@example.com' found in 2 packets (1, 3).
  Context: 'Contact: alice@example.com — Sales'
```

Pass `--no-scan-pii` to suppress the scan entirely:

```bash
packeteer sanitise capture.pcap --no-scan-pii --pcap clean.pcap
```

The scan does not modify the output — it only reports findings.  Combine with
`--payload` to zero the payloads, HTTP bodies included, after inspection.

A top-level payload is scanned only when it is `"utf8"` encoded; a hex
payload is left untouched.  An HTTP body is hex in its section too, and is
decoded and scanned when it is UTF-8 text.

## What is never changed

Protocol names, TCP flags, window size, sequence numbers, TTL, DSCP, VLAN
IDs, MPLS labels, GRE keys, packet count and order.

Nor is a TCP segment's length, so the sequence numbers stay true: every
redaction and every zeroing keeps the length of what it replaces.  Two
exceptions are known.  An HTTP message rebuilt from its fields because its
head could not be read line by line, above.  And a DNS message over TCP,
whose names are replaced by `labelN` labels of other lengths — that is
[#192](https://github.com/adamkjonsson/packeteer/issues/192).

## Unsupported IP protocol numbers

When the input is a pcap or pcapng file, `packeteer sanitise` parses it
the same way as `packeteer parse`.  If any packet carries an IP protocol
number that is not recognised, the same consolidated warning is printed to
stderr — one line per unique protocol, with the packet count and file name.
See {doc}`parse` for details.

## Overriding the link-layer type

When the input is a capture file, `--link-type TYPE` overrides the link-layer
type recorded in the header — use it when a capture declares the wrong type and
would otherwise parse incorrectly.  `TYPE` accepts `ethernet`, `raw`,
`linux_sll`, `linux_sll2`, or an integer (e.g. `1`, `101`, `113`, `276`).  The
flag is ignored when the input is a JSON packet
spec, since no parsing happens in that case.  See {doc}`parse` for details.

```bash
packeteer sanitise capture.pcap --link-type raw --pcap clean.pcap
```

## Examples

**One step from capture to clean pcap:**

```bash
packeteer sanitise capture.pcap --pcap clean.pcap
```

**Produce both a clean pcap and a packet spec:**

```bash
packeteer sanitise capture.pcap --pcap clean.pcap --output clean.json
```

**Sanitise with ports and payload zeroed:**

```bash
packeteer sanitise capture.pcap --ports --payload --pcap clean.pcap
```

**Sanitise DNS traffic including transaction IDs:**

```bash
packeteer sanitise dns-capture.pcap --dns-ids --pcap clean.pcap
```

**Redact sensitive HTTP headers:**

```bash
packeteer sanitise http-capture.pcap --http-headers --pcap clean.pcap
```

**Classic three-step workflow from packet spec:**

```bash
packeteer parse capture.pcap --output raw.json
packeteer sanitise raw.json --output clean.json
packeteer build clean.json --pcap clean.pcap
```
