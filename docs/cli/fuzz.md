# packeteer fuzz

```
packeteer fuzz <FILE> [--output FILE] [--pcap FILE] [--pcapng FILE]
                      [--mutations NAME [NAME ...]]
                      [--count N] [--seed N]
```

Produces adversarial variants of each packet in *FILE* for decoder robustness
testing.  Two complementary families of mutation are applied:

- **Spec-level** — operate on the packet spec JSON and produce well-formed
  (but deliberately unusual) packets: boundary values, reserved-bit settings,
  pathological TCP flag combinations, truncated and extended payloads.
- **Byte-level** — operate on the serialised raw bytes and produce deliberately
  malformed encodings: bit flips, wrong checksums, wrong length fields.

`FILE` may be a JSON packet spec **or** a pcap/pcapng capture file.  When a
capture is given it is parsed automatically.  The file type is detected from
its magic number, not its extension.

## Output options

`--output`, `--pcap`, and `--pcapng` may be combined freely.  When none are
given, the spec-level variants are printed to stdout as a packet spec JSON
string.

| Flag | Effect |
|------|--------|
| `--output FILE` / `-o FILE` | Write spec-level variants as a packet spec (JSON) to FILE |
| `--pcap FILE` | Write all variants (spec-level + byte-level) as a libpcap file |
| `--pcapng FILE` | Write all variants (spec-level + byte-level) as a pcapng file |

## Mutation types

### Spec-level

| Name | What it does |
|------|-------------|
| `boundary` | Sets numeric header fields to their minimum, near-minimum, near-maximum, and maximum representable values (TTL, TOS, IP identification, fragment offset, TCP window/seq/ack, port numbers, ICMP id/seq, SCTP verification tag) |
| `reserved-bits` | Sets reserved or undefined flag bits: the IPv4 "evil bit" (RFC 3514), the DF+MF combination (RFC-invalid), and the TCP reserved nibble |
| `tcp-flags` | Emits all classically pathological TCP flag combinations: SYN+FIN, SYN+RST, null scan (no flags), XMAS (all flags), FIN-only, PSH+URG without ACK, RST+ACK+URG, ECE+CWR |
| `truncate` | Removes the payload or cuts it to 1 byte, 25%, or 50% of its original length |
| `extend` | Appends extra zero bytes (1, 4, 8, 64, or 512 bytes) or 16 random bytes after the existing payload |

### Byte-level

| Name | What it does |
|------|-------------|
| `bit-flip` | Flips a single random bit per variant; `--count` controls how many variants are produced per source packet |
| `wrong-checksum` | Sets IP, TCP, and UDP checksum fields to `0x0000`, `0xffff`, and the bitwise inverse of the original |
| `wrong-length` | Sets IP total-length and UDP length fields to zero, IHL-only, off-by-one, and maximum (`0xffff`) |

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mutations NAME …` | all | Space-separated list of mutation type names to apply |
| `--count N` | `10` | Number of `bit-flip` variants per source packet |
| `--seed N` | random | Integer seed for reproducible output |

## Examples

**Produce all variants from a capture as a pcap:**

```bash
packeteer fuzz capture.pcap --pcap fuzzed.pcap
```

**Apply only boundary-value and TCP-flag mutations, write a packet spec:**

```bash
packeteer fuzz capture.pcap --mutations boundary tcp-flags --output fuzzed.json
```

**Reproduce a specific run deterministically:**

```bash
packeteer fuzz capture.pcap --seed 42 --pcap fuzzed.pcap
```

**Apply only byte-level mutations:**

```bash
packeteer fuzz capture.pcap --mutations bit-flip wrong-checksum wrong-length --pcap byte_fuzzed.pcap
```

**Increase the number of bit-flip variants per packet:**

```bash
packeteer fuzz capture.pcap --mutations bit-flip --count 50 --pcap flipped.pcap
```

**Write both a packet spec (for inspection) and a pcap (for replay):**

```bash
packeteer fuzz capture.pcap --output fuzzed.json --pcap fuzzed.pcap
```
