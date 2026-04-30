# Fuzzing Packets

packeteer can produce adversarial variants of any packet for decoder robustness
testing.  Start from a real capture, a synthetic packet spec, or raw bytes, and
get back a set of deliberately unusual or malformed packets.

## Quick start

```python
import json
from packeteer.fuzz import fuzz, fuzz_bytes, FuzzOptions

with open("capture.json") as f:
    config = json.load(f)

# Spec-level variants — boundary values, bad TCP flags, truncated payloads, …
variants = fuzz(config)
for v in variants:
    print(f"[{v.source_idx}] {v.label}")
```

The simplest call — `fuzz(config)` with no options — applies all mutation types
to every packet in the spec and returns a flat list of
{class}`~packeteer.fuzz.FuzzVariant` objects.

## Mutation types

Two families of mutation are available.

### Spec-level mutations

These work on the packet spec dict and produce well-formed (but deliberately
unusual) packets that can be serialised by `packeteer build`:

| Name | What it does |
|------|-------------|
| `boundary` | Sets numeric header fields to their minimum, near-minimum, near-maximum, and maximum representable values |
| `reserved-bits` | Sets reserved or undefined flag bits: the IPv4 "evil bit", DF+MF simultaneously, and the TCP reserved nibble |
| `tcp-flags` | Emits classically pathological TCP flag combinations: SYN+FIN, null scan, XMAS, and several others |
| `truncate` | Removes the payload or cuts it to 1 byte, 25%, or 50% of its original length |
| `extend` | Appends extra zero or random bytes after the existing payload |

Use {func}`packeteer.fuzz.fuzz` for these.

### Byte-level mutations

These work on raw serialised packet bytes and produce deliberately malformed
encodings that a spec-based builder cannot represent:

| Name | What it does |
|------|-------------|
| `bit-flip` | Flips a single random bit per variant; `FuzzOptions.count` controls how many variants are produced |
| `wrong-checksum` | Sets IP, TCP, and UDP checksum fields to `0x0000`, `0xffff`, and the bitwise inverse of the original |
| `wrong-length` | Sets IP total-length and UDP length fields to zero, IHL-only, off-by-one, and maximum |

Use {func}`packeteer.fuzz.fuzz_bytes` for these.

## Selecting mutations

Pass a {class}`~packeteer.fuzz.FuzzOptions` instance to choose which mutation
types to apply:

```python
from packeteer.fuzz import fuzz, FuzzOptions

# Only boundary-value and TCP-flag mutations
variants = fuzz(config, FuzzOptions(mutations=["boundary", "tcp-flags"]))
```

The same `FuzzOptions` object can be passed to both `fuzz` and `fuzz_bytes`;
each function silently ignores mutation names that do not apply to its domain:

```python
import json
from packeteer.parse import parse_pcap_file
from packeteer.fuzz import fuzz, fuzz_bytes, FuzzOptions
from packeteer.pcap import write_pcap

spec = json.loads(parse_pcap_file("capture.pcap"))

# Build raw bytes for the first packet so we can apply byte-level mutations
from packeteer.__main__ import _apply_spec_to_builder  # internal; see note below

opts = FuzzOptions(mutations=["boundary", "bit-flip"], seed=42)
spec_variants = fuzz(spec, opts)          # applies "boundary"
# byte_variants = fuzz_bytes(raw, opts)   # applies "bit-flip" (needs raw bytes)
```

## Working with FuzzVariant objects

Each {class}`~packeteer.fuzz.FuzzVariant` returned by `fuzz` carries:

| Attribute | Description |
|-----------|-------------|
| `source_idx` | Zero-based index of the original packet in `config["packets"]` |
| `mutation` | Mutation type name, e.g. `"boundary"` |
| `label` | Human-readable description, e.g. `"boundary: network.ttl=0"` |
| `spec` | Mutated single-packet spec dict |

You can filter, inspect, or serialise variants freely:

```python
# Only keep variants derived from the first source packet
first_pkt_variants = [v for v in variants if v.source_idx == 0]

# Collect all boundary variants
boundary_variants = [v for v in variants if v.mutation == "boundary"]

# Build a packet spec dict for replay with packeteer build
import json
fuzz_spec = {"packets": [v.spec for v in variants]}
with open("fuzzed.json", "w") as f:
    json.dump(fuzz_spec, f, indent=2)
```

## Byte-level fuzzing

{func}`~packeteer.fuzz.fuzz_bytes` takes raw serialised bytes and returns a
list of ``(label, corrupted_bytes)`` pairs:

```python
from packeteer.fuzz import fuzz_bytes, FuzzOptions
from packeteer.pcap import write_pcap, read_pcap

# Read the first raw packet from a pcap
frames = read_pcap("capture.pcap")
raw, _ts = frames[0]

for label, corrupted in fuzz_bytes(raw, FuzzOptions(seed=0)):
    print(label, len(corrupted))
```

Combine with `write_pcap` to write directly to a file:

```python
from packeteer.pcap import write_pcap

pairs = fuzz_bytes(raw)
write_pcap([(b, 0.0) for _, b in pairs], path="byte_fuzzed.pcap")
```

`wrong-checksum` and `wrong-length` only apply to Ethernet-framed IPv4 packets
(including 802.1Q/802.1ad VLAN-tagged frames).  `bit-flip` works on any
non-empty byte string.

## Reproducibility

Set `FuzzOptions.seed` to an integer for deterministic output:

```python
opts = FuzzOptions(seed=42)
variants_a = fuzz(config, opts)
variants_b = fuzz(config, opts)
assert [v.label for v in variants_a] == [v.label for v in variants_b]
```

Without a seed, the RNG is initialised from the system entropy source and each
run produces a different order of bit-flip target bytes.

## Using the CLI

All mutations are also accessible via `packeteer fuzz`.  The CLI applies both
spec-level and byte-level mutations and writes the result to pcap, pcapng, or
packet spec in one step:

```bash
# All mutations → pcap
packeteer fuzz capture.pcap --pcap fuzzed.pcap

# Only boundary values and bit flips, reproducibly
packeteer fuzz capture.pcap --mutations boundary bit-flip --seed 42 --pcap fuzzed.pcap

# Write a packet spec for inspection
packeteer fuzz capture.pcap --mutations boundary tcp-flags --output fuzzed.json
```

See {doc}`../cli/fuzz` for the full flag reference.

## Next steps

- {doc}`../api/fuzzer` — complete `FuzzOptions`, `FuzzVariant`, `fuzz`, and `fuzz_bytes` API reference
- {doc}`generating` — create synthetic captures to use as fuzzing inputs
- {doc}`sanitising` — strip sensitive fields before sharing fuzzed captures
