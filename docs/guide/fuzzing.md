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
from packeteer.fuzz import fuzz, fuzz_bytes, FuzzOptions
from packeteer.parse import parse_pcap_file
from packeteer.pcap import read_pcap

spec = json.loads(parse_pcap_file("capture.pcap"))
frames = read_pcap("capture.pcap")
raw, _ts = frames[0]

opts = FuzzOptions(mutations=["boundary", "bit-flip"], seed=42)
spec_variants = fuzz(spec, opts)     # applies "boundary"; ignores "bit-flip"
byte_variants = fuzz_bytes(raw, opts) # applies "bit-flip"; ignores "boundary"
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

## Coverage-guided fuzzing with Atheris

packeteer's built-in mutations cover a curated vocabulary of known bad patterns
and produce them deterministically.  For exhaustive exploration of an
application protocol's input space, pair packeteer with a coverage-guided
fuzzer such as [Atheris](https://github.com/google/atheris).

Coverage-guided fuzzers track which branches execute for each input and
preferentially mutate inputs that reach new code, finding edge cases that no
predefined mutation table would cover.

Install Atheris with:

```bash
pip install atheris
```

### Fuzzing an application-layer protocol

The natural combination is to let Atheris supply the application-layer payload
while packeteer provides the surrounding network framing.  Your decoder always
receives a properly-formed Ethernet/IP/UDP frame — exactly what it would
receive from a real socket or pcap capture — while Atheris concentrates its
exploration on the application payload where your parsing code lives.

```python
# fuzz_sensor_protocol.py
"""Fuzz a custom sensor protocol decoder using Atheris + packeteer."""
import struct
import sys

import atheris
from packeteer.generate import PacketBuilder


# ── Decoder under test ────────────────────────────────────────────────────────
# Wire format (application layer):
#   2 B version | 2 B sensor_id | 2 B reading_count
#   | reading_count × 4 B float (big-endian IEEE 754)

def decode_sensor_packet(raw_frame: bytes) -> dict:
    """Parse a raw Ethernet/IP/UDP sensor packet."""
    # Ethernet (14 B) + IPv4 (20 B) + UDP (8 B) = 42 B before payload
    payload = raw_frame[42:]
    if len(payload) < 6:
        raise ValueError("payload too short for sensor header")
    version, sensor_id, count = struct.unpack_from(">HHH", payload)
    if version not in (1, 2):
        raise ValueError(f"unsupported version {version}")
    readings = []
    offset = 6
    for _ in range(count):
        if offset + 4 > len(payload):
            raise ValueError("reading data truncated")
        (value,) = struct.unpack_from(">f", payload, offset)
        readings.append(value)
        offset += 4
    return {"sensor_id": sensor_id, "readings": readings}


# ── Atheris target ────────────────────────────────────────────────────────────

@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    # Packeteer wraps the fuzz-supplied bytes in a valid Ethernet/IP/UDP frame.
    # The network headers are always well-formed; only the application payload
    # — the part Atheris is exploring — varies.
    raw_frame = (
        PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.2", dst="10.0.0.1")
        .udp(src_port=5000, dst_port=5001)
        .payload(data=data)
        .build()
    )
    try:
        decode_sensor_packet(raw_frame)
    except ValueError:
        pass  # expected; any other exception propagates as a crash finding


atheris.Setup(sys.argv, TestOneInput)
atheris.instrument_all()
atheris.Fuzz()
```

Seed the corpus with a valid application payload so Atheris reaches the parsing
branches immediately rather than spending time on the length guard:

```bash
mkdir corpus/
python - <<'EOF'
import struct
header   = struct.pack(">HHH", 1, 42, 3)           # version=1, id=42, 3 readings
readings = struct.pack(">fff", 23.5, 18.1, 99.0)
open("corpus/valid_v1.bin", "wb").write(header + readings)
EOF
python fuzz_sensor_protocol.py corpus/ -max_total_time=300
```

For a TCP-based decoder, substitute `.tcp(src_port=…, dst_port=…)` for
`.udp(…)`.  For other framing — VLAN tags, GRE tunnels — use the same
encapsulation options as the stream generators.

For a deeper look at all three fuzzing patterns (pcap reader, packet parser,
and application-layer decoder) and guidance on building a seed corpus from
real captures or synthetic streams, see {doc}`../internals/atheris`.

## Next steps

- {doc}`../api/fuzzer` — complete `FuzzOptions`, `FuzzVariant`, `fuzz`, and `fuzz_bytes` API reference
- {doc}`../internals/atheris` — coverage-guided fuzzing patterns with Atheris
- {doc}`generating` — create synthetic captures to use as fuzzing inputs
- {doc}`sanitising` — strip sensitive fields before sharing fuzzed captures
